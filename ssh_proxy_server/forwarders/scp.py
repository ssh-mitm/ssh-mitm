import logging
import os
import time
from io import BytesIO

import paramiko
from paramiko.common import cMSG_CHANNEL_REQUEST, cMSG_CHANNEL_CLOSE, cMSG_CHANNEL_EOF
from paramiko.message import Message

from ssh_proxy_server.forwarders.base import BaseForwarder


class SCPBaseForwarder(BaseForwarder):
    pass


class SCPForwarder(SCPBaseForwarder):

    def forward(self):

        self.server_channel.exec_command(self.session.scp_command)  # nosec

        try:
            while self.session.running:
                # redirect stdout <-> stdin und stderr <-> stderr
                if self.session.scp_channel.recv_ready():
                    buf = self.session.scp_channel.recv(self.BUF_LEN)
                    buf = self.handleTraffic(buf, self.server_channel)
                    self._sendall(self.server_channel, buf, self.server_channel.send)
                if self.server_channel.recv_ready():
                    buf = self.server_channel.recv(self.BUF_LEN)
                    buf = self.handleTraffic(buf, self.session.scp_channel)
                    self._sendall(self.session.scp_channel, buf, self.session.scp_channel.send)
                if self.session.scp_channel.recv_stderr_ready():
                    buf = self.session.scp_channel.recv_stderr(self.BUF_LEN)
                    buf = self.handleErrorTraffic(buf)
                    self._sendall(self.server_channel, buf, self.server_channel.send_stderr)
                if self.server_channel.recv_stderr_ready():
                    buf = self.server_channel.recv_stderr(self.BUF_LEN)
                    buf = self.handleErrorTraffic(buf)
                    self._sendall(self.session.scp_channel, buf, self.session.scp_channel.send_stderr)

                if self._closed(self.session.scp_channel):
                    self.server_channel.close()
                    self.close_session(self.session.scp_channel, 0)
                    break
                if self._closed(self.server_channel):
                    self.close_session(self.session.scp_channel, 0)
                    break
                if self.server_channel.exit_status_ready():
                    status = self.server_channel.recv_exit_status()
                    self.close_session(self.session.scp_channel, status)
                    break
                if self.session.scp_channel.exit_status_ready():
                    self.session.scp_channel.recv_exit_status()
                    self.close_session(self.session.scp_channel, 0)
                    break
                time.sleep(0.1)
        except Exception:
            logging.exception('error processing scp command')
            raise

    def handleTraffic(self, traffic, recipient):
        return traffic

    @staticmethod
    def handleErrorTraffic(traffic):
        return traffic

    @staticmethod
    def _sendall(channel, data, sendfunc):
        if not data:
            return 0
        if channel.exit_status_ready():
            return 0
        sent = 0
        newsent = 0
        while sent != len(data):
            newsent = sendfunc(data[sent:])
            if newsent == 0:
                return 0
            sent += newsent
        return sent

    @staticmethod
    def close_session(channel, status):
        # pylint: disable=protected-access
        if channel.closed:
            return

        if not channel.exit_status_ready():
            message = Message()
            message.add_byte(cMSG_CHANNEL_REQUEST)
            message.add_int(channel.remote_chanid)
            message.add_string("exit-status")
            message.add_boolean(False)
            message.add_int(status)
            channel.transport._send_user_message(message)

        if not channel.eof_received:
            message = Message()
            message.add_byte(cMSG_CHANNEL_EOF)
            message.add_int(channel.remote_chanid)
            channel.transport._send_user_message(message)

            message = Message()
            message.add_byte(cMSG_CHANNEL_REQUEST)
            message.add_int(channel.remote_chanid)
            message.add_string('eow@openssh.com')
            message.add_boolean(False)
            channel.transport._send_user_message(message)

        message = Message()
        message.add_byte(cMSG_CHANNEL_CLOSE)
        message.add_int(channel.remote_chanid)
        channel.transport._send_user_message(message)

        channel._unlink()


class SCPStorageForwarder(SCPForwarder):
    """
    Kapselt das Weiterleiten bzw. Abfangen eines SCP Kommandos und der Dateien
    die damit übertragen werden.
    """
    @classmethod
    def parser_arguments(cls):
        cls.PARSER.add_argument(
            '--scp-storage',
            dest='scp_storage_dir',
            required=True,
            help='directory to store files from scp'
        )
        cls.PARSER.add_argument(
            '--scp-keep_files',
            dest='scp_keep_files',
            required=True,
            help='directory to store files from scp'
        )

    def __init__(self, session):
        super().__init__(session)

        self.fileSizeRemaining = 0
        self.fileName = ''
        self.tmpFile = None
        self.trafficBuffer = BytesIO()
        self.response = False

    def handleTraffic(self, traffic, recipient):
        """
        Behandelt den SCP Traffic zwischen Client und Server.
        Es ist nicht notwendig zu unterscheiden, ob wir Dateien senden oder
        empfangen bzw. ob der aktuelle `traffic` vom Client oder vom Server
        gesendet wurde.
        Ein typischer Dateitransfer sieht folgendermaßen aus:

        C0660 4 file.txt\n
        \0
        1234\0
        \0
        D0600 0 testdirectory\n
        \0
        C0660 5 file2.txt\n
        \0
        54321\0
        \0
        E\n
        \0

        Eine Dateiübertragung wird stets mit einem "C-Kommando" eingeleitet,
        mit der Syntax `C<mode> <filesize> <filename>`. Die eigentliche Datei
        wird daraufhin byteweise übertragen und außerdem ein 0 Byte angehängt.
        Äquivalent zu den "C-Kommandos" gibt es die "D-Kommandos",
        die verwendet werden um in Unterverzeichnisse zu wechseln.
        Die angegebene Dateigröße wird hierbei ignoriert. Um wieder aus einem
        Verzeichnis raus zu wechseln wird das "E-Kommando" verwendet.
        Jedes Kommando wird mit einem Statuscode beantwortet:
        0 -> paramiko.SFTP_OK
        1 -> Nicht kritischer Fehler
        2 -> Kritischer Fehler (Verbindung wird beendet)
        """

        # ignoriert das Datenpaket
        if self.response:
            self.response = False
            return traffic

        if self.fileSizeRemaining == 0:
            self.trafficBuffer.write(traffic)
            bufferVal = self.trafficBuffer.getvalue()
            cIndex = bufferVal.find(b'C')
            if cIndex == -1:
                return traffic
            nIndex = bufferVal.find(b'\n', cIndex)
            if nIndex == -1:
                return traffic
            command = bufferVal[cIndex:nIndex]
            # Kommandos des Formats "C0660 1234 file.txt" werden aufgesplittet
            _, size, name = command.decode('utf8').split(' ', 2)

            # resettet den Buffer
            self.trafficBuffer.seek(0)
            self.trafficBuffer.truncate(0)

            # setze Name, Dateigröße und das zu sendende Kommando
            self.fileName = name
            self.fileSizeRemaining = int(size)
            traffic = command + b'\n'
            # erstelle eine temporäre Datei
            name = self.session.get_unique_prefix() + self.fileName
            try:
                os.stat(os.path.dirname(self.args.scp_storage_dir))
            except Exception:
                os.makedirs(os.path.dirname(self.args.scp_storage_dir))

            # das nächste Datenpaket soll verworfen werden
            # (Antworten interessieren uns nicht!)
            self.response = True
            return traffic

        # notwendig, da im letzten Datenpaket ein NULL-Byte angehängt wird
        bytesToWrite = min(len(traffic), self.fileSizeRemaining)
        self.fileSizeRemaining -= bytesToWrite
        with open(self.args.scp_storage_dir, 'a+b') as tmpFile:
            tmpFile.write(traffic[:bytesToWrite])
        traffic = ''

        # Dateiende erreicht
        if self.fileSizeRemaining == 0:
            result = self.inspect_file(self.args.scp_storage_dir)
            if result == paramiko.SFTP_OK:
                with open(self.args.scp_storage_dir, 'rb') as tmpFile:
                    # while buf := tmpFile.read(self.BUF_LEN):  # use with python3.8
                    while True:
                        buf = tmpFile.read(self.BUF_LEN)
                        self._sendall(recipient, buf, recipient.send)
                        if len(buf) != self.BUF_LEN:
                            break
                traffic = '\0'
            else:
                self.close_session(self.session.scp_channel, 2)
            if not self.args.scp_keep_files:
                os.remove(self.args.scp_storage_dir)
        return traffic

    @staticmethod
    def inspect_file(filepath):
        """
        Validationsergebnisse für den Proxy. Entscheidet, ob eine Datei transferiert werden darf.
        """
        return paramiko.SFTP_OK
