import time

from ssh_proxy_server.forwarders.ssh import SSHForwarder


class NoShellForwarder(SSHForwarder):
    def forward(self):
        self.session.channel.send_stderr('Terminalzugriff nicht erlaubt!\r\n')
        self.session.channel.send_stderr('Verbindung kann als Masterchannel genutzt werden.\r\n')
        self.session.channel.send_stderr('Beenden mit strg+c!\r\n')
        while self.session.running:
            if self.session.channel.recv_ready():
                if b'\x03' in self.session.channel.recv(1024):  # Ctrl + C
                    self.session.channel.send_stderr('Warte bis alle Sessions beendet wurden!\r\n')
                    self.session.transport.close()
                    break
            time.sleep(0.5)
