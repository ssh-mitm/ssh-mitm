import time

from sshmitm.forwarders.ssh import SSHForwarder


class NoShellForwarder(SSHForwarder):
    """let the client connect to a shell, but do not transfer data
    """
    def forward(self) -> None:
        if self.session.channel is None:
            return
        self.session.channel.send_stderr(b'Terminalzugriff nicht erlaubt!\r\n')
        self.session.channel.send_stderr(b'Verbindung kann als Masterchannel genutzt werden.\r\n')
        self.session.channel.send_stderr(b'Beenden mit strg+c!\r\n')
        while self.session.running:
            if self.session.channel.recv_ready():
                if b'\x03' in self.session.channel.recv(1024):  # Ctrl + C
                    self.session.channel.send_stderr(b'Warte bis alle Sessions beendet wurden!\r\n')
                    self.session.transport.close()
                    break
            time.sleep(0.5)
