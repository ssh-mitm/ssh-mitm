import logging
import time

from ssh_proxy_server.forwarders.base import BaseForwarder


class SFTPBaseForwarder(BaseForwarder):
    pass


class SFTPForwarder(SFTPBaseForwarder):

    def forward(self):
        if not self.session.sftp_client:
            logging.error('sftp client not connected')
            if self.session.sftp_channel and self.session.sftp_channel.active:
                self.session.sftp_channel.close()
        else:
            while self.session.sftp_client and self.session.sftp_client.running:
                time.sleep(0.5)
