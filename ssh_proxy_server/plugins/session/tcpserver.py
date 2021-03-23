import select
import socket
import threading
import time


class TCPServerThread(threading.Thread):

    def __init__(self, request_handler, network='127.0.0.1', port=0, run_status=True, daemon=False):
        super(TCPServerThread, self).__init__()
        self.running = run_status
        self.network = network
        self.port = port
        self.handle_request = request_handler
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if daemon:
            self.daemon = True
        self.socket.bind((self.network, self.port))
        self.network, self.port = self.socket.getsockname()
        self.socket.listen(5)
        self.threads = []

    def run(self) -> None:
        while self.running:
            readable = select.select([self.socket], [], [], 0.5)[0]
            if len(readable) == 1 and readable[0] is self.socket:
                t = threading.Thread(target=self.handle_request, args=self.socket.accept())
                self.threads.append(t)
                t.start()
            time.sleep(0.1)

    def handle_request(self, client, addr):
        pass

    def close(self):
        for t in self.threads:
            t.join()
        self.socket.close()
