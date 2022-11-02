import select
import socket
import threading
import time
from typing import (
    Callable,
    List,
    Union,
    Tuple,
    Optional
)
import paramiko


class TCPServerThread(threading.Thread):

    def __init__(
        self,
        request_handler: Optional[Callable[
            [Tuple[str, int], Union[socket.socket, paramiko.Channel], Tuple[str, int]],
            None
        ]] = None,
        network: str = '127.0.0.1',
        port: int = 0,
        run_status: bool = True,
        daemon: bool = False
    ) -> None:
        super(TCPServerThread, self).__init__()
        self.running = run_status
        self.network = network
        self.port = port
        self.handle_request_callback = request_handler
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if daemon:
            self.daemon = True
        self.socket.bind((self.network, self.port))
        self.network, self.port = self.socket.getsockname()
        self.socket.listen(5)
        self.threads: List[threading.Thread] = []

    def run(self) -> None:
        while self.running:
            readable = select.select([self.socket], [], [], 0.5)[0]
            if len(readable) == 1 and readable[0] is self.socket:
                t = threading.Thread(target=self.handle_request, args=self.socket.accept())
                self.threads.append(t)
                t.start()
            time.sleep(0.1)

    def handle_request(self, client: Union[socket.socket, paramiko.Channel], addr: Tuple[str, int]) -> None:
        if self.handle_request_callback is not None:
            self.handle_request_callback((self.network, self.port), client, addr)

    def close(self) -> None:
        for t in self.threads:
            t.join()
        self.socket.close()
