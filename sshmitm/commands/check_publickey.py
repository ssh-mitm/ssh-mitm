import argparse
import sys
from paramiko.pkey import PublicBlob
from sshmitm.moduleparser import SubCommand
from sshmitm.authentication import probe_host


class Check_Publickey(SubCommand):  # pylint: disable=invalid-name
    """checks a username and publickey against a server"""

    HAS_CONFIG = False

    def register_arguments(self) -> None:
        self.parser.add_argument(
            "--host", type=str, required=True, help="Hostname or IP address"
        )
        self.parser.add_argument(
            "--port", type=int, default=22, help="port (default: 22)"
        )
        self.parser.add_argument(
            "--username", type=str, required=True, help="username to check"
        )
        self.parser.add_argument(
            "--public-key", type=str, required=True, help="publickey to check"
        )

    def execute(self, args: argparse.Namespace) -> None:
        """
        This function is used to check the validity of a public key file by
        using the probe_host function.

        :param args: Namespace object that contains the necessary parameters.
        """
        with open(args.public_key, "rt", encoding="utf-8") as key_handle:
            key = key_handle.read()
        try:
            pubkey = PublicBlob.from_string(key)
        except ValueError:
            sys.exit("file is not a valid public key")
        if not probe_host(
            hostname_or_ip=args.host,
            port=args.port,
            username=args.username,
            public_key=pubkey,
        ):
            sys.exit("bad key")
        print("valid key")
