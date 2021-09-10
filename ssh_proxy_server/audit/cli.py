# Source: https://github.com/rushter/blog_code
# More Information: https://rushter.com/blog/public-ssh-keys/

import argparse
import sys

from paramiko.pkey import PublicBlob
from ssh_proxy_server.authentication import probe_host


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('host', type=str, help='Hostname or IP address')
    parser.add_argument('--port', type=int, default=22)
    parser.add_argument('--username', type=str, required=True)
    parser.add_argument('--public-key', type=str, required=True)

    args = parser.parse_args(sys.argv[1:])
    key = open(args.public_key, 'rt').read()
    if probe_host(
        hostname_or_ip=args.host,
        port=args.port,
        username=args.username,
        public_key=PublicBlob.from_string(key)
    ):
        print("valid key")
    else:
        print("bad key")
