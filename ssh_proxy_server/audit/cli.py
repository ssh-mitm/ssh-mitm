# Source: https://github.com/rushter/blog_code
# More Information: https://rushter.com/blog/public-ssh-keys/

import argparse
import sys

from paramiko.pkey import PublicBlob
from typeguard import typechecked
from ssh_proxy_server.authentication import probe_host, Authenticator


@typechecked
def check_publickey(args: argparse.Namespace) -> bool:
    key = open(args.public_key, 'rt').read()
    try:
        pubkey = PublicBlob.from_string(key)
    except:
        print("file is not a valid public key")
        return False
    if probe_host(
        hostname_or_ip=args.host,
        port=args.port,
        username=args.username,
        public_key=pubkey
    ):
        print("valid key")
        return True
    else:
        print("bad key")
        return False


@typechecked
def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title='Available commands', dest="subparser_name", metavar='subcommand')
    subparsers.required = True

    parser_check_publickey = subparsers.add_parser('check-publickey', help='checks a username and publickey against a server')
    parser_check_publickey.add_argument('--host', type=str, required=True, help='Hostname or IP address')
    parser_check_publickey.add_argument('--port', type=int, default=22, help='port (default: 22)')
    parser_check_publickey.add_argument('--username', type=str, required=True, help='username to check')
    parser_check_publickey.add_argument('--public-key', type=str, required=True, help='publickey to check')

    parser_scan_auth = subparsers.add_parser('get-auth', help='checks authentication methods')
    parser_scan_auth.add_argument('--host', type=str, required=True, help='Hostname or IP address')
    parser_scan_auth.add_argument('--port', type=int, default=22, help='port (default: 22)')

    args = parser.parse_args(sys.argv[1:])
    if args.subparser_name == 'check-publickey':
        if not check_publickey(args):
            sys.exit(1)
    elif args.subparser_name == 'get-auth':
        auth_methods = Authenticator.get_auth_methods(args.host, args.port)
        if auth_methods:
            print(",".join(auth_methods))
