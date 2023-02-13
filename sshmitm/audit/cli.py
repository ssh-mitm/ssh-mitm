# Source: https://github.com/rushter/blog_code
# More Information: https://rushter.com/blog/public-ssh-keys/

import argparse
import sys

import paramiko

from paramiko.pkey import PublicBlob
from sshmitm.moduleparser import ModuleParser
from sshmitm.authentication import probe_host, Authenticator


def check_publickey(args: argparse.Namespace) -> bool:
    """
    This function is used to check the validity of a public key file by
    using the probe_host function.

    :param args: Namespace object that contains the necessary parameters.
    :type args: argparse.Namespace
    :return: True if the public key is valid, False otherwise
    :rtype: bool
    """
    with open(args.public_key, 'rt', encoding="utf-8") as key_handle:
        key = key_handle.read()
    try:
        pubkey = PublicBlob.from_string(key)
    except ValueError:
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
    print("bad key")
    return False


def check_privatekey(args: argparse.Namespace) -> bool:
    """
    Check if the given private key is valid.

    :param args: Namespace object that contains the necessary parameters.
    :type args: argparse.Namespace
    :return: True if the private key is valid, False otherwise
    :rtype: bool
    """
    ssh = paramiko.SSHClient()

    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(
            args.host,
            port=args.port,
            username=args.username,
            key_filename=args.private_key,
            passphrase=args.private_key_passphrase
        )
    except Exception as ex:  # pylint: disable=broad-exception-caught
        print(ex)
        return False
    finally:
        ssh.close()

    print('Authentication succeeded.')
    return True


def init_audit_parser(parser: ModuleParser) -> None:
    subparsers = parser.add_subparsers(title='Available commands', dest="audit_subparser_name", metavar='audit-command')
    subparsers.required = True

    parser_check_publickey = subparsers.add_parser(
        'check-publickey', help='checks a username and publickey against a server'
    )
    parser_check_publickey.add_argument('--host', type=str, required=True, help='Hostname or IP address')
    parser_check_publickey.add_argument('--port', type=int, default=22, help='port (default: 22)')
    parser_check_publickey.add_argument('--username', type=str, required=True, help='username to check')
    parser_check_publickey.add_argument('--public-key', type=str, required=True, help='publickey to check')

    parser_check_privatekey = subparsers.add_parser(
        'check-privatekey', help='checks a username and privatekey against a server'
    )
    parser_check_privatekey.add_argument('--host', type=str, required=True, help='Hostname or IP address')
    parser_check_privatekey.add_argument('--port', type=int, default=22, help='port (default: 22)')
    parser_check_privatekey.add_argument('--username', type=str, required=True, help='username to check')
    parser_check_privatekey.add_argument('--private-key', type=str, required=True, help='privatekey to check')
    parser_check_privatekey.add_argument('--private-key-passphrase', type=str, help='used to decrypt the private key')

    parser_scan_auth = subparsers.add_parser(
        'get-auth', help='checks authentication methods'
    )
    parser_scan_auth.add_argument('--host', type=str, required=True, help='Hostname or IP address')
    parser_scan_auth.add_argument('--port', type=int, default=22, help='port (default: 22)')


def run_audit(args: argparse.Namespace) -> None:
    if args.audit_subparser_name == 'check-publickey':
        if not check_publickey(args):
            sys.exit(1)
    if args.audit_subparser_name == 'check-privatekey':
        if not check_privatekey(args):
            sys.exit(1)
    elif args.audit_subparser_name == 'get-auth':
        auth_methods = Authenticator.get_auth_methods(args.host, args.port)
        if auth_methods:
            print(",".join(auth_methods))
