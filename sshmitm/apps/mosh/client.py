import argparse
import select
import shutil
import signal
import socket
import sys
import termios
import tty
from typing import Any

import pyte

from sshmitm.moduleparser import SubCommand

# pyte named colors → ANSI 256-palette index
_NAMED: dict[str, int] = {
    "black": 0,
    "red": 1,
    "green": 2,
    "yellow": 3,
    "blue": 4,
    "magenta": 5,
    "cyan": 6,
    "white": 7,
    "bright_black": 8,
    "bright_red": 9,
    "bright_green": 10,
    "bright_yellow": 11,
    "bright_blue": 12,
    "bright_magenta": 13,
    "bright_cyan": 14,
    "bright_white": 15,
}


def _color(color: str | int, bg: bool) -> str:
    layer = 48 if bg else 38
    default_code = 49 if bg else 39
    if color == "default":
        return f"\x1b[{default_code}m"
    if isinstance(color, int):
        return f"\x1b[{layer};5;{color}m"
    idx = _NAMED.get(color)
    if idx is not None:
        return f"\x1b[{layer};5;{idx}m"
    return ""


def _render_line(screen: pyte.Screen, y: int) -> str:
    """Render one screen row as an ANSI string, emitting codes only on attribute changes."""
    parts = ["\x1b[0m"]
    line = screen.buffer[y]

    pfg: str | int = "default"
    pbg: str | int = "default"
    pbold = pital = punder = pstrike = prev = False

    for x in range(screen.columns):
        char = line[x]
        state = (
            char.fg,
            char.bg,
            char.bold,
            char.italics,
            char.underscore,
            char.strikethrough,
            char.reverse,
        )
        if state != (pfg, pbg, pbold, pital, punder, pstrike, prev):
            attrs: list[str] = []
            if char.bold:
                attrs.append("1")
            if char.italics:
                attrs.append("3")
            if char.underscore:
                attrs.append("4")
            if char.strikethrough:
                attrs.append("9")
            if char.reverse:
                attrs.append("7")
            reset = "\x1b[0;" + ";".join(attrs) + "m" if attrs else "\x1b[0m"
            parts.append(reset + _color(char.fg, False) + _color(char.bg, True))
            pfg, pbg = char.fg, char.bg
            pbold, pital, punder, pstrike, prev = (
                char.bold,
                char.italics,
                char.underscore,
                char.strikethrough,
                char.reverse,
            )
        parts.append(char.data or " ")

    return "".join(parts)


def _cursor(screen: pyte.Screen) -> str:
    s = f"\x1b[{screen.cursor.y + 1};{screen.cursor.x + 1}H\x1b[0m"
    if not screen.cursor.hidden:
        s += "\x1b[?25h"
    return s


def _full_render(screen: pyte.Screen) -> bytes:
    lines = ["\x1b[?25l\x1b[H"]
    for y in range(screen.lines):
        lines.append(_render_line(screen, y))
        if y < screen.lines - 1:
            lines.append("\r\n")
    lines.append(_cursor(screen))
    screen.dirty.clear()
    return "".join(lines).encode("utf-8", errors="replace")


def _dirty_render(screen: pyte.Screen) -> bytes:
    """Redraw only rows that pyte marked as changed since the last render."""
    if not screen.dirty:
        return b""
    parts = ["\x1b[?25l"]
    for y in sorted(screen.dirty):
        parts.append(f"\x1b[{y + 1};1H")
        parts.append(_render_line(screen, y))
    parts.append(_cursor(screen))
    screen.dirty.clear()
    return "".join(parts).encode("utf-8", errors="replace")


def _run_client(host: str, port: int) -> None:
    cols, rows = shutil.get_terminal_size()
    screen = pyte.Screen(cols, rows)
    stream = pyte.ByteStream(screen)
    out = sys.stdout.buffer

    def on_resize(signum: object = None, frame: object = None) -> None:
        nonlocal cols, rows
        del signum
        del frame
        cols, rows = shutil.get_terminal_size()
        screen.resize(rows, cols)
        out.write(_full_render(screen))
        out.flush()

    signal.signal(signal.SIGWINCH, on_resize)

    # cbreak: disables echo and line buffering, but keeps ISIG so Ctrl+C still works.
    saved_tty: list[Any] | None = None
    if sys.stdin.isatty():
        saved_tty = termios.tcgetattr(sys.stdin)
        tty.setcbreak(sys.stdin)

    # Alternate screen buffer: saves terminal content and restores it on exit.
    out.write(b"\x1b[?1049h\x1b[2J\x1b[H\x1b[?25l")
    out.flush()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((host, port))
            first = True
            while True:
                ready, _, _ = select.select([sock], [], [], 0.05)
                if not ready:
                    continue
                chunk = sock.recv(65536)
                if not chunk:
                    break
                stream.feed(chunk)
                out.write(_full_render(screen) if first else _dirty_render(screen))
                out.flush()
                first = False
    except ConnectionRefusedError:
        print(f"Connection refused: {host}:{port}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    finally:
        out.write(b"\x1b[?1049l")
        out.flush()
        if saved_tty is not None:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, saved_tty)


class Mosh(SubCommand):
    """MOSH tools"""

    @classmethod
    def config_section(cls) -> str | None:
        return None

    def register_arguments(self) -> None:
        subparsers = self.parser.add_subparsers(
            title="Available commands",
            dest="mosh_subparser_name",
            metavar="mosh-command",
        )
        subparsers.required = True

        parser_client = subparsers.add_parser(
            "client",
            help="connect to a MOSH monitor and display the intercepted session",
        )
        parser_client.add_argument("host", type=str, help="monitor host")
        parser_client.add_argument("port", type=int, help="monitor port")

    def execute(self, args: argparse.Namespace) -> None:
        if args.mosh_subparser_name == "client":
            _run_client(args.host, args.port)
