"""Tutorial execution context passed to all condition callables."""

from __future__ import annotations

import dataclasses


@dataclasses.dataclass
class AuthEventData:
    method: str
    username: str
    success: bool


@dataclasses.dataclass
class SFTPEventData:
    operation: str
    path: str


@dataclasses.dataclass
class ShellInputData:
    data: bytes


@dataclasses.dataclass
class ExecCommandData:
    command: str


class TutorialContext:
    """Shared state passed to every condition callable during a tutorial session.

    The runner populates *credentials* at startup and appends to the event
    lists as the mock server fires callbacks.  Conditions read from this object
    to decide whether their step is complete.
    """

    def __init__(self, tutorial_session_data: dict[str, object]) -> None:
        self.tutorial_session_data: dict[str, object] = tutorial_session_data

        # Event queues — appended to by the runner; read by conditions.
        # Cleared at the start of each step so conditions see only events
        # that occurred while the step was active.
        self.auth_events: list[AuthEventData] = []
        self.sftp_events: list[SFTPEventData] = []
        self.shell_input_events: list[ShellInputData] = []
        self.exec_command_events: list[ExecCommandData] = []

        # User-supplied values keyed by credential name (e.g. "password_value").
        # Each entry is set by the web server when the user submits an input
        # field.  Cleared at the start of each step.
        self.user_inputs: dict[str, str] = {}

        # Set to True when the user clicks "Continue" for a Continue() condition.
        # Cleared at the start of each step.
        self.acknowledged: bool = False

        # Set by conditions to override hint_waiting with a dynamic message.
        # None means use the step's static hint_waiting text.
        self.hint_override: str | None = None
        self.hint_override_type: str = "info"  # "info" | "warning" | "error"

        # Set to True by a condition when a Continue button must be shown even
        # though the step's static condition tree contains no Continue() node
        # (e.g. PortOpen when the port was already open on step activation).
        self.needs_continue: bool = False

    # ------------------------------------------------------------------
    # Step lifecycle
    # ------------------------------------------------------------------

    def clear_step_state(self) -> None:
        """Clear all per-step state. Called by the runner when a step activates."""
        self.auth_events.clear()
        self.sftp_events.clear()
        self.shell_input_events.clear()
        self.exec_command_events.clear()
        self.user_inputs.clear()
        self.acknowledged = False
        self.hint_override = None
        self.hint_override_type = "info"
        self.needs_continue = False

    # ------------------------------------------------------------------
    # Port check
    # ------------------------------------------------------------------

    def port_open(self, port: int) -> bool:
        """Return True if *port* is currently listening (Linux /proc/net/tcp)."""
        hex_port = f"{port:04X}"
        for path in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(path) as f:
                    next(f)
                    for line in f:
                        parts = line.split()
                        if len(parts) > 3 and parts[3] == "0A":
                            _, local_port = parts[1].rsplit(":", 1)
                            if local_port.upper() == hex_port:
                                return True
            except OSError:
                pass
        return False

    # ------------------------------------------------------------------
    # Event queries used by conditions
    # ------------------------------------------------------------------

    def has_auth_event(self, method: str, success: bool) -> bool:
        return any(
            e.method == method and e.success == success
            for e in self.auth_events
        )

    def has_sftp_event(self, operation: str, path_pattern: str | None = None) -> bool:
        import re
        for e in self.sftp_events:
            if e.operation != operation:
                continue
            if path_pattern is None or re.search(path_pattern, e.path):
                return True
        return False

    def has_shell_input(self, pattern: str) -> bool:
        import re
        return any(
            re.search(pattern, e.data.decode("utf-8", errors="replace"))
            for e in self.shell_input_events
        )

    def has_exec_command(self, pattern: str) -> bool:
        import re
        return any(re.search(pattern, e.command) for e in self.exec_command_events)
