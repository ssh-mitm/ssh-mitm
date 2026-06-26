"""Condition types for tutorial step completion.

Each condition is a callable that receives a :class:`TutorialContext` and
returns *True* when the step should be marked complete.

Conditions with mutable state implement a ``reset()`` method; the runner
calls it whenever the step that owns them becomes active so that state from
a previous run does not carry over.

Example — common patterns::

    # Step completes immediately (e.g. automated setup)
    condition=TRUE()

    # Step waits for ssh-mitm to start (edge-triggered: won't skip if already running)
    condition=PortOpen("sshmitm_port")

    # Step waits for an SSH auth event
    condition=AuthEvent("password")

    # Pure info step — user reads and clicks Continue
    condition=Continue()

    # Step with one user input
    condition=UserInput("password_value", prompt="Enter the intercepted password:")

    # Step with multiple user inputs (all must be filled correctly)
    condition=All(
        UserInput("password_value", prompt="Enter the intercepted password:"),
        UserInput("password_user",  prompt="Enter the intercepted username:"),
    )

    # Wait for an event AND require user confirmation
    condition=All(AuthEvent("password"), Continue())
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from sshmitm.tutorial._context import TutorialContext


@runtime_checkable
class Condition(Protocol):
    """Protocol for step-completion conditions."""

    def __call__(self, ctx: "TutorialContext") -> bool: ...


class TRUE:
    """Completes immediately — use for automated setup steps.

    The step is still displayed in the sidebar; it advances without any user
    action as soon as it becomes active.
    """

    def __call__(self, ctx: "TutorialContext") -> bool:
        return True


class Continue:
    """Completes when the user explicitly clicks the **Continue** button.

    Use this for purely informational steps or when you want the user to
    acknowledge an event before moving on.  The web UI shows a *Continue*
    button whenever the active step's condition tree contains this type.
    """

    def __init__(self, label: str = "Continue") -> None:
        self.label = label

    def reset(self) -> None:
        pass  # state lives in ctx.acknowledged, cleared by the runner

    def __call__(self, ctx: "TutorialContext") -> bool:
        return ctx.acknowledged


class PortOpen:
    """True while the TCP port named by *var* is listening.

    Since steps never auto-advance, there is no need for edge-triggering:
    the Continue button simply becomes active whenever the port is open,
    regardless of whether it was already open when the step started.

    When the port is already open on step activation, ``ctx.hint_override``
    is set to an informational message so the user knows they can continue
    without restarting ssh-mitm.
    """

    def __init__(self, var: str) -> None:
        self.var = var
        self._was_open_at_start: bool | None = None  # None = first check not yet done

    def reset(self) -> None:
        self._was_open_at_start = None

    def __call__(self, ctx: "TutorialContext") -> bool:
        port = int(ctx.tutorial_session_data.get(self.var, 0))
        open_ = ctx.port_open(port)

        if self._was_open_at_start is None:
            self._was_open_at_start = open_
            if open_:
                ctx.hint_override = (
                    "SSH-MITM is already running on port {"
                    + self.var
                    + "}. "
                    "If you started it with the command shown below, click **Continue**."
                )
                ctx.hint_override_type = "info"
        elif not open_:
            # Port closed after step activation — clear the "already running" message
            self._was_open_at_start = False
            ctx.hint_override = None

        return open_


class AuthEvent:
    """True once an auth attempt with *method* and *success* has been seen."""

    def __init__(self, method: str, success: bool = True) -> None:
        self.method = method
        self.success = success

    def __call__(self, ctx: "TutorialContext") -> bool:
        return ctx.has_auth_event(self.method, self.success)


class SFTPEvent:
    """True once an SFTP *operation* (optionally matching *path_pattern*) occurs."""

    def __init__(self, operation: str, path_pattern: str | None = None) -> None:
        self.operation = operation
        self.path_pattern = path_pattern

    def __call__(self, ctx: "TutorialContext") -> bool:
        return ctx.has_sftp_event(self.operation, self.path_pattern)


class ShellInput:
    """True once shell input matching *pattern* (regex) is observed."""

    def __init__(self, pattern: str) -> None:
        self.pattern = pattern

    def __call__(self, ctx: "TutorialContext") -> bool:
        return ctx.has_shell_input(self.pattern)


class ExecCommand:
    """True once an exec command matching *pattern* (regex) is observed."""

    def __init__(self, pattern: str) -> None:
        self.pattern = pattern

    def __call__(self, ctx: "TutorialContext") -> bool:
        return ctx.has_exec_command(self.pattern)


class UserInput:
    """True once the user has entered the correct value for ``credentials[key]``.

    *prompt* is shown as the label next to the input field in the web UI.
    Multiple ``UserInput`` instances inside an :class:`All` condition are all
    displayed at once; the step completes only after every one is correct.
    """

    def __init__(self, key: str, prompt: str = "") -> None:
        self.key = key
        self.prompt = prompt

    def reset(self) -> None:
        pass  # state lives in ctx.user_inputs, cleared by the runner

    def __call__(self, ctx: "TutorialContext") -> bool:
        expected = str(ctx.tutorial_session_data.get(self.key, ""))
        return ctx.user_inputs.get(self.key) == expected


class All:
    """True once **all** child conditions are satisfied."""

    def __init__(self, *conditions: Condition) -> None:
        self.conditions = conditions

    def reset(self) -> None:
        for c in self.conditions:
            if hasattr(c, "reset"):
                c.reset()  # type: ignore[union-attr]

    def __call__(self, ctx: "TutorialContext") -> bool:
        return all(c(ctx) for c in self.conditions)


class Any:
    """True once **any** child condition is satisfied."""

    def __init__(self, *conditions: Condition) -> None:
        self.conditions = conditions

    def reset(self) -> None:
        for c in self.conditions:
            if hasattr(c, "reset"):
                c.reset()  # type: ignore[union-attr]

    def __call__(self, ctx: "TutorialContext") -> bool:
        return any(c(ctx) for c in self.conditions)


# ---------------------------------------------------------------------------
# Helpers for inspecting condition trees
# ---------------------------------------------------------------------------

def collect_user_inputs(condition: object) -> list[UserInput]:
    """Return all :class:`UserInput` instances found anywhere in *condition*."""
    found: list[UserInput] = []
    _walk(condition, found)
    return found


def has_continue(condition: object) -> bool:
    """Return True if *condition* contains a :class:`Continue` instance."""
    found: list[Continue] = []
    _walk_continue(condition, found)
    return bool(found)


def _walk(node: object, out: list[UserInput]) -> None:
    if isinstance(node, UserInput):
        out.append(node)
    elif isinstance(node, (All, Any)):
        for child in node.conditions:
            _walk(child, out)


def _walk_continue(node: object, out: list[Continue]) -> None:
    if isinstance(node, Continue):
        out.append(node)
    elif isinstance(node, (All, Any)):
        for child in node.conditions:
            _walk_continue(child, out)


# ---------------------------------------------------------------------------
# Fingerprint-state check (CVE-2020-14145)
# ---------------------------------------------------------------------------

class FingerprintState:
    """True when ``tutorial_session_data["fingerprint_state"]`` equals *expected*.

    Used together with :class:`~sshmitm.tutorial._client_actions.SSHOpenSSHKnownHostsAction`
    which sets the value to ``"new"`` or ``"cached"`` after each connection.
    """

    def __init__(self, expected: str) -> None:
        self.expected = expected

    def __call__(self, ctx: "TutorialContext") -> bool:
        return ctx.tutorial_session_data.get("fingerprint_state") == self.expected


# ---------------------------------------------------------------------------
# SSH-MITM process check
# ---------------------------------------------------------------------------

class SSHMitmRunning:
    """Wait for ssh-mitm to start with the correct arguments.

    Behaves like :class:`PortOpen` but additionally inspects the running
    process's command line.  When ssh-mitm is already running but was
    started with the **wrong** essential arguments, the condition sets
    ``ctx.hint_override`` with an actionable warning so the user knows what
    to do instead of silently waiting forever.

    If ssh-mitm is running with *matching* arguments the step completes
    immediately — no edge-triggering, because a pre-existing correct
    instance is fine.

    *required* maps CLI flag names to expected values.  Values are resolved
    against ``ctx.tutorial_session_data`` first, then treated as literals::

        SSHMitmRunning("sshmitm_port", {
            "--remote-host": "127.0.0.1",    # literal
            "--remote-port": "mock_port",     # looked up in credentials
            "--listen-port": "sshmitm_port",  # looked up in credentials
        })
    """

    def __init__(self, port_var: str, required: dict[str, str]) -> None:
        self.port_var = port_var
        self.required = required

    def __call__(self, ctx: "TutorialContext") -> bool:
        port = int(ctx.tutorial_session_data.get(self.port_var, 0))
        if not ctx.port_open(port):
            ctx.hint_override = None
            return False

        # Port is open — resolve expected values against credentials
        resolved = {
            flag: str(ctx.tutorial_session_data.get(val, val))
            for flag, val in self.required.items()
        }

        procs = _find_sshmitm_cmdlines()
        if not procs:
            # Something else is on the port — not our concern, let it pass
            ctx.hint_override = None
            return True

        # Try each found process
        for cmdline in procs:
            ok, _ = _check_args(cmdline, resolved)
            if ok:
                ctx.hint_override = None
                return True

        # ssh-mitm is running but with mismatched arguments — find best description
        best: list[str] | None = None
        for cmdline in procs:
            _, mismatches = _check_args(cmdline, resolved)
            if best is None or len(mismatches) < len(best):
                best = mismatches

        if best:
            problems = "; ".join(best)
            ctx.hint_override = (
                f"SSH-MITM is already running but with different arguments "
                f"({problems}). "
                f"Stop it and restart with the command shown below."
            )
        return False


def _find_sshmitm_cmdlines() -> list[list[str]]:
    """Return command-line argument lists for all running ssh-mitm processes."""
    import glob
    results: list[list[str]] = []
    try:
        for path in glob.glob("/proc/[0-9]*/cmdline"):
            try:
                data = open(path, "rb").read()  # noqa: WPS515
                parts = [p.decode("utf-8", errors="replace") for p in data.split(b"\x00") if p]
                if parts and any("ssh-mitm" in a or "sshmitm" in a for a in parts):
                    results.append(parts)
            except OSError:
                pass
    except OSError:
        pass
    return results


def _check_args(
    cmdline: list[str], required: dict[str, str]
) -> tuple[bool, list[str]]:
    """Return (all_match, list_of_mismatch_descriptions).

    Handles both ``--flag value`` and ``--flag=value`` forms.
    Extra arguments in *cmdline* are ignored.
    """
    parsed: dict[str, str] = {}
    i = 0
    while i < len(cmdline):
        token = cmdline[i]
        if token.startswith("-") and "=" in token:
            k, v = token.split("=", 1)
            parsed[k] = v
            i += 1
        elif (
            token.startswith("-")
            and i + 1 < len(cmdline)
            and not cmdline[i + 1].startswith("-")
        ):
            parsed[token] = cmdline[i + 1]
            i += 2
        else:
            i += 1

    mismatches: list[str] = []
    for flag, expected in required.items():
        actual = parsed.get(flag)
        if actual is None:
            mismatches.append(f"{flag} is missing")
        elif actual != expected:
            mismatches.append(f"{flag} is {actual!r} (expected {expected!r})")

    return len(mismatches) == 0, mismatches
