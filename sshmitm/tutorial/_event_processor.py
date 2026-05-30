"""General SSH-MITM event interpreter for the tutorial server.

Maps raw JSON log records received from SSH-MITM into typed, human-readable
display entries.  The mapping is data-driven: each known event name has a
spec dict whose values are either plain strings (formatted with the raw
record's fields) or callables that receive the raw dict and return a string.

Adding a new event requires only one entry in _EVENT_SPECS — no new code paths.
"""

from __future__ import annotations

from typing import Any, Callable

# ---------------------------------------------------------------------------
# Type alias for a spec value: static string or callable(raw) -> str | None
# ---------------------------------------------------------------------------

_Val = str | Callable[[dict[str, Any]], str | None]


# ---------------------------------------------------------------------------
# Event spec table
#
# Keys per spec:  type, title, detail, hint
# type can also be a callable(raw) -> "success"|"warning"|"error"|"info"
# ---------------------------------------------------------------------------

def _pw(r: dict) -> str:
    """Format intercepted password if present."""
    p = r.get("password")
    return f"  [{p}]" if p is not None else ""


def _remote(r: dict) -> str:
    h, p = r.get("remote_host"), r.get("remote_port")
    return f" → {h}:{p}" if h else ""


_EVENT_SPECS: dict[str, dict[str, _Val]] = {

    # --- None-auth (SSH method-discovery probe) ---
    # A successful none auth means the server accepts it as a real login method.
    # A failed none auth is always the standard SSH handshake probe — never show it.
    "auth_none_success": {
        "type": "info",
        "title": lambda r: f"Remote server accepted none auth for {r.get('username', '')}",
        "detail": "The server allows login without credentials. SSH-MITM will proxy this.",
    },

    # --- Session lifecycle ---
    "session_started": {
        "type": "success",
        "title": "SSH session established through SSH-MITM",
        "detail": "The client has successfully authenticated and a session is now active.",
    },
    "session_closed": {
        "type": "info",
        "title": "SSH session closed",
    },
    "session_rejected_early": {
        "type": "warning",
        "title": "Connection rejected before authentication",
        "detail": "The SSH client likely got a host key fingerprint warning and aborted.",
        "hint": "Remove the cached key: ssh-keygen -R '[HOST]:PORT'",
    },

    # --- Remote server capabilities ---
    "remote_auth_methods": {
        "type": "info",
        "title": lambda r: "Remote server supports: " + ", ".join(r.get("methods") or []),
        "detail": "SSH-MITM will only advertise these methods to the connecting client.",
    },

    # --- Password authentication ---
    "auth_password_attempt": {
        "type": lambda r: "success" if r.get("success") else "warning",
        "title": lambda r: (
            f"SSH-MITM intercepted a password login for {r.get('username', '')}"
        ),
        "detail": lambda r: (
            f"Intercepted password: {r['password']!r} — "
            + ("accepted by the remote server." if r.get("success") else "rejected by the remote server.")
        ) if r.get("password") is not None else (
            "accepted by the remote server." if r.get("success") else "rejected by the remote server."
        ),
    },
    "auth_password_disabled": {
        "type": "error",
        "title": "Client tried password login, but password auth is disabled",
        "detail": "SSH-MITM is configured to reject password authentication.",
    },

    # --- Remote authentication result ---
    "remote_auth_success": {
        "type": "success",
        "title": lambda r: f"Login succeeded — {r.get('username', '')} authenticated at {r.get('remote_host', 'remote server')}",
        "detail": lambda r: "  ".join(filter(None, [
            f"intercepted password: {r['password']!r}" if r.get("password") is not None
            else ("password was forwarded" if r.get("has_password") else ""),
            "SSH agent was forwarded" if r.get("has_agent") else "",
        ])) or None,
    },
    "remote_auth_failed": {
        "type": "error",
        "title": lambda r: f"Login failed — {r.get('username', '')} could not authenticate at {r.get('remote_host', 'remote server')}",
        "detail": lambda r: (
            f"The password {r['password']!r} was rejected by the remote server."
            if r.get("password") is not None else
            "The remote server rejected the credentials."
        ),
    },

    # --- Public key authentication ---
    "pubkey_valid_found": {
        "type": "info",
        "title": lambda r: f"SSH-MITM found a valid public key for {r.get('username', '')}",
        "detail": lambda r: (
            f"Key type: {r.get('keytype', '')}  Fingerprint: {r.get('fingerprint', '')}".strip()
            or None
        ),
    },

    # --- Agent forwarding ---
    "agent_forwarding_accepted": {
        "type": "success",
        "title": "SSH agent successfully forwarded through SSH-MITM",
        "detail": "SSH-MITM now has access to the client's agent keys.",
    },
    "agent_forwarding_denied": {
        "type": "warning",
        "title": "SSH agent was not forwarded",
        "detail": "The client did not request agent forwarding, or SSH-MITM could not access the agent.",
    },

    # --- Channel / command interception ---
    "channel_ssh_command": {
        "type": "info",
        "title": lambda r: f"SSH-MITM intercepted a command: {r.get('command', '')}",
        "detail": "This command was captured as it passed through the proxy.",
    },

    # --- Port forwarding ---
    "port_forward_denied": {
        "type": "warning",
        "title": "Client requested port forwarding, but it was denied",
        "detail": "SSH-MITM is not configured to allow TCP port forwarding.",
    },
    "port_forward_direct": {
        "type": "info",
        "title": lambda r: f"Client opened a TCP tunnel to {r.get('destination', '')}",
        "detail": "SSH-MITM is forwarding this TCP connection through the proxy.",
    },

    # --- Honeypot ---
    "honeypot_redirect": {
        "type": "warning",
        "title": "Client was silently redirected to a honeypot",
        "detail": "Public key auth failed and no agent was forwarded — SSH-MITM connected the client to the configured fallback host instead.",
    },
    "honeypot_failed": {
        "type": "error",
        "title": "Honeypot authentication failed",
        "detail": "SSH-MITM could not authenticate the client against the fallback host either.",
    },

    # --- Server ready ---
    "server_listening": {
        "type": "info",
        "title": lambda r: f"SSH-MITM listening on port {r['port']}" if r.get("port") else "SSH-MITM started",
    },
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def process(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Interpret one raw SSH-MITM log record.

    Returns a display dict with keys type/title (and optionally detail/hint),
    or None if the record is not worth showing.
    """
    event = raw.get("event", "")
    if event and event in _EVENT_SPECS:
        return _apply(_EVENT_SPECS[event], raw)

    # Unstructured WARNING / ERROR logs are always worth showing
    level = raw.get("level", "INFO")
    if level in ("WARNING", "ERROR"):
        msg = raw.get("message", "").strip()
        if msg:
            return {"type": "warning" if level == "WARNING" else "error", "title": msg}

    return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _resolve(val: _Val, raw: dict[str, Any]) -> str | None:
    if callable(val):
        return val(raw)
    if isinstance(val, str) and "{" in val:
        try:
            return val.format_map(raw)
        except (KeyError, ValueError):
            pass
    return val  # type: ignore[return-value]


def _apply(spec: dict[str, _Val], raw: dict[str, Any]) -> dict[str, Any] | None:
    result: dict[str, Any] = {}
    for key in ("type", "title", "detail", "hint"):
        if key not in spec:
            continue
        val = _resolve(spec[key], raw)
        if val:
            result[key] = val
    if "title" not in result:
        return None
    result.setdefault("type", "info")
    return result
