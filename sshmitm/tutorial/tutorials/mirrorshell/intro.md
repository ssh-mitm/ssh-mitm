<div class="objectives-box" markdown="1">

- See how SSH-MITM's mirrorshell feature exposes a live interactive session to a second terminal
- Understand why an unattended authenticated session is a significant attack surface
- Learn how to attach to a mirrored session and interact with the remote device as the legitimate user

</div>

<div class="note-box" markdown="1">
Most security thinking focuses on the moment of authentication. Once authenticated, the session itself is rarely considered. SSH-MITM can expose an active session as a mirrorshell: a live copy of the terminal, open for the duration of the connection. If the legitimate user steps away, the session remains open — and so does the attacker's window.
</div>

<div class="scenario-box" markdown="1">
Thomas Webb, **Logfile Inc.'s** network administrator, connects to `router01.logfileinc.internal` to check the running configuration — a routine task he has done dozens of times. He authenticates through SSH, the router prompt appears, and then his phone rings. He gets up to take the call and walks away from the terminal.

The session is still open.

SSH-MITM sits between Thomas and the router. It exposes the live session via a **mirrorshell** port: a local port you can connect to with a standard SSH client. Once connected, you see exactly what Thomas's terminal shows. Any command you type is sent to the router. Any output the router sends appears in both terminals.

Thomas has no indication that a second party is in his session.

Your goal: attach to the mirrorshell, read the router's running configuration, and extract the SNMP read-write community string stored there.
</div>

---

> **Further reading:** [Terminal Sessions](https://docs.ssh-mitm.at/user_guide/sessions.html)
