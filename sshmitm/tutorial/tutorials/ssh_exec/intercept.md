## Command execution in progress

A developer just ran a command on the target server via SSH — passing
through SSH-MITM without realising it.

Switch to the **SSH-MITM terminal**. The proxy logs every SSH exec
request it intercepts, including the full command string.

Find the **command** in the SSH-MITM output and enter it in the field
below to confirm you intercepted the execution.

---

**Why does this work?**

Non-interactive SSH commands use the exec channel type instead of a
shell. SSH-MITM intercepts this channel before forwarding it to the
real server, so it sees the exact command string in plaintext —
regardless of SSH encryption.

**What an attacker can do with this**

Beyond reading command strings, a real attacker in this position could
also modify the command before it reaches the server, or intercept and
alter the output returned to the client.
