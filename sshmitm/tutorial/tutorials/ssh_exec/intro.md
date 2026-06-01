## What you will learn

When a developer runs a single command non-interactively over SSH —
for example `ssh user@server "cat ~/.aws/credentials"` — the command
travels through the encrypted channel just like any other SSH traffic.

SSH-MITM intercepts the channel before it reaches the real server,
which means it can log every command that is executed via SSH exec,
including the exact command string and the output returned by the server.

In this tutorial you take the role of the attacker. A developer will
run a sensitive command on the target server through SSH-MITM without
knowing the connection is intercepted. You will identify the exact
command from the SSH-MITM log.

---

In the next step you will start SSH-MITM between the developer and the
target server.
