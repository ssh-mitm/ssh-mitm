## File transfer in progress

A developer just connected to the target server and downloaded a file
via SFTP — passing through SSH-MITM without realising it.

Switch to the **SSH-MITM terminal**. The proxy logs every SFTP operation
it intercepts, including the path of each file that was read from the
server.

Find the **filename** in the SSH-MITM output and enter it in the field
below to confirm you intercepted the transfer.

---

**Why does this work?**

SFTP runs as a subsystem on top of the SSH channel. SSH-MITM intercepts
the channel before it reaches the real server, so it can observe and log
every SFTP command — including `open`, `read`, `write`, and `close` — in
plaintext, regardless of the SSH encryption.

**What an attacker can do with this**

Beyond identifying filenames, a real attacker in this position could also
read or modify the file content in transit without the client or server
noticing any change.
