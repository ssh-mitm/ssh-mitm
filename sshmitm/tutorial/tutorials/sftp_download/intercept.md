## The file Alice downloaded

Alice just downloaded a file from the staging server through SSH-MITM —
without noticing anything unusual.

Switch to the **SSH-MITM terminal**. The proxy logs every SFTP operation
it intercepts, including the path of each file that was opened for reading.

Find the **filename** in the SSH-MITM output and enter it in the field
below.

---

**Why does this work?**

SFTP runs as a subsystem on top of the SSH channel. SSH-MITM intercepts
that channel before it reaches the real server, so it can observe every
SFTP command — including `open`, `read`, `write`, and `close` — in
plaintext, regardless of SSH encryption.

A real attacker in this position could also read or modify the file
content in transit without the client or server noticing any change.

---

*The engagement continues. In the next tutorial, Alice runs an automated
command on the production server.*
