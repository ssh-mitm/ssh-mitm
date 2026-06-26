<div class="scenario-box" markdown="1">
Max connected to `files.logfileinc.internal` via SFTP, opened a file, and downloaded it to his laptop. The transfer completed successfully from his point of view. SSH-MITM logged every step.
</div>

### What to look for

Switch to the **SSH-MITM terminal**. When Max's SFTP client sent the `open` request, SSH-MITM logged the full file path:

```
INFO     sftp open: /...
```

The proxy logs all SFTP operations in sequence — `open`, `read`, `close` — so you can see exactly which file was accessed and in which direction.

### Why does this work?

SFTP runs as a subsystem on top of the SSH connection. When SSH-MITM intercepts the connection, it terminates Max's SSH session and acts as the server for the SFTP subsystem. The proxy parses every SFTP protocol message before forwarding it, so it sees the filename, transfer direction, and full file content — regardless of SSH encryption.

An attacker in this position can do more than log filenames:

- Read the complete contents of any downloaded or uploaded file
- Modify a file in transit without the client or server detecting any change
- Selectively block transfers or substitute different content

The integrity guarantees of SSH apply to the transport layer only. They do not protect against the endpoint the client is actually connected to.

<div class="task-box" markdown="1">
Find the filename Max downloaded in the SSH-MITM terminal output and enter it in the field above.
</div>

> **Further reading:** [File Transfers](https://docs.ssh-mitm.at/audit_guide/file_transfer.html)
