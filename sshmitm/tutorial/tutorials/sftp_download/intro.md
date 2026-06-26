<div class="objectives-box" markdown="1">

- See how SSH-MITM intercepts SFTP file transfers and logs file paths in cleartext
- Understand why SFTP encryption does not protect file metadata or content from a proxy
- Learn what an attacker can do beyond logging — including reading or modifying file content in transit

</div>

<div class="note-box" markdown="1">
SFTP runs as a subsystem on top of SSH. Users often assume that because the transport is encrypted, file names and contents are protected from any observer on the network. That is true for passive eavesdroppers — but not for a MITM proxy that terminates the SSH session. SSH-MITM parses every SFTP protocol message before forwarding it, so it sees every operation: which files are opened, read, written, or deleted, and their full content.
</div>

<div class="scenario-box" markdown="1">
**Logfile Inc.** stores shared project files on `files.logfileinc.internal`, an internal file server accessible via SFTP.

Max Morgan opens an SFTP connection to retrieve a file as part of his regular workflow. He navigates to the directory, downloads the file, and closes the connection. The transfer completes successfully. The file arrives intact.

SSH-MITM sits between Max and the file server. The proxy logs the filename and path as soon as Max's client sends the first `open` request.
</div>

---

> **Further reading:** [File Transfers](https://docs.ssh-mitm.at/user_guide/file_transfer.html)
