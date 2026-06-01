## What you will learn

SFTP (SSH File Transfer Protocol) transfers files over an encrypted SSH
channel — but encryption alone does not prevent interception by a
man-in-the-middle positioned on the network path.

SSH-MITM terminates the client's handshake with its own host key, decrypts
all traffic, and forwards it to the real server. This means every file
transfer passes through the proxy in plaintext, including the filename,
the direction of the transfer, and the file content itself.

In this tutorial you take the role of the attacker. A developer will
connect to the target server and download a sensitive file via SFTP.
You will intercept the session with SSH-MITM and identify which file was
transferred — without the developer noticing anything unusual.

---

In the next step you will start SSH-MITM between the developer's SFTP
client and the target server.
