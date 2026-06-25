## Chapter 3 — The File Transfer

Alice is preparing a quarterly review for management.
She connects to the staging server and downloads a file via SFTP —
the same encrypted channel she trusts for all her sensitive work.

What she does not know: SSH encrypts the channel against third parties,
not against the proxy she is talking to. SSH-MITM terminates Alice's
handshake with its own host key, decrypts all traffic, and forwards it
to the real server.

Every file that passes through is visible in plaintext — including the
filename, the direction of the transfer, and the file content.

---

**What you will see**

SSH-MITM logs every SFTP operation it intercepts: `open`, `read`,
`write`, `close`. You will find the filename in the proxy output
as soon as Alice's client sends the first `open` request.

In the next step, start SSH-MITM and wait for Alice's SFTP session.
