## Credentials intercepted

A developer just connected to the target server through SSH-MITM and
authenticated with a password.

Switch to the **SSH-MITM terminal** — the intercepted password is logged
there in plaintext, even though the SSH session was fully encrypted from
the developer's point of view.

Find the **username** and **password** in the SSH-MITM output and enter
both values in the fields below to confirm you got them.

---

**Why does this work?**

SSH encrypts the channel between client and server, but only against
third parties.  It cannot protect data from the endpoint it is actually
talking to.  SSH-MITM terminates the client's handshake with its own host
key, decrypts all traffic, and opens a separate encrypted connection to
the real server.  The password passes through the proxy in plaintext before
being forwarded.

**How SSH normally prevents this**

SSH's host key verification is designed to detect exactly this attack.
On first connection the client asks to confirm the server's fingerprint.
If that step is skipped or the fingerprint is accepted blindly, a
man-in-the-middle can intercept everything unnoticed.
