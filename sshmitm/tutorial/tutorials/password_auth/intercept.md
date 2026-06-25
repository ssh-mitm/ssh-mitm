## Alice's password

Alice just connected to the dev server through SSH-MITM.

Switch to the **SSH-MITM terminal** — her password is logged there in
plaintext, even though the SSH session was fully encrypted from her point
of view.

Find the **username** and **password** in the SSH-MITM output and enter
both values in the fields below.

---

**Why does this work?**

SSH encrypts the channel between client and server, but only against
third parties. It cannot protect data from the endpoint it is actually
talking to. SSH-MITM terminates Alice's handshake with its own host key,
decrypts all traffic, and opens a separate encrypted connection to the
real server. Her password passes through the proxy in plaintext before
being forwarded.

**How SSH normally prevents this**

SSH's host key verification is designed to detect exactly this attack.
On first connection the client asks to confirm the server's fingerprint.
If that step is skipped or the fingerprint is accepted blindly, a
man-in-the-middle can intercept everything unnoticed.

---

*The engagement continues. In the next tutorial, Alice upgrades to key-based
authentication — but makes a common mistake.*
