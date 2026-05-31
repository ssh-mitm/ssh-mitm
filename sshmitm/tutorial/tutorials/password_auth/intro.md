## What you will learn

SSH encrypts the connection between client and server — but encryption
alone does not prevent a man-in-the-middle attack.  As long as the client
accepts the wrong host key, an attacker positioned on the network path
can intercept everything, including passwords.

In this tutorial you take the role of the attacker.  You will position
SSH-MITM between a developer and their SSH server, then watch the
developer's password appear in plaintext in the proxy log — without
breaking the session or alerting the developer.

---

A target SSH server is already running in the background.
In the next step you will start SSH-MITM and position it between the
developer's client and that server.
