## Chapter 1 — The First Connection

You are conducting an authorized red team assessment of **Meridian Systems**.
Your objective: determine how much an attacker positioned on the internal
network can learn from SSH sessions passing through.

SSH-MITM is running as a transparent proxy between Meridian's developers
and their servers. The first connection is coming in.

It is Alice — a senior developer — connecting to the dev server the same way
she does every morning. She types her password without thinking twice.

She does not know you are listening.

---

**What you will see**

SSH encrypts the channel between client and server — but only against
third parties. SSH-MITM terminates the client's handshake with its own
host key, decrypts all traffic, and opens a separate encrypted connection
to the real server. The password passes through the proxy in plaintext
before being forwarded.

In the next step, start SSH-MITM and wait for Alice to connect.
