## Credentials intercepted

SSH-MITM is positioned between the developer and the target server.

The developer's SSH client has just connected through the proxy and
authenticated with a password — without noticing anything unusual.

Switch to the **SSH-MITM terminal** now. You will find the intercepted
password logged there in plaintext.

---

The interception works because SSH-MITM terminates the client handshake
with its own host key, decrypts all traffic, and establishes a separate
encrypted connection to the real server. The password passes through the
proxy in plaintext and is logged before it is forwarded.
