<div class="scenario-box" markdown="1">
Max connected to `web01.logfileinc.internal` through SSH-MITM. He entered his password, the session opened, and he is now working — completely unaware that the proxy logged his credentials the moment he authenticated.
</div>

### What to look for

Switch to the **SSH-MITM terminal**. When Max's password authentication completed, SSH-MITM printed a line containing both the username and the password in cleartext:

```
INFO     Remote credentials: username='mmorgan', password='...'
```

The password appears in cleartext regardless of SSH encryption — because SSH-MITM is the endpoint Max's client is talking to.

### Why does this work?

SSH encrypts the channel between client and server, but only against third parties outside the connection. It cannot protect data from the endpoint the client is actually talking to.

SSH-MITM terminates Max's handshake using its own host key, decrypts all traffic, and opens a separate encrypted connection to the real server. His password passes through the proxy in cleartext at the moment of authentication, before being forwarded.

The only mechanism that would have prevented this is **host key verification**: if Max had confirmed the server fingerprint before connecting, his client would have refused SSH-MITM's key and the attack would have failed. He did not check.

<div class="task-box" markdown="1">
Find the username and password in the SSH-MITM terminal output and enter both values in the fields above.
</div>

> **Further reading:** [Authentication](https://docs.ssh-mitm.at/audit_guide/authentication.html)
