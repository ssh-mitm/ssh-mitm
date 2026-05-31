## Start SSH-MITM

Open a **new terminal** and run the command shown below.

**What the arguments do**

- `--remote-host` / `--remote-port` — the real target server that
  SSH-MITM forwards connections to
- `--listen-port` — the port SSH-MITM listens on; the developer's client
  connects here instead of the real server

**What SSH-MITM intercepts**

Even though the developer authenticates with a public key (no password is
transmitted), SSH-MITM terminates the TLS-like SSH handshake with its own
host key.  It sees the public key offered by the client, checks it against
the real server, and logs the result — including the SHA256 fingerprint of
the accepted key.

If agent forwarding is active, SSH-MITM also gains access to the
forwarded agent socket for the duration of the session, which can be used
to authenticate to other servers as the victim.

**What to expect**

Once started you will see:

```
INFO     Listening on 127.0.0.1:{sshmitm_port}
```

Leave this terminal open for the next step.
