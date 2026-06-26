<div class="scenario-box" markdown="1">
Sarah connected to `web01.logfileinc.internal` using public key authentication with agent forwarding enabled. Her private key never left her laptop — but SSH-MITM still captured everything it needs.
</div>

### What to look for

Switch to the **SSH-MITM terminal**. After Sarah authenticated, SSH-MITM logged the public key fingerprint the server accepted:

```
INFO     Public key: SHA256:...
```

This fingerprint uniquely identifies Sarah's key pair. If the same key is authorized on other servers in the infrastructure, that single value maps her entire access footprint.

SSH-MITM also reports whether agent forwarding is active:

```
INFO     Agent forwarding is enabled
```

While that line appears in the output, Sarah's agent is available to the proxy — and can be used to authenticate to any host reachable from SSH-MITM's network position.

### Why does this work?

Public key authentication proves to the server that the client holds the private key — but that proof happens inside the session that SSH-MITM controls. The proxy can observe which public key the server accepted. And when the client requests agent forwarding, it opens an agent channel back to the client: SSH-MITM sits on that channel and can use it to initiate new authentications to other servers as Sarah, without the private key ever being transferred.

This is why `ssh -A` (agent forwarding) should only be used when every host in the chain is fully trusted. Once agent forwarding is established through an intercepted session, an attacker has Sarah's credentials for the duration of the connection.

<div class="task-box" markdown="1">
Find the public key fingerprint (`SHA256:...`) in the SSH-MITM terminal output and enter it in the field above.
</div>

> **Further reading:** [Authentication](https://docs.ssh-mitm.at/audit_guide/authentication.html) · [SSH Agent Forwarding](https://docs.ssh-mitm.at/audit_guide/sshagent.html)
