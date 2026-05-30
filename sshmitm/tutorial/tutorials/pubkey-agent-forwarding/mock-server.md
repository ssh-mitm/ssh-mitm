## What you will learn

Public key authentication is widely regarded as more secure than passwords
because the private key never leaves the client. However, SSH-MITM can
still extract valuable information from a public key session:

- **Which key was accepted** — SSH-MITM sees the exact public key used for
  authentication and logs its fingerprint. This fingerprint uniquely
  identifies the key and can be used to track which key has access where.
- **Agent forwarding** — when the client enables agent forwarding, the
  forwarded agent travels through SSH-MITM. An attacker in this position
  can use the agent to authenticate to further systems as the victim,
  without ever seeing or copying the private key.

In this tutorial you take the role of the attacker. A developer connects
to the target server using their SSH key with agent forwarding enabled.
You will intercept the session and identify the key that was accepted.

---

In the next step you will start SSH-MITM between the developer and the
target server.
