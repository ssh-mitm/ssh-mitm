## Alice's key fingerprint

Alice just connected to the dev server through SSH-MITM using public key
authentication with agent forwarding enabled.

Switch to the **SSH-MITM terminal**. Look for a line containing a `SHA256:`
identifier — this is the **public key fingerprint** of the client key the
server accepted.

Enter that fingerprint in the field below to confirm you found it.

---

**Why the fingerprint matters**

The fingerprint uniquely identifies Alice's key pair. An attacker who has
observed it can:

- Confirm which key has access to which server.
- Search for the same fingerprint across other systems to map Alice's
  access across the infrastructure.
- Use the captured agent (available via agent forwarding) to authenticate
  to those systems without ever touching her private key.

**Avoid agent forwarding in production**

`ssh -A` (agent forwarding) should only be used when every host in the
chain is fully trusted. Once a host has access to the agent, it can use
Alice's keys for the duration of the session — from any process on that host.

---

*The engagement continues. In the next tutorial, Alice transfers a file
from the staging server.*
