## Key fingerprint intercepted

A developer just connected to the target server through SSH-MITM using
public key authentication with agent forwarding enabled.

Switch to the **SSH-MITM terminal**. Look for a line that shows a
`SHA256:` fingerprint — this is the fingerprint of the public key that
was accepted by the server.

Enter that fingerprint in the field below to confirm you found it.

---

**Why the fingerprint matters**

The fingerprint uniquely identifies the key pair. An attacker who knows
the fingerprint can:

- Confirm which key has access to which server
- Search for the same fingerprint in other systems to map the developer's
  access across the infrastructure
- Use a captured agent (via agent forwarding) to authenticate to those
  systems without needing the private key

**How to protect against this**

- Avoid agent forwarding (`ssh -A`) unless you fully trust every host in
  the chain. Once a host has access to your agent, it can use your keys
  for the duration of the session.
- Use per-host keys where possible to limit the blast radius if one key
  is compromised or observed.
- Monitor access logs for unexpected key fingerprints.
