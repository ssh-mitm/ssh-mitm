## Public key fingerprint intercepted

A developer just connected to the target server through SSH-MITM using
public key authentication with agent forwarding enabled.

Switch to the **SSH-MITM terminal**. Look for a line that shows a
`SHA256:` identifier — this is the **public key fingerprint** of the
client key that the server accepted.

Unlike the host key fingerprint (which identifies the *server*), a
public key fingerprint identifies the *connecting identity* — the key
pair used to prove who is logging in.

Enter that public key fingerprint in the field below to confirm you found it.

---

**Why the public key fingerprint matters**

The public key fingerprint uniquely identifies a key pair. An attacker
who has observed it can:

- Confirm which key has access to which server
- Search for the same fingerprint across other systems to map the
  developer's access across the infrastructure
- Use a captured agent (via agent forwarding) to authenticate to those
  systems without ever touching the private key

**How to protect against this**

- Avoid agent forwarding (`ssh -A`) unless you fully trust every host in
  the chain. Once a host has access to your agent, it can use your keys
  for the duration of the session.
- Use per-host keys where possible to limit the blast radius if one key
  is compromised or observed.
- Monitor access logs for unexpected public key fingerprints.
