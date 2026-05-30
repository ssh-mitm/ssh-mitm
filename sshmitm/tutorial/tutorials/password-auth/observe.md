## What the attacker sees

Switch to the SSH-MITM terminal.
You will find the developer's password logged there in plaintext —
even though the SSH connection was fully encrypted the entire time.

### Why encryption did not help

SSH encrypts the channel between client and server, but it cannot protect
data from the endpoint it is talking to. SSH-MITM terminated Alice's
handshake with its **own** host key, decrypted the incoming data, and
forwarded it through a separate encrypted connection to the real server.
Alice authenticated against the attacker's proxy without noticing.

### Why the developer did not get a warning

They would have — if host key verification had worked as intended.

On first connection, SSH asks the user to confirm the server's fingerprint.
If the developer had verified it against a trusted source (e.g. the server
provider's admin console), they would have noticed the fingerprint was wrong
and aborted. On later connections, SSH would have detected the changed key
automatically and refused to connect.

The attack only succeeded because the fingerprint was accepted without
verification — exactly as most users do in practice.

### How to protect against this

- **Verify host key fingerprints** on first connection using a trusted
  side channel, not just by typing `yes`.
- **Never use `StrictHostKeyChecking=no`** — it silently disables the only
  mechanism SSH has to detect this attack.
- **Switch to public-key authentication** — the private key is never
  transmitted, so intercepting the session yields no reusable secret.

---

You can now close the SSH-MITM terminal and move on to the next tutorial.
