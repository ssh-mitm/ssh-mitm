<div class="objectives-box" markdown="1">

- Understand why switching from passwords to SSH keys does not prevent a MITM attack
- See how SSH-MITM captures the public key fingerprint used to authenticate
- Learn what agent forwarding is and why it gives an attacker access to the victim's identity on other systems

</div>

<div class="note-box" markdown="1">
Key-based authentication prevents password sniffing — but a MITM proxy does not need the private key. It sees the public key fingerprint the server accepted. And if agent forwarding is enabled, it gains access to a live agent that can authenticate to other systems as the user. The private key never leaves the client, yet the attacker can use it.
</div>

<div class="scenario-box" markdown="1">
Following a credential theft incident at another company, Lisa Chen — Logfile Inc.'s IT manager — issued a company-wide directive: all developer accounts must migrate from password authentication to SSH key pairs. She also updated the internal SSH guide with a configuration template that includes ``ForwardAgent yes``, copied from an online tutorial.

Sarah King, the DevOps engineer, generated a key pair, added the public key to `web01.logfileinc.internal`, and updated her SSH config to use agent forwarding — so she can jump to other internal systems without re-entering credentials.

From her perspective, the upgrade made things significantly more secure. No more passwords to intercept.

SSH-MITM sits between Sarah and the server. You no longer capture a password — but you see the exact public key fingerprint the server accepted. That fingerprint uniquely identifies Sarah's key pair across every system in the infrastructure. And because agent forwarding is enabled, Sarah's SSH agent travels through the proxy for the duration of her session: any host reachable from SSH-MITM's network position can be accessed using Sarah's identity, without ever touching her private key.
</div>

---

> **Further reading:** [Authentication](https://docs.ssh-mitm.at/audit_guide/authentication.html) · [SSH Agent Forwarding](https://docs.ssh-mitm.at/audit_guide/sshagent.html)
