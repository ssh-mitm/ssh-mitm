<div class="scenario-box" markdown="1">
Max is opening an SSH connection to `web01.logfileinc.internal` for the first time from this machine. His `~/.ssh/known_hosts` has no entry for it. SSH presents the fingerprint prompt — Max clicks past it without checking, as most users do.
</div>

SSH-MITM intercepts the connection and presents its own host key. The attack is now in place.

### What to look for

Switch to the **SSH-MITM terminal**. When Max connects, SSH-MITM prints a CVE-2020-14145 report. Find the line:

```
Preferred server host key algorithm: ...
```

This is the algorithm Max's client put **first** in its key exchange proposal. When no fingerprint is cached, the client uses the default algorithm order defined by OpenSSH.

### Why does the algorithm order matter?

Every SSH client sends a list of accepted host-key algorithms during the key exchange — sorted by preference. OpenSSH moves the algorithm that matches a **cached** fingerprint to the top of this list.

- **No cached key →** default order, certificate type first (e.g. `rsa-sha2-512-cert-v01@openssh.com`)
- **Cached key →** matching algorithm type moves to the front

This ordering is visible to SSH-MITM before any authentication — and that is exactly what **CVE-2020-14145** describes.

<div class="task-box" markdown="1">
Find the line `Preferred server host key algorithm:` in the SSH-MITM terminal and enter the algorithm name in the field above.
</div>

> **Further reading:**
> [Attack Scenarios](https://docs.ssh-mitm.at/user_guide/attack_scenarios.html) ·
> [CVE-2020-14145](https://docs.ssh-mitm.at/vulnerabilities/CVE-2020-14145.html)
