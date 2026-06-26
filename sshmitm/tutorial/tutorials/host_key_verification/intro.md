<div class="objectives-box" markdown="1">

- Understand why SSH clients must verify the server fingerprint — and why most skip it
- See how SSH-MITM intercepts a connection when a client accepts its host key without checking (TOFU — Trust On First Use)
- Observe what **CVE-2020-14145** reveals about returning SSH clients before any authentication takes place
- Read the key exchange algorithm list to determine whether a client has connected to this server before

</div>

<div class="note-box" markdown="1">
Most users never verify the fingerprint. When SSH shows the fingerprint prompt, users routinely accept it without checking. If the key later changes and SSH warns "REMOTE HOST IDENTIFICATION HAS CHANGED!", many simply delete the entry with `ssh-keygen -R` and reconnect — a step many online tutorials recommend without explaining the risk. Both habits make an active MITM attack invisible to the victim.
</div>

<div class="scenario-box" markdown="1">
You are performing an authorized assessment of **Logfile Inc.** SSH-MITM is running between the developer and `web01.logfileinc.internal`.

Max Morgan, a developer at Logfile Inc., connects to the web server as part of his morning routine. You will observe two of his connections:

1. **First connection** — Max connects for the first time. His client has no cached fingerprint and will accept SSH-MITM's host key without verifying it.
2. **Return connection** — Max connects again. His client now has a cached key and — unknowingly — reveals this through the key exchange. This is the behaviour described in **CVE-2020-14145**.

All of this happens before Max enters a single credential.
</div>

---

> **Further reading:**
> [Attack Scenarios](https://docs.ssh-mitm.at/user_guide/attack_scenarios.html) ·
> [CVE-2020-14145](https://docs.ssh-mitm.at/vulnerabilities/CVE-2020-14145.html)
