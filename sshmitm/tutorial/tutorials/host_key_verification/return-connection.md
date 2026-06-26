<div class="scenario-box" markdown="1">
Max is opening a second connection to `web01.logfileinc.internal`. His client now has SSH-MITM's host key cached from the first connection. He does not notice anything unusual — the session looks identical. But the key exchange tells a different story.
</div>

### What to look for

Switch to the **SSH-MITM terminal** again. Find the same line:

```
Preferred server host key algorithm: ...
```

Compare it to what you saw in the previous step. SSH-MITM also reports the fingerprint state directly:

```
INFO     client has a locally cached remote fingerprint.
```

### What changed — and why

Max's client now puts the algorithm that **matches the cached key type** at the top of its proposal instead of the default. This shift is the information leak documented as **CVE-2020-14145**.

| Preferred algorithm type | What SSH-MITM concludes |
|---|---|
| Certificate type (`*-cert-v01@…`) | No cached key — first-time visitor |
| Plain key type (`ssh-ed25519`, `ecdsa-*`, …) | Cached key — returning user |

### The "just delete the key" mistake

If Max had a different key cached (the real server's key, not SSH-MITM's), he would see:

```
WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!
```

Most users — and many online tutorials — respond by running `ssh-keygen -R <hostname>` and reconnecting without question. For an attacker, this is the ideal outcome: the user removes the one protection that would have detected the MITM and trusts the new (attacker-controlled) key instead.

<div class="task-box" markdown="1">
Find the `Preferred server host key algorithm:` line for this second connection in the SSH-MITM terminal and enter it in the field above. Has the algorithm changed compared to the first connection?
</div>

> **Further reading:**
> [CVE-2020-14145](https://docs.ssh-mitm.at/vulnerabilities/CVE-2020-14145.html) ·
> [Attack Scenarios](https://docs.ssh-mitm.at/user_guide/attack_scenarios.html)
