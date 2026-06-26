<div class="scenario-box" markdown="1">
SSH-MITM will listen on a local port and transparently forward Max's connection to `web01.logfileinc.internal`. Max connects directly to SSH-MITM without knowing it.
</div>

Run the command below in a **new terminal** and leave it open. Once started you will see:

```
INFO     Listening on 127.0.0.1:{sshmitm_port}
```

SSH-MITM is now ready to intercept. Max's first connection will arrive as soon as you proceed to the next step.

---

> **Further reading:**
> [CVE-2020-14145](https://docs.ssh-mitm.at/vulnerabilities/CVE-2020-14145.html)
