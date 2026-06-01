## What you will learn

SSH-MITM does not only intercept credentials — it can also mirror every
active shell session to a second connection in real time.  This feature
is called **mirrorshell** and it is enabled by default.

When a developer connects through SSH-MITM and opens a shell, the proxy
automatically opens a separate port.  Anyone who connects to that port
sees a live copy of the session: every keystroke the developer types and
every response the server sends.

More importantly, the attacker can **inject their own commands** into the
open session.  If the developer steps away from their terminal, the
attacker has full, unnoticed access to everything the developer could do —
without any additional authentication.

---

**The scenario in this tutorial**

A developer has connected to a production server through SSH-MITM and
opened a shell.  They have just stepped away to get coffee, leaving the
terminal unattended.

You will connect to the mirrored session, explore the server, and
retrieve a secret that is stored in a file on the developer's home
directory — all without the developer noticing.

---

In the next step you will start SSH-MITM.  Mirrorshell is always active;
no additional flags are needed.
