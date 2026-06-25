## The admin stepped away

A network administrator just connected to a production router through
SSH-MITM and left the session unattended — you have approximately
**10 minutes** before they return.

**Step 1 — Find the mirrorshell port**

Check the **SSH-MITM terminal**. When the admin's session started,
SSH-MITM printed the exact command you need to connect. Look for a line
starting with `[i] created mirrorshell on port`.

**Step 2 — Connect to the mirrored session**

Run the `ssh` command shown by SSH-MITM to attach to the live session.

> **Note:** The terminal may appear blank at first — the prompt was
> already shown before you connected. Just start typing. A good first
> command is `help`, which lists everything the device supports.
> The prompt and output will appear as soon as you press Enter.

**Step 3 — Read the router configuration**

Use `show running-config` to display the device configuration. Look for
the SNMP read-write community string.

**Step 4 — Enter the SNMP community string below**

When you are done, type `exit` to leave the session and enter the value
you found in the field below.

---

**Why does this work?**

The administrator authenticated to the router — but the router they are
talking to is SSH-MITM. The proxy decrypts the session, exposes it via
the mirrorshell port, and forwards all traffic to the real device. The
admin has no indication that the session is being observed or that
commands can be injected.

---

**To be continued...**

The Logfile Inc. assessment is not over. More chapters are in development —
covering additional techniques and scenarios encountered during the engagement.

In the meantime, the [Audit Guide](https://docs.ssh-mitm.at/user_guide/index.html)
covers every technique shown here in depth, including configuration options,
plugin customization, and how to apply them in real authorized engagements.
