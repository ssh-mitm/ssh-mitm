## Chapter 5 — The Open Terminal

The network admin — responsible for Logfile Inc.'s core infrastructure —
connects to the production router to check the running configuration.
He authenticates, opens a shell, and then leaves to get coffee.

The terminal is unattended.

SSH-MITM is still in the middle. The admin is connected to the proxy, which
is connected to the real router. SSH-MITM keeps the session open and
exposes it via a local **mirrorshell** port — a live copy of every
keystroke and every response from the device.

You can attach to that port and explore the router as if you were sitting
at the admin's terminal. If you type a command, it runs on the device.
The admin cannot see what you are doing.

---

**What you will see**

When the admin's session starts, SSH-MITM prints the exact command to
attach to the mirrored session. Look for a line starting with:

```
[i] created mirrorshell on port
```

Connect to that port with `ssh` and use `show running-config` to read the
device configuration. The SNMP read-write community string is stored there.

In the next step, start SSH-MITM — mirrorshell is always active, no
additional flags are needed.
