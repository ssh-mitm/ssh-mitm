<div class="scenario-box" markdown="1">
Thomas connected to `router01.logfileinc.internal` through SSH-MITM, authenticated, and left the session unattended. The terminal is open. The router is waiting.
</div>

### What to look for

Switch to the **SSH-MITM terminal**. When Thomas's session started, SSH-MITM printed the command to attach to the mirrored session:

```
[i] created mirrorshell on port ...
```

SSH-MITM shows the exact `ssh` command to run. Use it to connect to the mirrored session.

### Navigating the mirrored session

Once connected, the terminal may appear blank — the router prompt was already shown before you joined. Press Enter to trigger a new prompt and confirm you are connected.

Run the following command to read the device configuration:

```
show running-config
```

Scroll through the output and locate the SNMP configuration section. The read-write community string is defined there.

When you are done, type `exit` to leave the mirrorshell session. Thomas's session on the router is unaffected.

### Why does this work?

Thomas authenticated to what appears to be `router01.logfileinc.internal` — but the device he is talking to is SSH-MITM. The proxy decrypts his session, forwards all traffic to the real router, and simultaneously exposes the session via a local port.

Connecting to that port gives a second party a live view of the terminal: every character Thomas types and every response from the router passes through the mirrorshell. An attacker can read, copy, or inject commands without leaving any trace in the legitimate session's output.

<div class="task-box" markdown="1">
Attach to the mirrorshell session, run `show running-config`, and find the SNMP read-write community string. Enter it in the field above.
</div>

> **Further reading:** [Terminal Sessions](https://docs.ssh-mitm.at/audit_guide/sessions.html)
