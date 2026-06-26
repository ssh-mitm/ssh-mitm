<div class="scenario-box" markdown="1">
Max's build server connected to `web01.logfileinc.internal`, executed a single command via SSH exec, and disconnected. The deployment completed successfully from both sides. SSH-MITM captured the command string before it reached the server.
</div>

### What to look for

Switch to the **SSH-MITM terminal**. When the exec channel opened, SSH-MITM logged the full command:

```
INFO     ssh exec: ...
```

The command appears exactly as Max's build server sent it — no shell expansion, no interpretation.

### Why does this work?

SSH exec is a channel type within the SSH protocol, used for non-interactive command execution. It follows the same path as any other SSH traffic: through SSH-MITM's termination of the client session, decrypted, then re-encrypted and forwarded to the real server.

At the moment SSH-MITM intercepts the exec channel request, the proxy has:

- The full command string as sent by the client
- The ability to modify the command before it reaches the server
- The ability to alter the output returned to the client

From Max's build system's perspective, the deployment completed normally. There is no indication in the client output that the command was observed or modified.

<div class="task-box" markdown="1">
Find the command that Max's deployment script executed in the SSH-MITM terminal and enter it in the field above.
</div>

> **Further reading:** [Terminal Sessions](https://docs.ssh-mitm.at/audit_guide/sessions.html)
