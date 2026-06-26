<div class="objectives-box" markdown="1">

- See how SSH-MITM intercepts non-interactive SSH exec commands and logs the full command string
- Understand why automated scripts using SSH exec are just as exposed as interactive sessions
- Learn what an attacker can do beyond logging — including command and output modification

</div>

<div class="note-box" markdown="1">
Developers often assume that automated scripts using SSH exec are harder to intercept than interactive shells — because there is no terminal, no prompt, and the connection closes immediately. In practice, the exec channel passes through the same MITM proxy as any other SSH traffic. SSH-MITM sees the full command string and the server's response, in cleartext, before either side receives it.
</div>

<div class="scenario-box" markdown="1">
**Logfile Inc.'s** deployment pipeline runs automatically at the end of each build cycle. The final step is a single SSH exec command: Max Morgan's build server connects to `web01.logfileinc.internal`, runs a deployment hook, and disconnects. No interactive shell. No human at the keyboard.

SSH-MITM sits between the build server and the web server. The proxy logs the exact command string the moment the client sends it. The deployment continues normally — nothing on either side indicates that the command was observed.

An attacker in this position can also modify the command before it reaches the server, or alter the output the client receives to conceal what actually ran.
</div>

---

> **Further reading:** [Terminal Sessions](https://docs.ssh-mitm.at/audit_guide/sessions.html)
