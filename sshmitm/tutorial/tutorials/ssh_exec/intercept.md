## The command Alice's script ran

Alice's deployment pipeline just executed a command on the production server
through SSH-MITM — without realising the connection was intercepted.

Switch to the **SSH-MITM terminal**. The proxy logs every SSH exec request
it intercepts, including the full command string.

Find the **command** in the SSH-MITM output and enter it in the field below.

---

**Why does this work?**

Non-interactive SSH commands use the exec channel type instead of a shell.
SSH-MITM intercepts this channel before forwarding it to the real server,
so it sees the exact command string in plaintext — regardless of SSH
encryption.

Beyond logging, a real attacker in this position could rewrite the command
before it reaches the server, or alter the output the client receives.

---

*The engagement continues. In the final tutorial, a different person
connects to the network router — and steps away from the terminal.*
