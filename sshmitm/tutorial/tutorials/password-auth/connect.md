## The developer connects

Open a **third terminal window** and run the command shown below.
This simulates the developer typing their usual `ssh` command — except the
connection goes through SSH-MITM instead of directly to the server.

### First connection — confirm the host key

On first connection SSH will display a fingerprint and ask whether you trust it:

```
The authenticity of host '[127.0.0.1]:{sshmitm_port}' can't be established.
ED25519 key fingerprint is SHA256:...
Are you sure you want to continue connecting (yes/no/[fingerprint])?
```

Type `yes` and press **Enter**.
SSH stores the fingerprint in `~/.ssh/known_hosts` and checks it on every
future connection — this is normally what stops a man-in-the-middle attack
before it can succeed.

### Enter the password

When SSH asks for a password, enter the value shown in the credentials box
above and press **Enter**.

The session will log in successfully. The developer notices nothing.

---

> **Note:** `-o PreferredAuthentications=password` tells the SSH client to
> use password authentication only, so the tutorial works even if you have
> SSH keys configured on your machine.
