<div class="objectives-box" markdown="1">

- See how SSH-MITM captures cleartext credentials even inside an encrypted SSH session
- Understand why SSH encryption does not protect passwords from a proxy that terminates the connection
- Recognise that host key verification is the only mechanism that would have prevented this attack

</div>

<div class="note-box" markdown="1">
SSH encrypts the channel between client and server — but only against parties outside the connection. A MITM proxy terminates the client's session with its own key and re-encrypts it toward the real server. The password crosses the proxy in cleartext, inside what looks like a perfectly normal SSH connection.
</div>

<div class="scenario-box" markdown="1">
Max Morgan, a developer at **Logfile Inc.**, connects to `web01.logfileinc.internal` as he does every morning. He opens a terminal, types `ssh mmorgan@web01.logfileinc.internal`, and enters his password when prompted. From his point of view, the session looks identical to every previous one.

SSH-MITM sits between Max and the server. It logs the username and password the moment Max authenticates — before forwarding them to the real server. The session continues normally; Max sees no error and no warning.
</div>

---

> **Further reading:** [Authentication](https://docs.ssh-mitm.at/user_guide/authentication.html)
