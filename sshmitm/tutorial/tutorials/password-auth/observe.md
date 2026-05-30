## What just happened?

SSH-MITM intercepted **{password_user}**'s password before forwarding it
to the target server.

Check the SSH-MITM terminal — it logged the plaintext password even
though the connection was encrypted end-to-end from the client's point of view.

---

This is the core capability of SSH-MITM: **transparent credential interception**
without breaking the SSH session.

You can now close the SSH-MITM terminal and move on to the next tutorial.
