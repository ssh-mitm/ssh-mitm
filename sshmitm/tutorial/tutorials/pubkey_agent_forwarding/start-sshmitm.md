<div class="scenario-box" markdown="1">
Sarah King is connecting to `web01.logfileinc.internal` with public key authentication and agent forwarding enabled. SSH-MITM terminates her SSH handshake with its own host key, sees the public key offered by her client, and logs the result — including the SHA256 fingerprint of the accepted key.
</div>

Open a **new terminal** and run the command below. Leave it open.

Once started you will see:

```
INFO     Listening on 127.0.0.1:{sshmitm_port}
```
