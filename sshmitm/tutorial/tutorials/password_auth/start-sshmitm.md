<div class="scenario-box" markdown="1">
SSH-MITM will intercept Max's connection and forward it to `web01.logfileinc.internal`. Max will authenticate normally — his session continues without interruption — but SSH-MITM logs his credentials the moment he authenticates.
</div>

Open a **new terminal** and run the command below. Leave it open.

- `--remote-host` / `--remote-port` — the real target server (`web01.logfileinc.internal`)
- `--listen-port` — the port SSH-MITM listens on (where Max's client connects)

Once started, SSH-MITM will print:

```
INFO     Listening on 127.0.0.1:{sshmitm_port}
```
