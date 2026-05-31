## Start SSH-MITM

Open a **new terminal** and run the command shown below.

**What the arguments do**

- `--remote-host` / `--remote-port` — the real target server that SSH-MITM
  forwards connections to (the developer's actual destination)
- `--listen-port` — the port SSH-MITM listens on; this is what the
  developer connects to instead of the real server

In a real attack the developer would be routed to this port through ARP
spoofing, a rogue DNS entry, or by compromising a network device on the
path.  In this tutorial the routing is handled automatically.

**What to expect**

Once started, SSH-MITM will print a line similar to:

```
INFO     Listening on 127.0.0.1:{sshmitm_port}
```

Leave this terminal open — SSH-MITM must keep running while the developer
connects in the next step.
