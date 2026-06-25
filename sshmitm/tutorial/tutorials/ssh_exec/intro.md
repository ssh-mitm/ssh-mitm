## Chapter 4 — The Automated Script

Alice's deployment pipeline runs a command automatically via SSH at the end
of each build cycle. A single non-interactive command, executing on the
production server. No shell is opened — just one exec call, one response.

She has never thought twice about it. It has always worked.

But the command travels through the encrypted channel the same way every
other SSH traffic does. SSH-MITM intercepts the exec channel before it
reaches the real server — which means it sees the exact command string
in plaintext, along with the output the server sends back.

---

**What you will see**

The proxy logs every SSH exec request it intercepts, including the full
command string. You will find it in the SSH-MITM output immediately after
Alice's client connects.

A real attacker in this position can also modify the command before it
reaches the server, or intercept and alter the output returned to the client.

In the next step, start SSH-MITM and wait for Alice's automated script to run.
