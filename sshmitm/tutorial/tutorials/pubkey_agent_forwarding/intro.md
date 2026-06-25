## Chapter 2 — The Security Upgrade

After the first session, Meridian Systems' IT department sent out a reminder:
passwords are to be replaced with SSH keys. Alice updated her configuration and
now connects with her private key and agent forwarding enabled.

From her perspective, the change made things more secure.

From your position between her and the server, the change looks different.
SSH-MITM no longer sees a password — but it sees the exact public key the
server accepted, and if agent forwarding is enabled, Alice's agent travels
through the proxy. That agent can be used to authenticate to further systems
as Alice, without ever copying her private key.

---

**What you will see**

- The **public key fingerprint** logged in SSH-MITM output — this uniquely
  identifies Alice's key pair across the entire infrastructure.
- A **forwarded agent** available while the session is open — any host you
  can reach from SSH-MITM's position can be accessed with Alice's identity.

In the next step, start SSH-MITM and wait for Alice to connect.
