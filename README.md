<h1 align="center"> SSH-MITM - ssh audits made simple </h1>
<p align="center">
  <a href="https://github.com/ssh-mitm/ssh-mitm">
    <img alt="SSH-MITM intercepting password login" title="SSH-MITM" src="https://docs.ssh-mitm.at/_images/intro.png" >
  </a>
  <p align="center">An interactive SSH interception tool for authorized security audits.<br>Intercept sessions, monitor live traffic, inject commands, and manipulate file transfers — all in real time.</p>
  <p align="center">
   <a href="https://github.com/ssh-mitm/ssh-mitm/releases/latest/download/ssh-mitm-x86_64.AppImage"><img height='56' alt='Download as an AppImage' src='https://docs.appimage.org/_images/download-appimage-banner.svg'/></a>
   &nbsp;&nbsp;&nbsp;
   <a href="https://flathub.org/apps/at.ssh_mitm.server"><img height='56' alt='Download on Flathub' src='https://dl.flathub.org/assets/badges/flathub-badge-en.png'/></a>
   &nbsp;&nbsp;&nbsp;
   <a href="https://snapcraft.io/ssh-mitm"><img  height='56' alt="Get it from the Snap Store" src="https://snapcraft.io/static/images/badges/en/snap-store-black.svg" /></a>
   <br />
   <br />
   <a href="https://docs.ssh-mitm.at"><img src="https://raw.githubusercontent.com/ssh-mitm/ssh-mitm/master/doc/_static/readthedocslogo.png" title="read the docs" width="256"></a>
  </p>
</p>

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/8906/badge)](https://www.bestpractices.dev/projects/8906)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![CodeFactor](https://www.codefactor.io/repository/github/ssh-mitm/ssh-mitm/badge)](https://www.codefactor.io/repository/github/ssh-mitm/ssh-mitm)
[![Documentation Status](https://readthedocs.org/projects/ssh-mitm/badge/?version=latest)](https://docs.ssh-mitm.at/?badge=latest)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)
[![GitHub](https://img.shields.io/github/license/ssh-mitm/ssh-mitm?color=%23434ee6)](https://github.com/ssh-mitm/ssh-mitm/blob/master/LICENSE)
<a rel="me" href="https://defcon.social/@sshmitm"><img src="https://img.shields.io/mastodon/follow/109597663767801251?color=%236364FF&domain=https%3A%2F%2Fdefcon.social&label=Mastodon&style=plastic"></a>

**Legal notice:** SSH-MITM is intended for authorized security audits, penetration testing, and research only.
Do not use it against systems you do not own or have explicit written permission to test.
Unauthorized interception of SSH traffic may be illegal in your jurisdiction.

---

## Quick Start

Placed between a client and its SSH server, SSH-MITM intercepts the connection transparently —
forwarding it to the target while giving the auditor full visibility and control:

<p align="center">
  <img alt="SSH-MITM setup" src="https://docs.ssh-mitm.at/_images/ssh-mitm-setup.svg" width="90%">
</p>

### 1. Install

SSH-MITM requires no installation. Download the AppImage and you are ready to go:

```bash
wget https://github.com/ssh-mitm/ssh-mitm/releases/latest/download/ssh-mitm-x86_64.AppImage
chmod +x ssh-mitm-x86_64.AppImage
```

For other installation options (pip, Flatpak, Snap) see the [installation guide](https://docs.ssh-mitm.at/get_started/installation.html).

### 2. Start SSH-MITM

Point SSH-MITM at your target host — use a system you are authorized to test:

```bash
./ssh-mitm-x86_64.AppImage server --remote-host <target-host>
```

### 3. Route a client connection

Have the SSH client connect through SSH-MITM on port 10022:

```bash
ssh -p 10022 user@mitm-host
```

SSH-MITM intercepts the session and logs the credentials immediately:

```
INFO     Remote authentication succeeded
    Remote Address: <target-host>:22
    Username: user
    Password: secret
    Agent: no agent
```

<p align="center">
  <img alt="SSH-MITM intercepting credentials" src="https://docs.ssh-mitm.at/_images/ssh-mitm-password.png" width="80%">
</p>

### 4. Attach to the live session

For every intercepted connection, SSH-MITM opens a mirror shell on a local port:

```
INFO     ℹ created mirrorshell on port 34463. connect with: ssh -p 34463 127.0.0.1
```

Connect to it from a separate terminal:

```bash
ssh -p 34463 127.0.0.1
```

The mirror shell reflects the session in real time. The auditor can observe the user's activity
and inject commands independently, without affecting the original connection.

## What SSH-MITM can do

| Feature | Description |
| ------- | ----------- |
| [Interactive session monitoring](https://docs.ssh-mitm.at/get_started/terminal_session.html) | Attach to any intercepted session via a mirror shell — observe and inject commands in real time |
| [File transfer manipulation](https://docs.ssh-mitm.at/get_started/file_transfer.html) | Intercept SCP/SFTP transfers, store copies, or replace files on the fly |
| [Port forwarding interception](https://docs.ssh-mitm.at/get_started/portforwarding.html) | Intercept TCP tunnels and dynamic SOCKS 4/5 forwarding |
| [FIDO2 token phishing](https://docs.ssh-mitm.at/user_guide/trivialauth.html) | Intercept hardware token authentication via the trivial auth attack ([OpenSSH info](https://www.openssh.com/agent-restrict.html)) |
| [Authentication interception](https://docs.ssh-mitm.at/user_guide/authentication.html) | Capture passwords; accept the same public key as the target server and fall back to password auth automatically |
| [MOSH session monitoring](https://docs.ssh-mitm.at/user_guide/mosh.html) | Intercept and decrypt MOSH (Mobile Shell) UDP sessions; view the live terminal via a built-in VT100/ANSI emulator |
| [Client auditing](https://docs.ssh-mitm.at/vulnerabilities/index.html) | Identify known vulnerabilities in connecting SSH clients |
| [Plugin support](https://docs.ssh-mitm.at/get_started/plugin_browser.html) | Extend and customize all interception behavior with plugins |

## Use Cases

- **Penetration testing** — actively audit SSH clients and servers in authorized engagements; intercept, manipulate, and replay sessions
- **Security research** — analyze SSH client behavior, authentication flows, and protocol-level weaknesses interactively
- **Training environments** — demonstrate MITM techniques and session hijacking in controlled lab setups
- **Malware analysis** — monitor and interact with SSH sessions from suspicious clients in isolated environments

## The attack that started it all

SSH-MITM was originally developed to investigate a fundamental weakness in how SSH clients handle
hardware token authentication. The research uncovered that FIDO2 tokens — often used as a second
factor — can be phished through a technique called [trivial authentication](https://docs.ssh-mitm.at/trivialauth.html),
which was subsequently assigned [CVE-2021-36368](https://docs.ssh-mitm.at/CVE-2021-36368.html).

The attack exploits the fact that SSH clients can be forced into a trivial authentication method —
such as keyboard-interactive with no prompts — which effectively grants access without any real
authentication. This completely bypasses hardware token protection, since the token is never
challenged. SSH-MITM can simulate this against any client that does not explicitly reject it:

```bash
ssh-mitm server --enable-trivial-auth
```

The attack only applies when public-key authentication is available — password authentication is
not affected and continues to work normally.

<p align="center">
  <b>Talk at DeepSec 2021 — full explanation of the attack:</b><br/>
  <i>Click to view on vimeo.com</i><br/>
  <a href="https://vimeo.com/showcase/9059922/video/651517195">
  <img src="https://github.com/ssh-mitm/ssh-mitm/raw/master/doc/images/ds2021-video.png" alt="Click to view video on vimeo.com">
  </a>
</p>

<p align="center">
  <a href="https://github.com/ssh-mitm/ssh-mitm/files/7568291/deepsec.pdf">Download presentation slides</a>
</p>

<p align="right">(<a href="#top">back to top</a>)</p>

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on the development setup, code style, and how to submit a pull request.

<p align="right">(<a href="#top">back to top</a>)</p>

## Contact

- E-Mail: [support@ssh-mitm.at](mailto:support@ssh-mitm.at)
- [Issue Tracker](https://github.com/ssh-mitm/ssh-mitm/issues)

<p align="right">(<a href="#top">back to top</a>)</p>

## Contributors

<a href="https://github.com/ssh-mitm/ssh-mitm/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=ssh-mitm/ssh-mitm" />
</a>
