<h1 align="center"> SSH-MITM - ssh audits made simple </h1>
<p align="center">
  <a href="https://github.com/ssh-mitm/ssh-mitm">
    <img alt="SSH-MITM intercepting password login" title="SSH-MITM" src="https://docs.ssh-mitm.at/_images/intro.png" >
  </a>
  <p align="center">ssh man-in-the-middle (ssh-mitm) server for security audits supporting<br> <b>publickey authentication</b>, <b>session hijacking</b> and <b>file manipulation</b></p>
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

## Quick Install

### AppImage (recommended — no installation required)

```bash
wget https://github.com/ssh-mitm/ssh-mitm/releases/latest/download/ssh-mitm-x86_64.AppImage
chmod +x ssh-mitm-x86_64.AppImage
./ssh-mitm-x86_64.AppImage server --remote-host <target-host>
```

For other installation options (pip, Flatpak, Snap) see the [Installation](#installation) section below.

---

## Table of Contents

- [Introduction](#introduction)
- [Use Cases](#use-cases)
- [Features](#features)
- [Installation](#installation)
- [Quickstart](#quickstart)
- [Session hijacking](#session-hijacking)
- [Phishing FIDO Tokens](#phishing-fido-tokens)
- [Contributing](#contributing)
- [Contact](#contact)

## Introduction

**SSH-MITM** is a man-in-the-middle SSH server for security audits and malware analysis.

Password and **publickey authentication** are supported. SSH-MITM can detect if a user is able to log in with publickey authentication on the remote server, allowing it to accept the same key as the destination server. If publickey authentication is not possible, it falls back to password authentication.

When publickey authentication is possible, a forwarded agent is needed to log in to the remote server. If no agent is forwarded, SSH-MITM can redirect the session to a honeypot.

<p align="right">(<a href="#top">back to top</a>)</p>

## Use Cases

- **Penetration testing** — audit SSH clients and servers in authorized engagements
- **Security research** — analyze SSH client behavior and authentication flows
- **Training environments** — demonstrate MITM attacks in controlled lab setups
- **Malware analysis** — inspect SSH traffic from suspicious clients in isolated environments

<p align="right">(<a href="#top">back to top</a>)</p>

## Features

| Feature | Description |
| ------- | ----------- |
| Publickey authentication | Accepts the same key as the destination server; detects and falls back to password auth |
| FIDO2 token phishing | Intercepts hardware token authentication via the trivial authentication attack ([OpenSSH info](https://www.openssh.com/agent-restrict.html)) |
| Session hijacking | Mirror and interact with live SSH sessions in real time |
| File interception | Store and replace files during SCP/SFTP transfers |
| Port forwarding | TCP and dynamic forwarding with SOCKS 4/5 support |
| MOSH interception | Intercept MOSH connections |
| Client auditing | Check connecting clients against known vulnerabilities |
| Plugin support | Extend functionality with custom plugins |

<p align="right">(<a href="#top">back to top</a>)</p>

## Installation

### Requirements

- Linux (x86_64)
- Python 3.11 or newer (for pip installation)

### AppImage (recommended)

No installation required — just download and run:

```bash
wget https://github.com/ssh-mitm/ssh-mitm/releases/latest/download/ssh-mitm-x86_64.AppImage
chmod +x ssh-mitm-x86_64.AppImage
```

### Flatpak

```bash
flatpak install flathub at.ssh_mitm.server
flatpak run at.ssh_mitm.server
```

### Snap

```bash
sudo snap install ssh-mitm
```

### pip (Python 3.11+)

```bash
pip install "ssh-mitm[production]"
```

For more details, see the [SSH-MITM installation guide](https://docs.ssh-mitm.at/get_started/installation.html).

<p align="right">(<a href="#top">back to top</a>)</p>

## Quickstart

Start SSH-MITM and point it at your target host (replace `<target-host>` with the SSH server you want to audit):

    ssh-mitm server --remote-host <target-host>

SSH-MITM listens on port 10022 by default. Connect through the proxy:

    ssh -p 10022 testuser@proxyserver

You will see the intercepted credentials in the log output:

    INFO     Remote authentication succeeded
        Remote Address: 127.0.0.1:22
        Username: testuser
        Password: secret
        Agent: no agent

<p align="right">(<a href="#top">back to top</a>)</p>

## Session hijacking

When a client connects, SSH-MITM starts a mirror shell that can be used for session hijacking:

    INFO     ℹ created mirrorshell on port 34463. connect with: ssh -p 34463 127.0.0.1

Connect to the mirror shell with any SSH client:

    ssh -p 34463 127.0.0.1

Commands executed in either the original or the hijacked session will be visible in both.

<p align="right">(<a href="#top">back to top</a>)</p>

## Phishing FIDO Tokens

SSH-MITM is able to phish FIDO2 tokens which can be used for two-factor authentication.

The attack is called [trivial authentication](https://docs.ssh-mitm.at/trivialauth.html) ([CVE-2021-36367](https://docs.ssh-mitm.at/CVE-2021-36367.html), [CVE-2021-36368](https://docs.ssh-mitm.at/CVE-2021-36368.html)) and can be enabled with the command line argument `--enable-trivial-auth`:

  ssh-mitm server --enable-trivial-auth

The attack is only performed when publickey login is possible, so password authentication continues to work normally.

<p align="center">
  <b>Video explaining the phishing attack:</b><br/>
  <i>Click to view video on vimeo.com</i><br/>
  <a href="https://vimeo.com/showcase/9059922/video/651517195">
  <img src="https://github.com/ssh-mitm/ssh-mitm/raw/master/doc/images/ds2021-video.png" alt="Click to view video on vimeo.com">
  </a>
</p>

<p align="center">
  <b><a href="https://github.com/ssh-mitm/ssh-mitm/files/7568291/deepsec.pdf">Download presentation slides</a></b>
</p>

<p align="right">(<a href="#top">back to top</a>)</p>

## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#top">back to top</a>)</p>

## Contact

- E-Mail: [support@ssh-mitm.at](mailto:support@ssh-mitm.at)
- [Issue Tracker](https://github.com/ssh-mitm/ssh-mitm/issues)

<p align="right">(<a href="#top">back to top</a>)</p>

## Contributors

<a href="https://github.com/ssh-mitm/ssh-mitm/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=ssh-mitm/ssh-mitm" />
</a>
