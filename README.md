<div id="top" align="center">
<img src="https://github.com/ssh-mitm/ssh-mitm/raw/master/doc/images/ssh-mitm-logo.png" width="200"><br/>
</div>
<h1 align="center"> SSH-MITM - ssh audits made simple </h1>
<p align="center">
  <a href="https://docs.ssh-mitm.at">
    <img alt="SSH-MITM intercepting password login" title="SSH-MITM" src="https://docs.ssh-mitm.at/_images/ssh-mitm-password.png#20230214" >
  </a>
  <p align="center">ssh man-in-the-middle (ssh-mitm) server for security audits supporting<br> <b>publickey authentication</b>, <b>session hijacking</b> and <b>file manipulation</b></p>
  <p align="center">
   <a href="https://snapcraft.io/ssh-mitm">
     <img alt="Get it from the Snap Store" src="https://snapcraft.io/static/images/badges/en/snap-store-black.svg" />
   </a>
   <br />
   <br />
   <a href="https://docs.ssh-mitm.at"><img src="https://read-the-docs-guidelines.readthedocs-hosted.com/_downloads/d9606423d87d78fcceae4ee2af883b12/logo-wordmark-dark.png" title="read the docs" width="256"></a>
  </p>
</p>


<h3 align="center">Contributors</h3>
<p align="center">
<a href="https://github.com/ssh-mitm/ssh-mitm/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=ssh-mitm/ssh-mitm" />
</a>
</p>

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Quickstart](#quickstart)
- [Session hijacking](#session-hijacking)
- [Phishing FIDO Tokens](#phishing-fido-tokens)
- [Contributing](#contributing)
- [Contact](#contact)

## Introduction

[![Downloads](https://pepy.tech/badge/ssh-mitm)](https://pepy.tech/project/ssh-mitm)
[![CodeFactor](https://www.codefactor.io/repository/github/ssh-mitm/ssh-mitm/badge)](https://www.codefactor.io/repository/github/ssh-mitm/ssh-mitm)
[![Documentation Status](https://readthedocs.org/projects/ssh-mitm/badge/?version=latest)](https://docs.ssh-mitm.at/?badge=latest)
[![GitHub](https://img.shields.io/github/license/ssh-mitm/ssh-mitm?color=%23434ee6)](https://github.com/ssh-mitm/ssh-mitm/blob/master/LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)
<a rel="me" href="https://defcon.social/@sshmitm"><img src="https://img.shields.io/mastodon/follow/109597663767801251?color=%236364FF&domain=https%3A%2F%2Fdefcon.social&label=Mastodon&style=plastic"></a>


**SSH-MITM** is a man in the middle SSH Server for security audits and malware analysis.

Password and **publickey authentication** are supported and SSH-MITM is able to detect, if a user is able to login with publickey authentication on the remote server. This allows SSH-MITM to accept the same key as the destination server. If publickey authentication is not possible, the authentication will fall back to password-authentication.

When publickey authentication is possible, a forwarded agent is needed to login to the remote server. In cases, when no agent was forwarded, SSH-MITM can rediredt the session to a honeypot.

<p align="right">(<a href="#top">back to top</a>)</p>

## Features

* publickey authentication
   * accept same key as destination server
   * Phishing FIDO Tokens ([Information from OpenSSH](https://www.openssh.com/agent-restrict.html))
* hijacking and logging of terminal sessions
* store and replace files during SCP/SFTP file transferes
* port porwarding
  * SOCKS 4/5 support for dynamic port forwarding
* intercept MOSH connections
* audit clients against known vulnerabilities
* plugin support

<p align="right">(<a href="#top">back to top</a>)</p>

## Installation

**SSH-MITM** can be installed as a [Ubuntu Snap](https://snapcraft.io/ssh-mitm), [PIP-Package](https://pypi.org/project/ssh-mitm/), [AppImage](https://github.com/ssh-mitm/ssh-mitm/releases/latest), [Nix](https://search.nixos.org/packages?channel=unstable&show=ssh-mitm&type=packages&query=ssh-mitm) and even runs on **[Android devices](https://github.com/ssh-mitm/ssh-mitm/discussions/83#discussioncomment-1531873)**

    # install ssh-mitm as snap package
    $ sudo snap install ssh-mitm

    # install ssh-mitm as python pip package
    $ python3 -m pip install ssh-mitm

    # install as Nix package
    $ nix-env -iA nixos.ssh-mitm

<p align="right">(<a href="#top">back to top</a>)</p>

## Quickstart

To start SSH-MITM, all you have to do is run this command in your terminal of choice.

    $ ssh-mitm server --remote-host 192.168.0.x

Now let's try to connect. SSH-MITM is listening on port 10022.

    $ ssh -p 10022 testuser@proxyserver

You will see the credentials in the log output.

    INFO     Remote authentication succeeded
        Remote Address: 127.0.0.1:22
        Username: testuser
        Password: secret
        Agent: no agent

<p align="right">(<a href="#top">back to top</a>)</p>

## Session hijacking

Getting the plain text credentials is only half the fun.
When a client connects, the ssh-mitm starts a new server, which is used for session hijacking.

    INFO     ℹ created mirrorshell on port 34463. connect with: ssh -p 34463 127.0.0.1

To hijack the session, you can use your favorite ssh client.

    $ ssh -p 34463 127.0.0.1

Try to execute somme commands in the hijacked session or in the original session.

The output will be shown in both sessions.

<p align="right">(<a href="#top">back to top</a>)</p>

## Phishing FIDO Tokens

SSH-MITM is able to phish FIDO2 Tokens which can be used for 2 factor authentication.

The attack is called [trivial authentication](https://docs.ssh-mitm.at/trivialauth.html) ([CVE-2021-36367](https://docs.ssh-mitm.at/CVE-2021-36367.html), [CVE-2021-36368](https://docs.ssh-mitm.at/CVE-2021-36368.html)) and can be enabled with the command line argument `--enable-trivial-auth`.

  ssh-mitm server --enable-trivial-auth

Using the trivial authentication attack does not break password authentication, because the attack is only performed when a publickey login is possible.

<p align="center">
  <b>Video explaining the phishing attack:</b><br/>
  <i>Click to view video on vimeo.com</i><br/>
  <a href="https://vimeo.com/showcase/9059922/video/651517195">
  <img src="https://github.com/ssh-mitm/ssh-mitm/raw/master/doc/images/ds2021-video.png" alt="Click to view video on vimeo.com">
  </a>
</p>

<p align="center">
  <b><a href="https://github.com/ssh-mitm/ssh-mitm/files/7568291/deepsec.pdf">Downlaod presentation slides</a></b>
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

See also the list of [contributors](https://github.com/ssh-mitm/ssh-mitm/graphs/contributors) who participated in this project.

<p align="right">(<a href="#top">back to top</a>)</p>

## Contact

- E-Mail: support@ssh-mitm.at
- [Issue Tracker](https://github.com/ssh-mitm/ssh-mitm/issues)

<p align="right">(<a href="#top">back to top</a>)</p>
