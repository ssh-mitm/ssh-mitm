<h1 align="center"> SSH-MITM - ssh audits made simple </h1> <br>
<p align="center">
  <a href="https://www.ssh-mitm.at">
    <img alt="SSH-MITM intercepting password login" title="SSH-MITM" src="https://www.ssh-mitm.at/img/ssh-mitm-password.png?20220211" >
  </a>
  <p align="center">ssh man-in-the-middle (ssh-mitm) server for security audits supporting<br> <b>publickey authentication</b>, <b>session hijacking</b> and <b>file manipulation</b></p>
  <p align="center">
   <a href="https://snapcraft.io/ssh-mitm">
     <img alt="Get it from the Snap Store" src="https://snapcraft.io/static/images/badges/en/snap-store-black.svg" />
   </a>
   <br />
   <br />
   <a href="https://docs.ssh-mitm.at"><strong>Explore the docs »</strong></a>
  </p>
</p>


## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Quickstart](#quickstart)
- [Session hijacking](#session-hijacking)
- [Publickey authentication](#publickey-authentication)
- [Contributing](#contributing)

## Introduction

[![CodeFactor](https://www.codefactor.io/repository/github/ssh-mitm/ssh-mitm/badge)](https://www.codefactor.io/repository/github/ssh-mitm/ssh-mitm)
[![Documentation Status](https://readthedocs.org/projects/ssh-mitm/badge/?version=latest)](https://docs.ssh-mitm.at/?badge=latest)
[![PyPI downloads](https://pepy.tech/badge/ssh-mitm/month)](https://pepy.tech/project/ssh-mitm)
[![GitHub](https://img.shields.io/github/license/ssh-mitm/ssh-mitm?color=%23434ee6)](https://github.com/ssh-mitm/ssh-mitm/blob/master/LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)

**SSH-MITM** is a man in the middle SSH Server for security audits and malware analysis.

Password and **publickey authentication** are supported and SSH-MITM is able to detect, if a user is able to login with publickey authentication on the remote server. This allows SSH-MITM to acccept the same key as the destination server. If publickey authentication is not possible, the authentication will fall back to password-authentication.

When publickey authentication is possible, a forwarded agent is needed to login to the remote server. In cases, when no agent was forwarded, SSH-MITM can rediredt the session to a honeypot.


## Features

* publickey authentication
   * accept same key as destination server
   * Spoofing FIDO2 Tokens
* hijacking and logging of terminal sessions
* store and replace files during SCP/SFTP file transferes
* port porwarding
  * SOCKS 4/5 support for dynamic port forwarding
* audit clients against known vulnerabilities
* plugin support


## Installation

<img src="https://www.ssh-mitm.at/assets/images/streamline-free/monitor-loading-progress.svg" align="left" width="128">

**SSH-MITM** can be installed as a [Ubuntu Snap](https://snapcraft.io/ssh-mitm), [PIP-Package](https://pypi.org/project/ssh-mitm/) or [AppImage](https://github.com/ssh-mitm/ssh-mitm/releases/latest) and even runs on **[Android devices](https://github.com/ssh-mitm/ssh-mitm/discussions/83#discussioncomment-1531873)**

    # install ssh-mitm as snap package
    $ sudo snap install ssh-mitm

    # install ssh-mitm as python pip package
    $ pip install ssh-mitm



## Quickstart

<img src="https://www.ssh-mitm.at/assets/images/streamline-free/programmer-male.svg" align="left" width="128">

To start SSH-MITM, all you have to do is run this command in your terminal of choice.

    $ ssh-mitm server --remote-host 192.168.0.x:PORT

Now let's try to connect. SSH-MITM is listening on port 10022.

    $ ssh -p 10022 testuser@proxyserver

You will see the credentials in the log output.

    INFO     Remote authentication succeeded
        Remote Address: 127.0.0.1:22
        Username: testuser
        Password: secret
        Agent: no agent


## Session hijacking

<img src="https://www.ssh-mitm.at/assets/images/streamline-free/customer-service-woman.svg" align="left" width="128">

Getting the plain text credentials is only half the fun.
When a client connects, the ssh-mitm starts a new server, which is used for session hijacking.

    INFO     ℹ created mirrorshell on port 34463. connect with: ssh -p 34463 127.0.0.1

To hijack the session, you can use your favorite ssh client.

    $ ssh -p 34463 127.0.0.1

Try to execute somme commands in the hijacked session or in the original session.

The output will be shown in both sessions.

## Publickey authentication

SSH-MITM is able to verify, if a user is able to login with publickey authentication on the remote server. If publickey authentication is not possible, SSH-MITM falls back to password authentication. **This step does not require a forwarded agent.**

For a full login on the remote server agent forwarding is still required. When no agent was forwarded, SSH-MITM can redirect the connection to a honeypot.

    ssh-mitm server --fallback-host username:password@hostname:port

## Spoofing of FIDO2 Tokens (2 factor authentication)

SSH-MITM is able to spoof FIDO2 Tokens which can be used for 2 factor authentication.

The attack is called trivial authentication and can be enabled with the command line argument `--enable-trivial-auth`.

  ssh-mitm server --enable-trivial-auth

Using the trivial authentication attack does not break password authentication, because the attack is only performed when a publickey login is possible.

## Contributing

<img src="https://www.ssh-mitm.at/assets/images/streamline-free/write-paper-ink.svg" align="left" width="128">

**Pull requests are welcome.**

For major changes, please open an issue first to discuss what you would like to change.

See also the list of [contributors](https://github.com/ssh-mitm/ssh-mitm/graphs/contributors) who participated in this project.
