# SSH-MITM - ssh audits made simple [![Tweet](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?text=ssh%20mitm%20server%20for%20security%20audits%20supporting%20public%20key%20authentication%2C%20session%20hijacking%20and%20file%20manipulation%20&url=https://github.com/ssh-mitm/ssh-mitms&via=SshMitm&hashtags=ssh,mitm,security,audit)

[![CodeFactor](https://www.codefactor.io/repository/github/ssh-mitm/ssh-mitm/badge)](https://www.codefactor.io/repository/github/ssh-mitm/ssh-mitm)
[![Documentation Status](https://readthedocs.org/projects/ssh-mitm/badge/?version=latest)](https://docs.ssh-mitm.at/?badge=latest)
[![PyPI downloads](https://pepy.tech/badge/ssh-mitm/month)](https://pepy.tech/project/ssh-mitm)
[![GitHub](https://img.shields.io/github/license/ssh-mitm/ssh-mitm?color=%23434ee6)](https://github.com/ssh-mitm/ssh-mitm/blob/master/LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)


**man in the middle (mitm) server for security audits supporting public key authentication, session hijacking and file manipulation**

![SSH-MITM example](https://www.ssh-mitm.at/img/mitm-example.png)


## Give a Star! :star:
This keeps me motivated in developing this tool. Thanks!

## Features

* Hijacking and logging of terminal sessions
* [Public key authentication](https://docs.ssh-mitm.at/advanced-usage.html#public-key-authentication)
    * use same publickey as the destination server
    * supports agent forwarding
* [support for ssh commands (e.g. git over ssh)](https://docs.ssh-mitm.at/advanced-usage.html#debug-git-and-rsync)
* SCP and SFTP
    * store files
    * replace files
    * [inject additional files](https://docs.ssh-mitm.at/CVE-2019-6110.html)
* [Port Forwarding](https://docs.ssh-mitm.at/portforwarding.html)
* [Check and test clients against known vulnerabilities](https://docs.ssh-mitm.at/ssh_vulnerabilities.html)
* Plugin support

[Full Changelog](https://github.com/ssh-mitm/ssh-mitm/blob/master/CHANGELOG.md)

## Installation of SSH-MITM

<img src="https://www.ssh-mitm.at/assets/images/streamline-free/monitor-loading-progress.svg" align="left" width="128">

The first step to using any software package is getting it properly installed.

To install **SSH-MITM**, simply run one of these commands in your terminal of choice:

There are different options to install ssh-mitm on your system. So you have the option to choose the one which fits best.

### Install as Ubuntu Snap

    $ snap install ssh-mitm

<a href="https://snapcraft.io/ssh-mitm">
  <img alt="Get it from the Snap Store" src="https://snapcraft.io/static/images/badges/en/snap-store-black.svg" />
</a>

### Install as AppImage

SSH-MITM is available as AppImage. Just download it, make it executable and start it.

    $ wget https://github.com/ssh-mitm/ssh-mitm/releases/latest/download/ssh-mitm-x86_64.AppImage
    $ chmod +x ssh-mitm-x86_64.AppImage
    $ ./ssh-mitm-x86_64.AppImage


### Install as pip-package

    $ pip install ssh-mitm

If you want to install all supported plugins for ssh-mitm you can install them with:

    $ pip install ssh-mitm[plugins]

## Quickstart

<img src="https://www.ssh-mitm.at/assets/images/streamline-free/programmer-male.svg" align="left" width="128">

Starting an intercepting mitm-ssh server with password authentication and session hijacking is very simple.

All you have to do is run this command in your terminal of choice.

    $ ssh-mitm --remote-host 192.168.0.x

Now let's try to connect to the ssh-mitm server.
The ssh-mitm server is listening on port 10022.

    $ ssh -p 10022 user@proxyserver

You will see the credentials in the log output.

    INFO     Remote authentication succeeded
        Remote Address: 127.0.0.1:22
        Username: user
        Password: supersecret
        Agent: no agent


## Session hijacking

<img src="https://www.ssh-mitm.at/assets/images/streamline-free/customer-service-woman.svg" align="left" width="128">

Getting the plain text credentials is only half the fun.
When a client connects, the ssh-mitm starts a new server, which is used for session hijacking.

    INFO     ℹ created mirrorshell on port 34463. connect with: ssh -p 34463 127.0.0.1

To hijack the session, you can use your favorite ssh client. This connection does not require authentication.

    $ ssh -p 34463 127.0.0.1

After you are connected, your session will only be updated with new responses, but you are able to execute commands.

Try to execute somme commands in the hijacked session or in the original session.

The output will be shown in both sessions.

## Public key authentication

SSH-MITM is able to intercept connections with publickey authentication, but this requires a forwarded agent. If no agent is forwarded it's possible to redirect the traffic to a different host.

When a client uses publickey authentication SSH-MITM uses the same key as the remote host for authentication. If the user os not allowed to login to the remote server with publickey authentication, SSH-MITM falls back to password authentication.

Using agent forwarding, SSH-MITM must be started with --request-agent.

    $ ssh-mitm --request-agent --remote-host 192.168.0.x

The client must be started with agent forwarding enabled.

    $ ssh -A -p 10022 user@proxyserver

**Using ssh agent forwarding comes with some security risks and should not be used, when the integrity of a machine is not trusted.** (https://tools.ietf.org/html/draft-ietf-secsh-agent-02)


## Further steps

Other use cases are described in the documentation under [Advanced useage](https://docs.ssh-mitm.at/advanced-usage.html)

SSH-MITM has some client exploits integrated, which can be used to audit various ssh clients like OpenSSH and PuTTY.

* [CVE-2021-33500](https://docs.ssh-mitm.at/CVE-2021-33500.html)
* [CVE-2020-14145](https://docs.ssh-mitm.at/CVE-2020-14145.html)
* [CVE-2020-14002](https://docs.ssh-mitm.at/CVE-2020-14002.html)
* [CVE-2019-6111](https://docs.ssh-mitm.at/CVE-2019-6111.html)
* [CVE-2019-6110](https://docs.ssh-mitm.at/CVE-2019-6110.html)
* [CVE-2019-6109](https://docs.ssh-mitm.at/CVE-2019-6109.html)



## Contributing

<img src="https://www.ssh-mitm.at/assets/images/streamline-free/write-paper-ink.svg" align="left" width="128">

**Pull requests are welcome.**

For major changes, please open an issue first to discuss what you would like to change.

See also the list of [contributors](https://github.com/ssh-mitm/ssh-mitm/graphs/contributors) who participated in this project.
