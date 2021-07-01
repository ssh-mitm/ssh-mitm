# ssh-mitm - intercept ssh traffic [![Tweet](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?text=ssh%20mitm%20server%20for%20security%20audits%20supporting%20public%20key%20authentication%2C%20session%20hijacking%20and%20file%20manipulation%20&url=https://github.com/ssh-mitm/ssh-mitms&via=SshMitm&hashtags=ssh,mitm,security,audit)

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
* [Public key authentication](https://docs.ssh-mitm.at/advanced-usage.html#public-key-authentication) and Agent Forwarding
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

    2021-01-01 11:38:26,098 [INFO]  Client connection established with parameters:
        Remote Address: 192.168.0.x
        Port: 22
        Username: user
        Password: supersecret
        Key: None
        Agent: None


## Session hijacking

<img src="https://www.ssh-mitm.at/assets/images/streamline-free/customer-service-woman.svg" align="left" width="128">

Getting the plain text credentials is only half the fun.
When a client connects, the ssh-mitm starts a new server, which is used for session hijacking.

    2021-01-01 11:42:43,699 [INFO]  created injector shell on port 34463.
                                    connect with: ssh -p 34463 127.0.0.1

To hijack the session, you can use your favorite ssh client. This connection does not require authentication.

    $ ssh -p 34463 127.0.0.1

After you are connected, your session will only be updated with new responses, but you are able to execute commands.

Try to execute somme commands in the hijacked session or in the original session.

The output will be shown in both sessions.

## Advanced usage

SSH-MITM proxy server is capable of advanced man in the middle attacks and can be used in scenarios, where the remote host is not known or a single remote host is not sufficient or public key authentication is usded.

### Public key authentication

Public key authentication is a way of logging into an SSH/SFTP account using a cryptographic key rather than a password.

The advantage is, that no confidential data needs to be sent to the remote host which can be intercepted by a man in the middle attack.

Due to this design concept, SSH-MITM proxy server is not able to reuse the data provided during authentication.

It you need to intercept a client with public key authentication, there are some options.

#### Request ssh agent for authentication

SSH supports agent forwarding, which allows a remote host to authenticate against another remote host.

SSH-MITM proxy server is able to request the agent from the client and use it for remote authentication. By using this feature, a SSH-MITM proxy server is able to do a full man in the middle attack.

Since OpenSSH 8.4 the commands scp and sftp are supporting agent forwarding. Older releases or other implementations, does not support agent forwarding for file transfers.

Using agent forwarding, SSH-MITM proxy server must be started with --request-agent.

    $ ssh-mitm --request-agent --remote-host 192.168.0.x

The client must be started with agent forwarding enabled.

    $ ssh -A -p 10022 user@proxyserver

**Using ssh agent forwarding comes with some security risks and should not be used, when the integrity of a machine is not trusted.** (https://tools.ietf.org/html/draft-ietf-secsh-agent-02)


#### Redirect session to a honey pot

If agent forwarding is not possible, the SSH-MITM proxy server can accept the public key authentication request and redirect the session to a honey pot.

When the client sends a command, which requires a password to enter (like sudo), those passwords can be used for further attacks.

SSH-MITM does not support reusing entered passwords for remote authentication, but this feature could be implemented as a plugin.

### Debug git and rsync

Sometime it’s interesting to debug git or rsync. Starting with version 5.4, ssh-mitm is able to intercept ssh commands like git or rsync.

Performing a git pull or rsync with a remote server execute a remote ssh command and the file transfer is part of the communication.

    ssh-mitm --request-agent --scp-interface debug_traffic

#### Intercept git

In most cased, when git is used over ssh, public key authentication is used. The default git command does not have a forward agent parameter.

To enable agent forwarding, git has to be executed with the ``GIT_SSH_COMMAND`` environment variable.

    # start the ssh server
    ssh-mitm --remote-host github.com --request-agent --scp-interface debug_traffic
    # invoke git commands
    GIT_SSH_COMMAND="ssh -A" git clone ssh://git@127.0.0.1:10022/ssh-mitm/ssh-mitm.git

#### Intercept rsync

When ssh-mitm is used to intercept rsync, the port must be provided as a parameter to rsync. Also the agent can be forwarded, if needed.

To sync a local directory with a remote directory, rsync can be executed with following parameters.

    rsync -r -e 'ssh -p 10022 -A' /local/folder/ user@127.0.0.1:/remote/folder/

## Further steps

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
