# ssh-proxy-server - intercept ssh traffic

[![Github version](https://img.shields.io/github/v/release/manfred-kaiser/ssh-proxy-server?label=github&logo=github)](https://github.com/manfred-kaiser/ssh-proxy-server/releases)
[![PyPI version](https://img.shields.io/pypi/v/ssh-proxy-server.svg?logo=pypi&logoColor=FFE873)](https://pypi.org/project/ssh-proxy-server/)
[![Supported Python versions](https://img.shields.io/pypi/pyversions/ssh-proxy-server.svg?logo=python&logoColor=FFE873)](https://pypi.org/project/ssh-proxy-server/)
[![PyPI downloads](https://pepy.tech/badge/ssh-proxy-server/week)](https://pepy.tech/project/ssh-proxy-server/week)
[![GitHub](https://img.shields.io/github/license/manfred-kaiser/ssh-proxy-server.svg)](LICENSE)


`ssh-proxy-server` is an intercepting (mitm) proxy server for security audits.

**Since release 0.1.5, SSH Proxy Server has full support for tty (shell), scp and sftp!**

> :warning: **do not use this library in production environments! This tool is only for security audits!**

## Installation

`pip install ssh-proxy-server`

## Start Proxy Server

### Password authentication


Start the server:


```bash

ssh-proxy-server --remote-host 127.0.0.1

```

Connect to server:

```bash

ssh -p 10022 user@proxyserver

```

### Public key authentication

When public key authentication is used, the agent is forwarded to the remote server.

Start the server:

```bash
ssh-proxy-server --forward-agent --remote-host 127.0.0.1
```

Connect to server:

```bash
ssh -A -p 10022 user@proxyserver
```

## SSH MITM Attacks

SSH uses trust on first use. This means, that you have to accept the fingerprint if it is not known.

```bash
$ ssh -p 10022 hugo@localhost
The authenticity of host '[localhost]:10022 ([127.0.0.1]:10022)' can't be established.
RSA key fingerprint is SHA256:GIAALZgy8Z86Sezld13ZM74HGbE9HbWjG6T9nzja/D8.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '[localhost]:10022' (RSA) to the list of known hosts.
```
If a server fingerprint is known, ssh warns the user, that the host identification has changed.

```bash
$ ssh -p 10022 remoteuser@localhost
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the RSA key sent by the remote host is
SHA256:GIAALZgy8Z86Sezld13ZM74HGbE9HbWjG6T9nzja/D8.
Please contact your system administrator.
Add correct host key in /home/user/.ssh/known_hosts to get rid of this message.
Offending RSA key in /home/user/.ssh/known_hosts:22
  remove with:
  ssh-keygen -f "/home/user/.ssh/known_hosts" -R "[localhost]:10022"
RSA host key for [localhost]:10022 has changed and you have requested strict checking.
Host key verification failed.
```


## Available modules

The proxy can be configured and extended using command line arguments.

Some arguments accept Python-class names as string.

Loading a class from a package:

`ssh-proxy-server --ssh-interface ssh_proxy_server.forwarders.ssh.SSHForwarder`

> :warning: creating a pip package for custom classes is recommended, because loading from files has some bugs at the moment

Loading a class from a file (experimental):

`ssh-proxy-server --ssh-interface /path/to/my/file.py:ExtendedSSHForwarder`

### SSH interface

- **cmd argument:** `--ssh-interface`
- **base class:** `ssh_proxy_server.forwarders.ssh.SSHBaseForwarder`
- **default:** `ssh_proxy_server.forwarders.ssh.SSHForwarder`

#### Available forwarders:

- **`ssh_proxy_server.forwarders.ssh.SSHForwarder`** - forwards traffic from client to remote server
- **`ssh_proxy_server.forwarders.ssh.SSHLogForwarder`** - write the session to a file, which can be replayed with `script`
- **`ssh_proxy_server.forwarders.ssh.NoShellForwarder`** - keeps the session open, when used as master channel, but tty should not be possible to the remote server


### SCP interface

- **cmd argument:** `--scp-interface`
- **base class:** `ssh_proxy_server.forwarders.scp.SCPBaseForwarder`
- **default:** `ssh_proxy_server.forwarders.scp.SCPForwarder`

#### Available forwarders:

- **`ssh_proxy_server.forwarders.scp.SCPForwarder`** - transfer file between client and server
- **`ssh_proxy_server.forwarders.scp.SCPStorageForwarder`** - save file to file system


### Authentication:

- **cmd argument:** `--authenticator`
- **base class:** `ssh_proxy_server.authentication.Authenticator`
- **default:** `ssh_proxy_server.authentication.AuthenticatorPassThrough`

#### Available Authenticators:

- **`ssh_proxy_server.authentication.AuthenticatorPassThrough`** - default authenticator, which can reuse credentials

Currently, only one authenticator (AuthenticatorPassThrough) exists, but it supports arguments to specify remote host, username and password, which shlould fit most scenarios. (public keys are on the roadmap)
