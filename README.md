# ssh-proxy-server - intercept ssh traffic

[![Github version](https://img.shields.io/github/v/release/manfred-kaiser/ssh-proxy-server?label=github&logo=github)](https://github.com/manfred-kaiser/ssh-proxy-server/releases)
[![PyPI version](https://img.shields.io/pypi/v/ssh-proxy-server.svg?logo=pypi&logoColor=FFE873)](https://pypi.org/project/ssh-proxy-server/)
[![Supported Python versions](https://img.shields.io/pypi/pyversions/ssh-proxy-server.svg?logo=python&logoColor=FFE873)](https://pypi.org/project/ssh-proxy-server/)
[![PyPI downloads](https://img.shields.io/pypi/dm/signed-xmlrpc.svg)](https://pypistats.org/packages/ssh-proxy-server)
[![GitHub](https://img.shields.io/github/license/manfred-kaiser/ssh-proxy-server.svg)](LICENSE)


`ssh-proxy-server` is a python library and command line utility to intercept ssh traffic.

At this time, only ssh (terminal) and scp filetransfers are supported.

This library can be used in cyber defense exercises when communication with a compromised server
and using credentials like usernames and passwords is not possible, because an attacker can use those to compromise more services and servers.

> :warning: **do not use this library in production environments! This tool is only for security audits!**

## Installation

`pip install ssh-proxy-server`

## Start Proxy Server with password authentication


Start the server:


```bash

ssh-proxy-server

```

Connect to server:

```bash

ssh -p 10022 user@remotehost@proxyserver

```

## Start Proxy Server with public key authentication

When public key authentication is used, the agent is forwarded to the remote server.

Start the server:

```bash

ssh-proxy-server --forward-agent

```

Connect to server:

```bash

ssh -A -p 10022 user@remotehost@proxyserver

```

