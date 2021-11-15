Authentication
==============

The choice of the right authentication method against SSH-MITM can have a decisive influence on the success of a Man in the Middle attack.

The most popular authentication methods are "password" and "publickey" authentication. However, there are others, such as "none" and "keyboard-interactive".

To log in to an SSH server it is necessary to specify an existing user. There are systems that use a default username.
This is most common with Git repositories. Examples of this are GitLab and GitHub, which use the username "git" and distinguish which
resources a user is allowed to access based on the public key at login.


none Authentication
-------------------

The none authentication takes a special position among the authentication methods.
The reason is that this authentication method is used to tell the client which methods are accepted by the server. For this reason, none-Authentication is executed before all other authentication methods.

However, it can also be used to give a user access to a system without requiring an explicit login.

password authentication
-----------------------

Password authentication is one of the most common login methods. Almost all current operating systems support this method both for local logins and over the network. By default, OpenSSH and many other SSH servers have this type of authentication active.

With SSH, within the encrypted channel, the password is transmitted in clear text. If a client connects to a Man in the Middle server, the server is able to read the username and password in clear text. This information can then be used to log in to other servers if the user exists and uses the same password.

Another problem is that accounts with weak passwords can be compromised relatively easily through a brute force attack. This happens very often with IoT devices because they often have the same username on many devices and they are protected by a default password or only a weak password is set.

.. warning::

    Password authentication should not be used for these reasons!


Example SSH-MITM session intercepting password authentication:

.. code-block:: none

    $ ssh-mitm
    2021-09-02 09:51:35,354 [INFO]  starting SSH-MITM 0.5.13
    2021-09-02 09:51:38,590 [INFO]  connected client version: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
    2021-09-02 09:51:48,629 [INFO]  Client connection established with parameters:
        Remote Address: 127.0.0.1
        Port: 22
        Username: testuser
        Password: secret
        Key: None
        Agent: no agent


keyboard-interactive authentication
-----------------------------------

keyboard-interactive is similar to password authentication. The main difference is that the server can send any number of requests to the client, which are necessary for the login process. The server defines both the prompt text and whether the value is visible or not when entered.

In many cases keyboard-interactive is used for 2 factor authentication. In the first step a password is requested and then e.g. the input of a time-based token is necessary (TOTP).

Unless special tools are used to create cryptographically secured input, all input via keyboard-interactive can be reused during a man in the middle attack to login to another server.



publickey authentication
------------------------

In contrast to password authentication, where the password is transmitted in plain text, publickey authentication is based on asymmetric encryption. In asymmetric encryption, a key pair consisting of a private part and a public part is created.

With SSH, the public key is stored on the server while the private key remains in the possession of the user.

With OpenSSH, the private key can be additionally protected by a password in case it is stolen. Starting with OpenSSH 8.2, FIDO2 tokens are supported and can be used for a 2 factor confirmation when using the key.

As an alternative to a FIDO2 token, SSH-Askpass can also be used to confirm cryptographic operations. If there is an increased need for security, SSH-Askpass should only be used if the use of a FIDO2 token is not possible.

Publickey authentication is only partially suitable for a man-in-the-middle attack. Unlike password authentication, no data is exchanged that can be used for a complete login.

Another problem is that the key that should be used for the login is not known. This can lead to FIDO2 and SSH-Askpass protected keys displaying a prompt for an incorrect key to the user.

An attacker should use PublicKey authentication only if the client does not accept other authentication methods.
