=================================
SSH-MITM - ssh audits made simple
=================================

ssh man-in-the-middle (ssh-mitm) server for security audits supporting **publickey authentication**, **session hijacking** and **file manipulation**

.. image:: _static/image2.png

Introduction
============

**SSH-MITM** is a man in the middle SSH Server for security audits and malware analysis.

Password and publickey authentication are supported and SSH-MITM is able to detect, if a user is able to
login with publickey authentication on the remote server. This allows SSH-MITM to accept the same key as
the destination server. If publickey authentication is not possible, the authentication will fall
back to password-authentication.

When publickey authentication is possible, a forwarded agent is needed to login to the remote server.
In cases, when no agent was forwarded, SSH-MITM can rediredt the session to a honeypot.

Installation
============

This part of the documentation covers the installation of SSH-MITM.
The first step to using any software package is getting it properly installed.

To install SSH-MITM, simply run one of those commands in your terminal of choice:

:fab:`linux` Flatpak
--------------------

Install SSH-MITM as Flatpak from Flathub:

.. code-block:: none

    # install Flatpak
    $ flatpak install flathub at.ssh_mitm.server

    # run SSH-MITM from Flatpak
    $ flatpak run at.ssh_mitm.server


:fab:`ubuntu` snap
------------------

If you use ``snap``, you can install it with:

.. code-block:: none

    $ sudo snap install ssh-mitm


:fas:`cog` AppImage
-------------------

If you use the ``AppImage``, you can install it as:

.. code:: none

    $ wget https://github.com/ssh-mitm/ssh-mitm/releases/latest/download/ssh-mitm-x86_64.AppImage
    $ chmod +x ssh-mitm*.AppImage


:fab:`python` pip
------------------

If you use ``pip``, you can install it with:

.. code-block:: none

    $ python3 -m pip install ssh-mitm


For more installation methods, refer to the  :doc:`installation guide </get_started/installation>`.


Start SSH-MITM
==============

Let’s get started with some simple examples.

Starting an intercepting mitm-ssh server is very simple.

All you have to do is run this command in your terminal of choice.

.. code-block:: none

    $ ssh-mitm server --remote-host 192.168.0.x

Now let's try to connect to the ssh-mitm server.
The ssh-mitm server is listening on port 10022.

.. code-block:: none

    $ ssh -p 10022 testuser@proxyserver

You will see the credentials in the log output.


.. code-block:: none
    :class: no-copybutton

    INFO     Remote authentication succeeded
        Remote Address: 192.168.0.x:22
        Username: testuser
        Password: secret
        Agent: no agent


Hijack a SSH terminal session
=============================

Getting the plain text credentials is only half the fun.
SSH-MITM proxy server is able to hijack a ssh session and allows you to interact with it.

Let's get started with hijacking the session.

When a client connects, the ssh-mitm proxy server starts a new server, where you can connect with another ssh client.
This server is used to hijack the session.

.. code-block:: none
    :class: no-copybutton

    INFO     ℹ created mirrorshell on port 34463. connect with: ssh -p 34463 127.0.0.1

To hijack the session, you can use your favorite ssh client. This connection does not require authentication.

.. code-block:: none

    $ ssh -p 34463 127.0.0.1

After you are connected, your session will only be updated with new responses, but you are able to execute commands.

Try to execute somme commands in the hijacked session or in the original session.

The output will be shown in both sessions.


Publickey authentication
========================

SSH-MITM is able to verify, if a user is able to login with publickey authentication on the remote server.
If publickey authentication is not possible, SSH-MITM falls back to password authentication.
This step does not require a forwarded agent.

For a full login on the remote server agent forwarding is still required. When no agent was forwarded,
SSH-MITM can redirect the connection to a honeypot.

.. code-block:: none

    $ ssh-mitm server --enable-auth-fallback \
      --fallback-host HONEYPOT \
      --fallback-username HONEYPOT_USER \
      --fallback-password HONEYPOT_PASSWORD


.. toctree::
   :maxdepth: 1
   :hidden:

   get_started/index
   user_guide/index
   vulnerabilities/index
   develop/contributing
   api
