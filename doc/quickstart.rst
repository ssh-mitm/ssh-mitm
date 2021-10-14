Quickstart
==========

**SSH-MITM** is a man in the middle SSH Server for security audits and malware analysis.

Password and publickey authentication are supported and SSH-MITM is able to detect, if a user is able to
login with publickey authentication on the remote server. This allows SSH-MITM to acccept the same key as
the destination server. If publickey authentication is not possible, the authentication will fall
back to password-authentication.

When publickey authentication is possible, a forwarded agent is needed to login to the remote server.
In cases, when no agent was forwarded, SSH-MITM can rediredt the session to a honeypot.

.. raw:: html

    <p align="center">
    <a href="https://www.ssh-mitm.at/img/ssh-mitm-password.png">
        <img alt="SSH-MITM intercepting password login" title="SSH-MITM" src="https://www.ssh-mitm.at/img/ssh-mitm-password.png" width="75%" >
    </a>
    <p align="center">ssh man-in-the-middle (ssh-mitm) server for security audits supporting<br> <b>publickey authentication</b>, <b>session hijacking</b> and <b>file manipulation</b></p>
    <p align="center">
    <a href="https://snapcraft.io/ssh-mitm">
        <img alt="Get it from the Snap Store" src="https://snapcraft.io/static/images/badges/en/snap-store-black.svg" />
    </a>
    <br />
    <br />

    </p>
    </p>
    <section class="how-section py-5">
        <div class="container">
            <div class="row">
                <div class="item col-12 col-md-4">
                    <div class="icon-holder">
                        <img src="https://www.ssh-mitm.at/assets/images/streamline-free/monitor-loading-progress.svg" alt="">
                        <div class="arrow-holder d-none d-lg-inline-block"></div>
                    </div><!--//icon-holder-->
                    <div class="desc p-3">
                        <h5><span class="step-count mr-2">1</span>Install SSH-MITM</h5>
                        <p>
                            To install SSH-MITM, simply run this command in your terminal of choice:<br/>
                            <code>
                                $ sudo snap install ssh-mitm
                            </code>
                        </p>
                        <p><a href="https://snapcraft.io/ssh-mitm">
                            <img alt="Get it from the Snap Store" src="https://snapcraft.io/static/images/badges/en/snap-store-black.svg" />
                        </a></p>
                    </div><!--//desc-->
                </div><!--//item-->
                <div class="item col-12 col-md-4">
                    <div class="icon-holder">
                        <img src="https://www.ssh-mitm.at/assets/images/streamline-free/programmer-male.svg" alt="">
                        <div class="arrow-holder d-none d-lg-inline-block"></div>
                    </div><!--//icon-holder-->
                    <div class="desc p-3">
                        <h5><span class="step-count mr-2">2</span>Connect to the network</h5>
                        <p>
                            To start an intercepting mitm-ssh server on Port 10022,
                            all you have to do is run a single command.<br/>
                            <code>$ ssh-mitm --remote-host 192.168.0.x:PORT</code>
                        </p>
                        <p>
                            Now let's try to connect to the ssh-mitm server.<br/>
                            <code>$ ssh -p 10022 user@proxyserver</code>
                        </p>
                    </div><!--//desc-->
                </div><!--//item-->
                <div class="item col-12 col-md-4">
                    <div class="icon-holder">
                        <img src="https://www.ssh-mitm.at/assets/images/streamline-free/customer-service-woman.svg" alt="">
                    </div><!--//icon-holder-->
                    <div class="desc p-3">
                        <h5><span class="step-count mr-2">3</span>Hijack SSH sessions</h5>
                        <p>
                            When a client connects, the ssh-mitm starts a new server, which is used for session hijacking.<br/>
                            <code>[INFO]  created injector shell on port 34463</code>
                        </p><p>
                            To hijack this session, you can use your favorite ssh client.
                            All you have to do is to connect to the hijacked session.<br/>
                            <code>$ ssh -p 34463 127.0.0.1</code>
                        </p>
                    </div><!--//desc-->
                </div><!--//item-->
            </div><!--//row-->
        </div><!--//container-->
    </section><!--//how-section-->



Alternative installation methods
--------------------------------

This part of the documentation covers the installation of SSH-MITM.
The first step to using any software package is getting it properly installed.

To install SSH-MITM, simply run one of those commands in your terminal of choice:

Install as snap
"""""""""""""""

.. code-block:: bash

    $ sudo snap install ssh-mitm


Install with pip
""""""""""""""""

.. code-block:: bash

    $ python -m pip install ssh-mitm

Install as AppImage
"""""""""""""""""""

.. code-block:: bash

    $ wget https://github.com/ssh-mitm/ssh-mitm/releases/latest/download/ssh-mitm-x86_64.AppImage
    $ chmod +x ssh-mitm*.AppImage


Start SSH-MITM
--------------

Let’s get started with some simple examples.

Starting an intercepting mitm-ssh server with password authentication is very simple.

All you have to do is run this command in your terminal of choice.

.. code-block:: bash

    $ ssh-mitm --remote-host 192.168.0.x:PORT

Now let's try to connect to the ssh-mitm server.
The ssh-mitm server is listening on port 10022.

.. code-block:: bash

    $ ssh -p 10022 testuser@proxyserver

You will see the credentials in the log output.


.. code-block:: none

    INFO     Remote authentication succeeded
        Remote Address: 127.0.0.1:22
        Username: testuser
        Password: secret
        Agent: no agent


Hijack a SSH terminal session
-----------------------------

Getting the plain text credentials is only half the fun.
SSH-MITM proxy server is able to hijack a ssh session and allows you to interact with it.

Let's get started with hijacking the session.

When a client connects, the ssh-mitm proxy server starts a new server, where you can connect with another ssh client.
This server is used to hijack the session.

.. code-block:: none

    INFO     ℹ created mirrorshell on port 34463. connect with: ssh -p 34463 127.0.0.1

To hijack the session, you can use your favorite ssh client. This connection does not require authentication.

.. code-block:: bash

    $ ssh -p 34463 127.0.0.1

After you are connected, your session will only be updated with new responses, but you are able to execute commands.

Try to execute somme commands in the hijacked session or in the original session.

The output will be shown in both sessions.


Publickey authentication
------------------------

SSH-MITM is able to verify, if a user is able to login with publickey authentication on the remote server.
If publickey authentication is not possible, SSH-MITM falls back to password authentication.
This step does not require a forwarded agent.

For a full login on the remote server agent forwarding is still required. When no agent was forwarded,
SSH-MITM can redirect the connection to a honeypot.

.. code-block:: bash

    $ ssh-mitm --fallback-host username:password@hostname:port
