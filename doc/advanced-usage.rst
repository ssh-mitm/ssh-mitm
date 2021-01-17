Advanced usage
==============

SSH-MITM proxy server is capable of advanced man in the middle attacks and
can be used in scenarios, where the remote host is not known or a single
remote host is not sufficient or public key authentication is usded.

Public key authentication
-------------------------

Public key authentication is a way of logging into an SSH/SFTP account
using a cryptographic key rather than a password.

The advantage is, that no confidential data needs to be sent to the remote host which can
be intercepted by a man in the middle attack.

Due to this design concept, SSH-MITM proxy server is not able to reuse the data provided
during authentication.

It you need to intercept a client with public key authentication, there are some options.


Request ssh agent for authentication
""""""""""""""""""""""""""""""""""""

SSH supports agent forwarding, which allows a remote host to authenticate
against another remote host.

SSH-MITM proxy server is able to request the agent from the client and use
it for remote authentication. By using this feature, a SSH-MITM proxy server is able
to do a full man in the middle attack.

Since OpenSSH 8.4 the commands scp and sftp are supporting agent forwarding.
Older releases or other implementations, does not support agent forwarding for
file transfers.

Using agent forwarding, SSH-MITM proxy server must be started with ``--request-agent``.

.. code-block:: none
    :linenos:

    $ ssh-mitm --request-agent --remote-host 192.168.0.x

The client must be started with agent forwarding enabled.

.. code-block:: none
    :linenos:

    $ ssh -A -p 10022 user@proxyserver

.. note::

    If the client does not forward the agent, but SSH-MITM server requested the agent,
    the client will get a break in attempt.

    .. code-block:: none

        Warning: ssh server tried agent forwarding.
        Warning: this is probably a break-in attempt by a malicious server.



Redirect session to a honey pot
"""""""""""""""""""""""""""""""

If agent forwarding is not possible, the SSH-MITM proxy server can accept the
public key authentication request and redirect the session to a honey pot.

When the client sends a command, which requires a password to enter (like sudo),
those passwords can be used for further attacks.

SSH-MITM does not support reusing entered passwords for remote authentication,
but this feate could be implemented as a plugin.


Transparent proxy
-----------------

To intercept ssh sessions, where the destination is not known, ssh-mitm proxy server can run
in transparent mode, which uses the TProxy kernel feature from Linux.

Transparent proxying often involves "intercepting" traffic on a router. When redirecting packets
to a local socket, the destination address will be rewritten to the routers address.

To intercept ssh connections on a network, this is not acceptable. By using TProxy from the
Linux Kernel, SSH-MITM proxy server can intercept ssh connections, without loosing the
destination address.

.. note::

    To intercept the traffic, a static route can be configured on a router.
    An alternative to a static route is using arp spoofing.

    Both configurations are not part of this documentation.
