Advanced usage cases
====================

SSH-MITM is capable of advanced man-in-the-middle attacks. It
can be used in scenarios where the remote host is not known or a single
remote host is not sufficient.


Publickey authentication
-------------------------

**Publickey authentication** is supported and SSH-MITM is able to detect, if a user is able
to login with publickey authentication on the remote server. This allows SSH-MITM to acccept
the same key as the destination server.

If publickey authentication is not possible, the
authentication will fall back to password-authentication.


Agent forwarding
""""""""""""""""

SSH supports agent forwarding, which allows a remote host to authenticate
against another remote host.

SSH-MITM is able to request the agent from the client and use
it for remote authentication. By using this feature, it's possible
to do a full man-in-the-middle attack when publickey authentication is used.

Since OpenSSH 8.4 the commands scp and sftp support agent forwarding.
Older releases or other implementations do not support agent forwarding for
file transfers.

Publickey authentication in SSH-MITM is enabled by default. All you have to do is to start the server:

.. code-block:: none
    :linenos:

    $ ssh-mitm --remote-host 192.168.0.x:PORT

The client must be started with agent forwarding enabled.

.. code-block:: none
    :linenos:

    $ ssh -A -p 10022 user@proxyserver



Using ssh agent forwarding comes with some security risks and should not be used
when the integrity of a machine is not trusted. (https://tools.ietf.org/html/draft-ietf-secsh-agent-02)

.. code-block:: none

    6.  Security Considerations

    The authentication agent is used to control security-sensitive
    operations, and is used to implement single sign-on.

    Anyone with access to the authentication agent can perform private key
    operations with the agent.  This is a power equivalent to possession of
    the private key as long as the connection to the key is maintained.  It
    is not possible to retrieve the key from the agent.

    It is recommended that agent implementations allow and perform some form
    of logging and access control.  This access control may utilize
    information about the path through which the connection was received (as
    collected with SSH_AGENT_FORWARDING_NOTICE messages; however, the path
    is reliable only up to and including the first unreliable machine.).
    Implementations should also allow restricting the operations that can be
    performed with keys - e.g., limiting them to challenge-response only.

    One should note that a local superuser will be able to obtain access to
    agents running on the local machine.  This cannot be prevented; in most
    operating systems, a user with sufficient privileges will be able to
    read the keys from the physical memory.

    The authentication agent should not be run or forwarded to machine whose
    integrity is not trusted, as security on such machines might be
    compromised and might allow an attacker to obtain unauthorized access to
    the agent.

    Adding a key with SSH_AGENT_ADD_KEY over the net (especially over the
    Internet) is generally not recommended, because at present the private
    key has to be moved unencrypted. Implementations SHOULD warn the user of
    the implications. Even moving the key in encrypted form could be
    considered unwise.


Currently, SSH-MITM only uses the forwarded agent for remote authentication,
but does not allow to rewrite the ``SSH_AGENT_FORWARDING_NOTICE`` message.

If a client uses an agent which displays a warning when the client is accessed, the original notice will be shown.


Redirect session to a honeypot
""""""""""""""""""""""""""""""

If agent forwarding is not possible, SSH-MITM can accept the
publickey authentication request and redirect the session to a honeypot.

When the client sends a command which requires a password to enter (like sudo),
those passwords can be used for further attacks.

.. code-block:: none
    :linenos:

    ssh-mitm --fallback-host username:password@hostname:port

Connections are only redirected to the honeypot if no agent was forwarded after publickey authentication.
All other connections are forwarded to the destination server and a full man in the middle attack is possible.


Transparent proxy
-----------------

To intercept ssh sessions, where the destination is not known, SSH-MITM can run
in transparent mode, which uses the TProxy kernel feature from Linux.

Transparent proxying often involves "intercepting" traffic on a router. When redirecting packets
to a local socket, the destination address will be rewritten to the routers address.

To intercept ssh connections on a network, this is not acceptable. By using TProxy from the
Linux Kernel, SSH-MITM can intercept ssh connections without losing the
destination address.

.. note::

    To intercept the traffic, a static route can be configured on a router.
    An alternative to a static route is using arp spoofing.

    Router configuration and arp spoofing are not part of this documentation.


Setting up firewall rules
"""""""""""""""""""""""""

To setup SSH-MITM in transparent mode, the system has to be prepared.

**Using iptables:**

.. code-block:: none

    $ iptables -t mangle -A PREROUTING -p tcp --dport 22 -j TPROXY --tproxy-mark 0x1/0x1 --on-port=10022 --on-ip=127.0.0.1

**Using firewalld**

.. code-block:: none

    firewall-cmd --direct --permanent --add-rule ipv4 mangle PREROUTING 1 -p tcp --dport 22 --j TPROXY --tproxy-mark 0x1/0x1 --on-port=10022 --on-ip=127.0.0.1

.. warning::

    Additional firewall rules may be necessary to maintain device management capabilities over ssh


.. note::

    To process the packets locally, further routing needs to take place:

    .. code-block:: none

        $ echo 100 tproxy >> /etc/iproute2/rt_tables
        $ ip rule add fwmark 1 lookup tproxy
        $ ip route add local 0.0.0.0/0 dev lo table tproxy


Now only the ssh proxy server needs to be started in transparent mode to be able to handle sockets that do not have local addresses:


.. code-block:: none

    $ ssh-mitm --transparent

By using the transparent mode, no remote host must be specified. If the ``--remote-host`` parameter is used,
all incoming connections are redirected to the same remote host.


Debug git and rsync
-------------------

Sometimes it's interesting to debug ``git`` or ``rsync``.
Starting with version 5.4, SSH-MITM is able to intercept ssh commands like git or rsync.

Performing a ``git pull`` or ``rsync`` with a remote server only executes a remote ssh command and the file transfer is part of the communication.

There is also a new plugin ``debug_traffic`` to debug the traffic of ssh commands.

.. code-block:: bash

    ssh-mitm --scp-interface debug_traffic


.. note::

    SCP file transfers are executed as ssh command. This is the reason why the ``debug_traffic`` plugin is implemented as a scp-interface plugin.


Intercept git
"""""""""""""

In most cased, when git is used over ssh, publickey authentication is used. The default git command does not have a forward agent parameter.

To enable agent forwarding, git has to be executed with the ``GIT_SSH_COMMAND`` environment variable.

.. code-block:: bash

    # start the ssh server
    ssh-mitm --remote-host github.com:PORT --scp-interface debug_traffic

    # invoke git commands
    GIT_SSH_COMMAND="ssh -A" git clone ssh://git@127.0.0.1:10022/ssh-mitm/ssh-mitm.git


Intercept rsync
"""""""""""""""

When SSH-MITM is used to intercept rsync, the port must be provided as a parameter to rsync. Also the agent can be forwarded, if needed.


To sync a local directory with a remote directory, rsync can be executed with following parameters.

.. code-block:: bash

    rsync -r -e 'ssh -p 10022 -A' /local/folder/ user@127.0.0.1:/remote/folder/


Further steps
-------------

SSH-MITM has some client exploits integrated, which can be used to audit various ssh clients like OpenSSH and PuTTY.

.. toctree::
    :maxdepth: 1

    CVE-2021-33500
    CVE-2020-14145
    CVE-2020-14002
    CVE-2019-6111
    CVE-2019-6110
    CVE-2019-6109
