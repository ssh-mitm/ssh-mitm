Advanced usage cases
====================

SSH-MITM is capable of advanced man-in-the-middle attacks. It
can be used in scenarios where the remote host is not known or a single
remote host is not sufficient.

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

    $ ssh-mitm server --transparent

By using the transparent mode, no remote host must be specified. If the ``--remote-host`` parameter is used,
all incoming connections are redirected to the same remote host.


Debug git and rsync
-------------------

Sometimes it's interesting to debug ``git`` or ``rsync``.
Starting with version 5.4, SSH-MITM is able to intercept ssh commands like git or rsync.

Performing a ``git pull`` or ``rsync`` with a remote server only executes a remote ssh command and the file transfer is part of the communication.

There is also a new plugin ``debug_traffic`` to debug the traffic of ssh commands.

.. code-block:: bash

    ssh-mitm server --scp-interface debug_traffic


.. note::

    SCP file transfers are executed as ssh command. This is the reason why the ``debug_traffic`` plugin is implemented as a scp-interface plugin.


Intercept git
"""""""""""""

In most cased, when git is used over ssh, publickey authentication is used. The default git command does not have a forward agent parameter.

To enable agent forwarding, git has to be executed with the ``GIT_SSH_COMMAND`` environment variable.

.. code-block:: bash

    # start the ssh server
    ssh-mitm server --remote-host github.com --scp-interface debug_traffic

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
