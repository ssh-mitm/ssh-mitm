===================================
:fas:`route` Transparent Proxy Mode
===================================

SSH-MITM is capable of advanced man-in-the-middle attacks. It
can be used in scenarios where the remote host is not known or a single
remote host is not sufficient.

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

Example network
===============

In following example there are 2 networks. SSH-MITM is installed on the default gateway.
This allows to intercept all connections between the two networks.

.. image:: transparent-network.png

The default gateway needs 2 network interfaces, one for each network.
The network interfaces must be configured as shown in the network diagram.


Setting up firewall rules
=========================

To setup SSH-MITM in transparent mode, the system has to be prepared.

**Using iptables:**

.. code-block:: none

    $ iptables -t mangle -A PREROUTING -p tcp --dport 22 -j TPROXY --tproxy-mark 0x1/0x1 --on-port=10022 --on-ip=127.0.0.1

**Using firewalld**

.. code-block:: none

    $ firewall-cmd --direct --permanent --add-rule ipv4 mangle PREROUTING 1 -p tcp --dport 22 --j TPROXY --tproxy-mark 0x1/0x1 --on-port=10022 --on-ip=127.0.0.1

Routing configuration
=====================

Following configuration is needed to redirect the incomming traffic to SSH-MITM.

.. code-block:: none

    $ echo 100 tproxy >> /etc/iproute2/rt_tables
    $ ip rule add fwmark 1 lookup tproxy
    $ ip route add local 0.0.0.0/0 dev lo table tproxy


Start SSH-MITM
==============

Now only the ssh proxy server needs to be started in transparent mode to be able to handle sockets that do not have local addresses:


.. code-block:: none

    $ ssh-mitm server --transparent

By using the transparent mode, no remote host must be specified. If the ``--remote-host`` parameter is used,
all incoming connections are redirected to the same remote host.


ARP Spoofing Issues
===================

When deploying SSH-MITM in transparent mode, Address Resolution Protocol (ARP) spoofing can
introduce challenges, such as network loops or unintended traffic redirection. To mitigate these
issues, it's essential to ensure that SSH-MITM can establish direct connections to the intended SSH
servers without being affected by its own ARP spoofing rules.

Using the ``ip`` Command to Prevent ARP Spoofing Issues
-------------------------------------------------------

To prevent ARP spoofing from affecting critical devices, a static ARP entry can be added using the
``ip`` command. This ensures that the system maintains the correct mapping between an IP address
and a hardware address (MAC address), preventing unwanted changes.

**Adding a Static ARP Entry**

In modern Linux distributions, the ``ip`` command replaces the older ``arp`` command for managing
neighbor entries. The following command adds a permanent ARP entry:

.. code-block:: bash

   ip neighbor add <TARGET_IP_ADDRESS> lladdr <MAC_ADDRESS> nud permanent dev <NETWORK_INTERFACE>

**Example:**

.. code-block:: bash

   ip neighbor add 192.168.1.100 lladdr 00:1A:2B:3C:4D:5E nud permanent dev eth0

- ``<TARGET_IP_ADDRESS>``: The IP address of the target device.
- ``<MAC_ADDRESS>``: The hardware address of the target device.
- ``<NETWORK_INTERFACE>``: The name of the network interface (e.g., ``eth0``).
- ``nud permanent``: Marks the entry as static and prevents automatic updates.

**Verifying and Managing ARP Entries**

To check the current ARP table:

.. code-block:: bash

   ip neighbor show

To delete a static ARP entry:

.. code-block:: bash

   ip neighbor del 192.168.1.100 dev eth0

By configuring static ARP entries appropriately, you can prevent SSH-MITM from intercepting its own
connections, ensuring stable and predictable network behavior during ARP spoofing scenarios.

