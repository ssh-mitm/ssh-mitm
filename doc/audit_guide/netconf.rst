========================================
:fas:`network-wired` NETCONF (RFC 6242)
========================================

NETCONF is the network management protocol used to configure routers,
switches, and other managed devices. It runs as an SSH subsystem — the
same transport mechanism as SFTP — which means SSH-MITM can intercept
NETCONF sessions the same way it intercepts any other SSH traffic.

Once positioned between a NETCONF client and a managed device, SSH-MITM
decrypts every RPC operation the client sends and every reply the server
returns, without interrupting the session.


Quick start
===========

Start SSH-MITM with the NETCONF logging plugin. Point it at the target
device on port 830 (the IANA-assigned NETCONF port):

.. code-block:: none

    $ ssh-mitm server \
        --remote-host <device-ip> \
        --remote-port 830 \
        --listen-port 10022 \
        --netconf-forwarder log-session

Route the NETCONF client through SSH-MITM instead of connecting directly:

.. code-block:: none

    $ netconf-console --host 127.0.0.1 --port 10022 -u admin --get

SSH-MITM intercepts the session, logs every RPC operation and reply, and
forwards everything to the real device unchanged.


Log output
==========

For each client RPC, the proxy logs the operation name and its
``message-id``:

.. code-block:: none
    :class: no-copybutton

    INFO  NETCONF RPC  [session=1 message-id=101 op=get-config]
    INFO  NETCONF reply[session=1 message-id=101 ok]
    INFO  NETCONF RPC  [session=1 message-id=102 op=edit-config]
    INFO  NETCONF reply[session=1 message-id=102 ok]

If the server returns an error, the error tags are included:

.. code-block:: none
    :class: no-copybutton

    WARNING  NETCONF reply[session=1 message-id=103 error(s)=invalid-value]


Framing support
===============

NETCONF has used two message-framing formats across its history:

.. list-table::
   :header-rows: 1
   :widths: 20 25 55

   * - RFC
     - Framing
     - Terminator
   * - RFC 4742 (legacy)
     - EOM
     - ``]]>]]>`` appended to each message
   * - RFC 6242 (current)
     - Chunked
     - ``\n#<size>\n<data>...\n##\n``

SSH-MITM detects the framing mode automatically from the ``<hello>``
exchange: if both sides advertise ``:base:1.1``, chunked framing is used
for all subsequent messages. Otherwise the legacy EOM format is used.
No configuration is required.


Test setup
==========

Two server implementations are recommended for testing:

**yuma123 / netconfd** — RFC 4742, EOM framing (easy to install):

.. code-block:: none

    # Debian / Ubuntu
    $ sudo apt install yuma123
    $ sudo netconfd --no-startup --superuser=$USER

**netopeer2** — RFC 6242, chunked framing (modern devices):

Build from source following the upstream documentation at
https://github.com/CESNET/netopeer2.

**Client**:

.. code-block:: none

    $ pip install netconf-console

    # Basic <get> request
    $ netconf-console --host 127.0.0.1 --port 10022 -u admin --get


Writing a custom NETCONF plugin
================================

To inspect or rewrite individual RPC messages, subclass
:class:`~sshmitm.forwarders.netconf.NetconfBaseForwarder` and override
``handle_rpc_request`` or ``handle_rpc_reply``.

Return a modified :class:`~xml.etree.ElementTree.Element` to rewrite the
message, or ``None`` to forward the original bytes unchanged:

.. code-block:: python

    import xml.etree.ElementTree as ET
    from sshmitm.forwarders.netconf import NetconfBaseForwarder

    class MyNetconfPlugin(NetconfBaseForwarder):

        def handle_rpc_request(self, message_id, operation, element):
            if operation == "edit-config":
                print(f"[AUDIT] edit-config message-id={message_id}")
            return None  # forward unchanged

        def handle_rpc_reply(self, message_id, element):
            return None  # forward unchanged

Enable the plugin with ``--netconf-forwarder``:

.. code-block:: none

    $ ssh-mitm server --remote-host <device-ip> --remote-port 830 \
        --netconf-forwarder my_package.my_module:MyNetconfPlugin


Known limitations
=================

.. warning::

    The NETCONF forwarder is **experimental**. It is functional for testing
    and auditing purposes but has not been hardened for production use.

- **No notification support** — NETCONF event notifications
  (RFC 5277 ``create-subscription``) are forwarded transparently but not
  tracked or intercepted.
- **No mid-session attach** — SSH-MITM must be present from the start of
  the connection; it cannot attach to an already-established NETCONF session.
