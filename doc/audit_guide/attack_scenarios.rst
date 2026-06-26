:fas:`crosshairs` Positioning SSH-MITM
=======================================

.. tip:: **Try it first**

   The **Prologue** of the interactive tutorial positions SSH-MITM between
   mmorgan and ``web01.logfileinc.internal`` using a direct connection —
   the simplest case described on this page:

   .. code-block:: none

       $ ssh-mitm tutorial

   See :doc:`/get_started/index` for the full tutorial list.


SSH-MITM intercepts connections between an SSH client and a server.  For the
interception to work, the client must connect to SSH-MITM instead of the real
server.  Achieving this is the central challenge in every real-world audit.

This page covers the three fundamental positioning strategies: direct
connection, network redirection, and transparent proxying.


Threat model
------------

SSH-MITM requires exactly one thing: the client's TCP connection must reach
the SSH-MITM process.  It does **not** require:

- Access to the client machine
- Knowledge of the client's private key
- Control over the real server
- Any modification of the SSH protocol

The interception is entirely at the network or naming layer — which is what
the strategies below address.

.. note::

    SSH itself is not broken.  SSH-MITM can only intercept a session if the
    client accepted its host key.  A client that rejects the fingerprint
    cannot be intercepted — SSH-MITM cannot read or modify any data if the
    key was not trusted.


Direct connection
-----------------

The simplest positioning strategy is to have the client connect to SSH-MITM
directly.  No network manipulation is needed — SSH-MITM acts as the server
from the client's point of view and forwards every session to the real target.

.. code-block:: bash

    ssh-mitm server --remote-host <real-target>

.. mermaid::

    flowchart LR
        classDef client fill:#dae8fc,stroke:#6c8ebf
        classDef mitm fill:#f8cecc,stroke:#b85450
        classDef server fill:#d5e8d4,stroke:#82b366

        C(["SSH client"])
        M["SSH-MITM"]
        S(["Real server"])

        C -->|"connects to SSH-MITM"| M
        M -->|"forwards to"| S

        class C client
        class M mitm
        class S server

This scenario applies when:

- **Authorized audit / lab setup** — the client is pointed at SSH-MITM
  deliberately, e.g. to test a specific authentication flow or client
  hardening.
- **Rogue server** — SSH-MITM is reachable under a hostname the target client
  normally trusts (e.g. via a spoofed hostname, a misconfigured host alias,
  or social engineering that makes the user connect to the wrong host).
- **Compromised entry point** — SSH-MITM replaces or is installed alongside a
  bastion host, jump host, or CI runner that legitimate users connect to.
  Because the traffic passes through a host the organization already trusts,
  no network manipulation is required.
- **ProxyJump chain** — SSH-MITM runs as one hop in a multi-hop SSH chain.
  It intercepts the first connection; the client is unaware that the chain
  passes through a MITM.

The direct connection model is the setup used throughout the tutorial.


Network redirection
-------------------

When the client already connects to a specific hostname or IP that you cannot
replace, the alternative is to redirect that traffic to SSH-MITM at the
network layer.  The client believes it is connecting to the real server; the
packets arrive at SSH-MITM instead.

.. mermaid::

    flowchart LR
        classDef client fill:#dae8fc,stroke:#6c8ebf
        classDef mitm fill:#f8cecc,stroke:#b85450
        classDef server fill:#d5e8d4,stroke:#82b366
        classDef net fill:#fff2cc,stroke:#d6b656

        C(["SSH client"])
        N(["Network / DNS"])
        M["SSH-MITM"]
        S(["Real server"])

        C -->|"ssh target-host"| N
        N -.->|"redirected to SSH-MITM"| M
        M -->|"forwards to"| S

        class C client
        class M mitm
        class S server
        class N net

SSH-MITM itself does not perform the redirection — it only needs to listen on
the intercepted port.  Redirection is done with standard network tools:

**ARP spoofing** (same broadcast domain)
    The attacker sends forged ARP replies, associating the real server's IP
    address with the attacker's MAC address.  Clients on the same network
    segment send their SSH connections to the attacker's machine.  Works on
    Ethernet and Wi-Fi networks without additional infrastructure.

**DNS hijacking / poisoning**
    The real server's hostname resolves to SSH-MITM's IP address instead of
    the server's real address.  This can be achieved by controlling a DNS
    server the client queries, by poisoning the client's DNS cache, or by
    controlling the network's DHCP server to hand out a malicious DNS
    resolver.  Effective across network segments.

**Rogue access point**
    The attacker operates a Wi-Fi access point with the same SSID as a
    trusted network (e.g. a corporate network or a hotel hotspot).  Clients
    that connect to the rogue AP route all traffic through the attacker's
    machine, making any of the redirection techniques above trivially
    applicable.

**Compromised router or gateway**
    If the attacker controls a router or default gateway on the client's
    network path, static routes or packet filter rules can redirect SSH
    traffic to SSH-MITM without any per-client manipulation.

For authorized internal audits, a static route on a managed switch or firewall
is the least disruptive and most reliable approach.

.. note::

    These techniques require access to the network the client is on.  In a
    real penetration test engagement, the scope and authorization must
    explicitly cover the network segment being targeted.


Transparent proxy mode
----------------------

When SSH-MITM operates at a network gateway (e.g. the default gateway between
two network segments), transparent proxy mode lets it intercept SSH connections
without knowing the destination in advance.  The Linux kernel's TProxy feature
preserves the original destination address even after packet redirection, so
SSH-MITM can forward each session to the correct server automatically.

.. mermaid::

    flowchart LR
        classDef client fill:#dae8fc,stroke:#6c8ebf
        classDef mitm fill:#f8cecc,stroke:#b85450
        classDef server fill:#d5e8d4,stroke:#82b366

        subgraph net_a["Network A"]
            C(["SSH client"])
        end

        subgraph gw["Gateway (SSH-MITM)"]
            M["SSH-MITM<br/>transparent mode"]
        end

        subgraph net_b["Network B"]
            S(["SSH server"])
        end

        C -->|"ssh any-server"| M
        M -->|"forwards to original dest"| S

        class C client
        class M mitm
        class S server

Start SSH-MITM in transparent mode:

.. code-block:: bash

    ssh-mitm server --transparent

Transparent mode requires firewall rules (``iptables``/``nftables``) to
redirect port 22 traffic to SSH-MITM, and the ``CAP_NET_ADMIN`` capability or
root privileges.

.. seealso::

    :doc:`transparent` — full setup instructions including firewall rules,
    TProxy kernel configuration, and a worked network example.


Choosing a strategy
-------------------

.. list-table::
    :widths: 30 23 23 24
    :header-rows: 1

    * - Scenario
      - Direct
      - Network redirect
      - Transparent
    * - Authorized lab / controlled test
      - ✓ simplest
      -
      -
    * - Compromised jump host / bastion
      - ✓
      -
      -
    * - Same network segment as client
      -
      - ✓ ARP spoof
      - ✓ if at gateway
    * - Different network segment
      -
      - ✓ DNS hijack
      - ✓ if at gateway
    * - Unknown destination per session
      -
      -
      - ✓ required
    * - Wireless environment
      -
      - ✓ rogue AP
      -
