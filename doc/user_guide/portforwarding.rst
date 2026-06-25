====================================
:fas:`network-wired` Port Forwarding
====================================

SSH port forwarding (SSH tunneling) routes TCP traffic through an encrypted
SSH connection.  The core idea: if your machine cannot reach a service
directly — because it sits behind a firewall or in a separate network segment
— but an SSH server *can*, you can borrow that connectivity by tunneling
through the SSH connection.

In an audit, this matters in two directions: understanding what traffic the
intercepted client is tunneling, and using those tunnels yourself to reach
internal services that are otherwise inaccessible.

Types of Port Forwarding
========================

There are three types of port forwarding with SSH:

* **Local port forwarding:** opens a port on *your* machine; connections to
  that port are forwarded through the SSH server to a destination.
  Useful for reaching services that are only reachable from the server side.
* **Remote port forwarding:** opens a port on the *SSH server*; connections
  to that port are forwarded back through the tunnel to your machine.
  Useful for exposing a local service to anyone on the server side.
* **Dynamic port forwarding:** turns the SSH client into a SOCKS proxy.
  Each application request is forwarded through the server to its own
  destination — no fixed target required.

The names refer to *where the port is opened*: **local** means on your own
machine, **remote** means on the SSH server.

.. warning::

    Traffic monitoring and filtering is usually in place for a reason.
    Only use port forwarding in audits that explicitly authorise it.


Local Port Forwarding
---------------------

Local port forwarding opens a port on Alice's laptop.  Any connection to that
port travels through the SSH tunnel to ``dev-server`` and from there to the
destination — which only needs to be reachable from ``dev-server``, not from
Alice's laptop directly.

**Scenario:** Logfile Inc.'s internal employee portal (``portal.logfile.internal``)
runs on plain HTTP — it is only reachable from within the corporate network, so
no one bothered adding TLS.  Alice opens a local tunnel so she can access it
from her laptop:

.. code-block:: bash

    ssh -L 8080:portal.logfile.internal:80 alice@dev-server

The ``-L`` format is ``LOCAL_PORT:DESTINATION_HOST:DESTINATION_PORT``:

* ``8080`` — port opened on Alice's laptop
* ``portal.logfile.internal`` — destination host, resolved by ``dev-server``
* ``80`` — destination port on that host

For the duration of the session, ``http://localhost:8080/`` in Alice's browser
connects to the internal portal through the tunnel.

.. mermaid::

    flowchart TD
        classDef client fill:#dae8fc,stroke:#6c8ebf
        classDef server fill:#d5e8d4,stroke:#82b366
        classDef external fill:#fff2cc,stroke:#d6b656
        classDef dest fill:#e1d5e7,stroke:#9673a6

        subgraph alice["Alice's laptop"]
            B(["Browser"])
            L["SSH client"]
        end

        subgraph corp["Logfile Inc. network"]
            D["dev-server"]
            P(["portal.logfile.internal:80"])
        end

        B -.->|"request localhost:8080"| L
        L -->|"SSH tunnel · -L 8080:portal.logfile.internal:80"| D
        D -.->|"plain HTTP"| P

        class L client
        class D server
        class B external
        class P dest


Remote Port Forwarding
----------------------

Remote port forwarding opens a port on ``dev-server``.  Connections to that
port travel back through the tunnel to Alice's laptop and from there to the
destination.

**Scenario:** Alice is running a local development server on her laptop
(port 3000) and wants to show it to a colleague who is logged in on
``dev-server``.  She opens a remote tunnel:

.. code-block:: bash

    ssh -R 8000:localhost:3000 alice@dev-server

The ``-R`` format is ``REMOTE_PORT:DESTINATION_HOST:DESTINATION_PORT``:

* ``8000`` — port opened on ``dev-server``
* ``localhost`` — destination host, resolved by Alice's laptop (herself)
* ``3000`` — destination port on that host

For the duration of the session, anyone on ``dev-server`` can reach
``localhost:8000`` and the request is forwarded to Alice's laptop on port 3000.

.. mermaid::

    flowchart LR
        classDef client fill:#dae8fc,stroke:#6c8ebf
        classDef server fill:#d5e8d4,stroke:#82b366
        classDef external fill:#fff2cc,stroke:#d6b656

        subgraph alice["Alice's laptop"]
            L["SSH client<br/>(localhost:3000)"]
        end

        subgraph corp["Logfile Inc. network"]
            direction TB
            D["dev-server"]
            C(["Colleague"])
        end

        L -->|"SSH tunnel<br/>-R 8000:localhost:3000"| D
        C -.->|"request localhost:8000"| D
        D -.->|"forwarded via tunnel<br/>to localhost:3000"| L

        class L client
        class D server
        class C external


Dynamic Port Forwarding
-----------------------

Dynamic port forwarding turns the SSH connection into a SOCKS proxy.  Unlike
local port forwarding, there is no fixed destination — each application
request is forwarded individually, so Alice can reach any host that
``dev-server`` can reach.

.. note::

    The SOCKS protocol never reaches the server.  The OpenSSH client handles
    it locally: it accepts SOCKS5 connections from applications and converts
    each one into a standard ``direct-tcpip`` channel — the same mechanism
    used for local port forwarding.  ``dev-server`` sees individual connection
    requests with explicit destinations; it never processes SOCKS.

**Scenario:** Alice needs to reach several internal services during an audit
session.  Instead of opening a separate local tunnel for each one, she opens
a single SOCKS proxy:

.. code-block:: bash

    ssh -D 1080 alice@dev-server

Any application that supports SOCKS5 (browser, curl, vulnerability scanner)
can now route traffic through ``dev-server`` to the internal network.  The
tunnel closes when Alice closes the SSH session.

.. mermaid::

    flowchart LR
        classDef client fill:#dae8fc,stroke:#6c8ebf
        classDef server fill:#d5e8d4,stroke:#82b366
        classDef external fill:#fff2cc,stroke:#d6b656
        classDef dest fill:#e1d5e7,stroke:#9673a6

        subgraph alice["Alice's laptop (SOCKS proxy: localhost:1080)"]
            direction TB
            L["SSH client"]
            B1(["Browser"])
            B2(["curl / scanner"])
        end

        subgraph corp["Logfile Inc. network"]
            direction TB
            D["dev-server"]
            P1(["portal.logfile.internal"])
            P2(["any internal host"])
        end

        B1 -.->|"via SOCKS"| L
        B2 -.->|"via SOCKS"| L
        L -->|"SSH tunnel<br/>-D 1080"| D
        D -.-> P1
        D -.-> P2

        class L client
        class D server
        class B1,B2 external
        class P1,P2 dest


Bastion hosts
=============

A bastion host is a hardened, publicly reachable machine that acts as the
entry point to a network.  SSH's ``ProxyJump`` (``-J``) chains the connection
through the bastion transparently.

**Scenario:** ``dev-server`` is the only machine at Logfile Inc. reachable
from outside.  Alice needs to connect directly to an internal database server
(``db-server.logfile.internal``) that is firewalled from the internet.
``ProxyJump`` lets her do it in one command:

.. code-block:: bash

    ssh -J alice@dev-server alice@db-server.logfile.internal

SSH establishes the first connection to ``dev-server`` and uses it as a relay
to ``db-server.logfile.internal``.  Alice needs only one command; ``dev-server``
sees an encrypted relay channel, not a shell session.

You can also specify different users and ports:

.. code-block:: bash

    ssh -J alice@dev-server:22 alice@db-server.logfile.internal:2222

.. note::

    ``ProxyJump`` uses a ``direct-tcpip`` channel on the bastion rather than
    a full shell session.  SSH-MITM intercepts and rewrites these channels, so
    the forwarded connection remains visible at the proxy layer — but because
    the payload is an independent SSH session, its contents are encrypted from
    SSH-MITM's point of view unless a second SSH-MITM instance is chained.


Port forwarding in SSH-MITM
===========================

SSH-MITM intercepts both local and remote port forwarding requests from the
client and surfaces them as usable tunnels for the auditor.  No extra
configuration is needed — SSH-MITM handles this automatically.


Local port forwarding
---------------------

When Alice opens a local port forward (``-L``), SSH-MITM receives the
``direct-tcpip`` channel from her client.  At the same time, SSH-MITM starts
a local SOCKS server that the auditor can use independently to reach the same
destination.

.. mermaid::

    flowchart LR
        classDef client fill:#dae8fc,stroke:#6c8ebf
        classDef mitm fill:#f8cecc,stroke:#b85450
        classDef server fill:#d5e8d4,stroke:#82b366
        classDef external fill:#fff2cc,stroke:#d6b656
        classDef dest fill:#e1d5e7,stroke:#9673a6

        subgraph alice["Alice's laptop"]
            direction TB
            L["SSH client<br/>-L 8080:portal.logfile.internal:80"]
            B(["Browser"])
        end

        subgraph intercept["Interception"]
            direction TB
            M["SSH-MITM"]
            A(["Auditor"])
        end

        subgraph corp["Logfile Inc. network"]
            direction TB
            D["dev-server"]
            P(["portal.logfile.internal:80"])
        end

        B -.->|"request localhost:8080"| L
        L -->|"SSH tunnel"| M
        M -->|"relay"| D
        M -.->|"plain HTTP visible"| P
        A -.->|"via SOCKS<br/>localhost:PORT"| M

        class L client
        class M mitm
        class D server
        class B,A external
        class P dest

SSH-MITM prints the SOCKS details to its log as soon as the tunnel is opened:

.. code-block:: none
    :class: no-copybutton

    INFO     ℹ a9ed77c5-ef1b-42ec-b0f7-57594f4a7b42 - local port forwarding
        SOCKS port: 39859
          SOCKS4:
            * socat: socat TCP-LISTEN:LISTEN_PORT,fork socks4:127.0.0.1:DESTINATION_ADDR:DESTINATION_PORT,socksport=39859
            * netcat: nc -X 4 -x localhost:39859 address port
          SOCKS5:
            * netcat: nc -X 5 -x localhost:39859 address port

The log shows a template — fill in the values for the intercepted tunnel:

* ``LISTEN_PORT`` — any free local port, e.g. ``8080``
* ``DESTINATION_ADDR`` — the tunneled destination, e.g. ``portal.logfile.internal``
* ``DESTINATION_PORT`` — the destination port, e.g. ``80``

For the portal scenario:

.. code-block:: bash

    socat TCP-LISTEN:8080,fork socks5:127.0.0.1:portal.logfile.internal:80,socksport=39859

Because ``portal.logfile.internal`` uses plain HTTP, the traffic is
unencrypted — the auditor can read every request and response in full, even
though it arrived over an SSH tunnel.


Remote port forwarding
----------------------

When Alice opens a remote port forward (``-R``), she is asking ``dev-server``
to listen on a port and forward connections back to her.  SSH-MITM sits in
the middle and also exposes that connection locally.

.. mermaid::

    flowchart LR
        classDef client fill:#dae8fc,stroke:#6c8ebf
        classDef mitm fill:#f8cecc,stroke:#b85450
        classDef server fill:#d5e8d4,stroke:#82b366
        classDef external fill:#fff2cc,stroke:#d6b656

        subgraph alice["Alice's laptop"]
            direction TB
            L["SSH client<br/>-R 8000:localhost:3000"]
            S(["Dev server<br/>localhost:3000"])
        end

        subgraph intercept["Interception"]
            direction TB
            M["SSH-MITM"]
            A(["Auditor"])
        end

        subgraph corp["Logfile Inc. network"]
            direction TB
            D["dev-server"]
            C(["Colleague"])
        end

        L -->|"SSH tunnel"| M
        M --> D
        C -.->|"request localhost:8000"| D
        A -.->|"request<br/>localhost:PORT injector"| M
        M -.->|"forwarded via tunnel"| L
        L -.->|"localhost:3000"| S

        class L client
        class S dest
        class M mitm
        class D server
        class C,A external

SSH-MITM prints the injector details to its log:

.. code-block:: none
    :class: no-copybutton

    created server tunnel injector for host 127.0.0.1 on port 38763 to destination ('localhost', 3000)

The auditor can connect to the injector port alongside the original client.
This makes it possible to inspect or interact with Alice's exposed service
during an audit without disrupting her session.


ProxyJump
---------

SSH-MITM intercepts ``ProxyJump`` (``-J``) connections and rewrites the
forwarded channel.  From the client's perspective the jump succeeds normally;
SSH-MITM sees and controls the relay.

Because the payload of a ``ProxyJump`` is an independent SSH session, its
contents are encrypted end-to-end — SSH-MITM cannot read the inner session
without chaining a second SSH-MITM instance as the final target.  However,
metadata is visible: SSH-MITM knows that a jump occurred, to which
destination, and can log or redirect the connection.
