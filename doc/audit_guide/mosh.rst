============================================
:fas:`mobile` Intercept MOSH sessions
============================================

`Mosh <https://mosh.org>`_ (Mobile Shell) is a remote terminal application that runs
on top of SSH for session setup but then switches to its own UDP-based protocol called
the **State Synchronization Protocol (SSP)**.  Unlike SSH, Mosh maintains the session
across IP address changes and network interruptions, making it popular for mobile and
high-latency connections.

Because Mosh leaves the SSH connection after the initial handshake and communicates
directly over UDP, a standard SSH MITM proxy alone cannot intercept the terminal
traffic.  SSH-MITM includes a dedicated MOSH proxy that intercepts and decrypts the
UDP stream using the shared secret exchanged during the SSH session setup.


How MOSH works
==============

Session bootstrap
-----------------

Mosh uses SSH exclusively for bootstrapping:

1. The client connects to the server via SSH.
2. The server starts ``mosh-server``, which binds a UDP port in the range
   **60000–61000** and prints a ``MOSH CONNECT <port> <key>`` line back over the
   SSH channel.
3. The client reads the port and the shared AES-128 key, then closes the SSH
   connection and communicates with the server directly over UDP from that point on.

SSH-MITM intercepts the ``MOSH CONNECT`` line, starts its own UDP proxy, and rewrites
the line so that the client connects to the proxy instead of the real server.  The
shared secret and port are both logged:

.. code-block:: none
   :class: no-copybutton

    INFO  ℹ MOSH connection info
          * MOSH-port: 60001
          * MOSH-shared-secret: <base64-key>
    INFO  ℹ MOSH proxy started on port 60001 - the SSH connection will close, but MOSH remains active
    INFO  ℹ MOSH monitor on port 41409 - view intercepted session with: ssh-mitm mosh client 127.0.0.1 41409

.. warning::

    The shared secret printed in the log is sufficient to decrypt any MOSH traffic
    captured on the wire.  Treat SSH-MITM log output as sensitive data.


The State Synchronization Protocol (SSP)
-----------------------------------------

SSP operates in two layers:

**Datagram layer**
  Each UDP datagram carries an incrementing sequence number in cleartext and is
  encrypted with **AES-128 in OCB mode**.  The sequence number doubles as the nonce
  for AES-OCB and is used for RTT estimation.  Client roaming is implicit: the server
  always directs its replies to whichever IP address and port sent the most recent
  authenticated datagram.

**Transport layer**
  The transport layer synchronizes *object state* between client and server.  Instead
  of streaming every byte, it sends *diffs* between numbered states.  Because every
  diff is an idempotent operation (``old_num → new_num``), lost or reordered packets
  can simply be retransmitted without a replay cache.

  The server modulates its transmission rate like a frame rate (capped at 50 Hz),
  batching terminal updates into a single diff rather than sending one datagram per
  write.  Large diffs are split into fragments and reassembled by the receiver before
  parsing.


Packet structure
================

Encrypted wire format
---------------------

Every UDP datagram on the wire has this layout:

.. code-block:: none

    ┌──────────────────────────────────────────────────────────────┐
    │  Sequence number   8 bytes  (cleartext — used as nonce)      │
    ├──────────────────────────────────────────────────────────────┤
    │  Ciphertext        n bytes  (AES-128-OCB encrypted payload)  │
    │  Auth tag         16 bytes  (AES-128-OCB authentication tag) │
    └──────────────────────────────────────────────────────────────┘

The 12-byte AES-OCB nonce is constructed as:

.. code-block:: none

    nonce = b"\x00\x00\x00\x00" + sequence_number   (4 fixed zero bytes + 8-byte seq)

If the authentication tag verification fails, the datagram is discarded.

Decrypted payload
-----------------

After successful decryption the plaintext contains:

.. code-block:: none

    ┌─────────────────────────────────────────────────────────────────────┐
    │  Timestamp         2 bytes  (milliseconds, for RTT estimation)      │
    │  Timestamp reply   2 bytes  (echo of the remote's last timestamp)   │
    │  Fragment ID       8 bytes  (groups all fragments of one message)   │
    │  Fragment number   2 bytes  (high bit set = this is the last frag.) │
    │  Fragment payload  n bytes  (slice of the reassembled protobuf)     │
    └─────────────────────────────────────────────────────────────────────┘

Once all fragments with the same Fragment ID have arrived they are concatenated in
fragment-number order.  The reassembled bytes may be **zlib-compressed**; magic bytes
``\x78\x9c``, ``\x78\xda``, or ``\x78\x01`` at the start indicate deflate compression.
After optional decompression the data is parsed as a protobuf
``TransportBuffers.Instruction``:

.. code-block:: none

    Instruction {
        protocol_version  uint32
        old_num           uint64   ← source state number
        new_num           uint64   ← target state number
        ack_num           uint64   ← acknowledges remote new_num
        throwaway_num     uint64   ← states below this can be discarded
        diff              bytes    ← HostMessage or UserMessage (see below)
        chaff             bytes    ← random padding (traffic-analysis resistance)
    }


Message types
=============

The ``diff`` field is a protobuf message whose type depends on the direction of travel.

Server → Client: ``HostMessage``
---------------------------------

The server sends a ``HostMessage`` containing one or more ``Instruction`` records.
Each instruction carries exactly one of the following extensions:

.. list-table::
   :header-rows: 1
   :widths: 20 20 60

   * - Extension
     - Type
     - Description
   * - ``hostbytes``
     - ``HostBytes``
     - Raw terminal bytes from the server's pty.  These are standard VT100/ANSI
       sequences — the bytes that a terminal emulator must process to advance the
       screen from state ``old_num`` to state ``new_num``.  Both server responses
       and the server's echo of user input appear here as a single undifferentiated
       byte stream.
   * - ``echoack``
     - ``EchoAck``
     - Carries ``echo_ack_num``: the sequence number of the latest user keystroke
       whose effect should already be visible on screen.  Mosh uses this to decide
       whether its local speculative echo was correct.  The server often sends a
       second datagram with the same ``old_num`` roughly **50 ms** after the first,
       adding an ``EchoAck`` once the application has had time to process the input.
   * - ``resize``
     - ``ResizeMessage``
     - Notifies the client of a terminal size change (``width`` × ``height``).

Client → Server: ``UserMessage``
---------------------------------

The client sends a ``UserMessage`` containing one or more ``Instruction`` records.
Each instruction carries exactly one of:

.. list-table::
   :header-rows: 1
   :widths: 20 20 60

   * - Extension
     - Type
     - Description
   * - ``keystroke``
     - ``Keystroke``
     - Raw bytes typed by the user (``keys`` field).  Mosh sends every keystroke
       immediately without buffering.  In parallel, the client shows a **speculative
       local echo** — a locally rendered prediction of the effect — while waiting for
       server confirmation via ``EchoAck``.  The speculative echo is never transmitted;
       only the raw keystrokes are sent.
   * - ``resize``
     - ``ResizeMessage``
     - Notifies the server that the local terminal was resized.

Heartbeat packets
-----------------

Packets whose ``diff`` field is empty, or whose decoded message contains neither
``HostBytes`` nor ``Keystroke``, are heartbeats.  They keep the UDP path open,
provide timing information for RTT estimation, and allow the server to detect
when the client has roamed to a new IP address.


Intercepting MOSH sessions
==========================

SSH-MITM intercepts MOSH sessions automatically when the client starts a Mosh
connection through the proxy.  No additional server-side configuration is required.

Quick start
-----------

.. code-block:: none

    # Terminal 1 — start the proxy (listens on port 10022 by default)
    $ ssh-mitm server --remote-host <target-host>

    # Terminal 2 — connect through the proxy with mosh
    $ mosh --ssh="ssh -p 10022" user@<proxy-host>

    # The proxy logs the shared secret and the monitor port, e.g.:
    #   INFO  ℹ MOSH monitor on port 41409 - view intercepted session with: ssh-mitm mosh client 127.0.0.1 41409

    # Terminal 3 — attach a live viewer
    $ ssh-mitm mosh client 127.0.0.1 41409

If you changed ``--listen-port`` on the proxy, adjust the ``-p`` argument in the
``mosh --ssh`` call accordingly.

What is intercepted
-------------------

Once the MOSH handshake completes, SSH-MITM has the shared AES-128 session key and
decrypts every UDP packet in both directions:

* **Server → Client** (``HostMessage`` / ``HostBytes``): the raw VT100/ANSI terminal
  bytes produced by the server.  These are forwarded in real time to the monitor and
  rendered by the built-in viewer.
* **Client → Server** (``UserMessage`` / ``Keystroke``): the raw bytes typed by the
  user.  The proxy decodes and has access to these keystrokes, but the current
  implementation does not forward them to the live viewer — they are available as a
  basis for plugin development.

The monitor port streams the decrypted terminal output of the session.  Any number of
viewers can connect, and a viewer that connects after the session has already started
receives the full history immediately.


Viewing the intercepted session
================================

Use the built-in ``ssh-mitm mosh client`` command to attach a full terminal emulator
to the monitor stream:

.. code-block:: none

    $ ssh-mitm mosh client 127.0.0.1 41409

The viewer behaviour:

* The local terminal is put into **cbreak mode**: keyboard input is silenced and
  not echoed, so nothing you type interferes with the display.
* Only **Ctrl+C** is recognised, to exit the viewer.
* The **alternate screen buffer** is used, so your terminal content is fully restored
  when you quit.
* Connecting **after** the session has started is safe — the monitor server buffers
  all terminal output and replays it on connect.
* Received bytes are fed into a **pyte** VT100/ANSI terminal emulator.  Escape
  sequences such as ``ESC[O`` (keypad initialisation sent by ``vim``) are processed
  internally and never shown as literal characters.
* Only rows that changed since the last render are redrawn (**dirty-line rendering**),
  minimising flickering.

.. note::

    The viewer shows the **server's authoritative terminal state**, reconstructed
    from ``HostBytes`` packets only.  It does not receive the client-side speculative
    local echo that the real Mosh user sees while waiting for server confirmation.
    During fast typing there can therefore be a brief visual difference between what
    the target user currently sees and what the viewer displays; both converge once
    the server sends its next ``HostBytes`` update acknowledging the keystrokes.

Terminal size
-------------

The viewer uses the size of your local terminal.  Resizing the terminal window sends
``SIGWINCH``, which the client catches: it reads the new dimensions, calls
``screen.resize()`` on the pyte virtual screen, and immediately redraws the full
screen.

Note that the intercepted MOSH session runs at its own fixed terminal size on the
server.  The viewer cannot change that size, so if your local terminal is larger the
extra rows and columns remain empty, and if it is smaller some content may be clipped.

Known limitations of the terminal emulator
------------------------------------------

The viewer uses `pyte <https://pyte.readthedocs.io>`_, a pure-Python VT100/ANSI
terminal emulator.  pyte handles the vast majority of real-world terminal output but
has known gaps:

* **Scrollback buffer**: only the current visible screen is rendered; scrollback
  history is not replayed or displayed.
* **256-colour and True Colour**: 256-colour (``xterm-256color``) is supported; 24-bit
  True Colour sequences (``CSI 38;2;r;g;b m``) may be silently dropped or
  approximated.
* **Mouse reporting**: SGR mouse-tracking escape sequences are not handled.
  The viewer itself cannot forward mouse events to the session.
* **Uncommon escape sequences**: sixel graphics, ``DECCRA``, ``REP``, and similar
  less-common sequences are ignored or only partially handled.


Security properties relevant for auditors
==========================================

No forward secrecy
-------------------

Mosh derives a single AES-128 session key at connection time and uses it for the
entire session without any key rotation.  There is no Diffie-Hellman or equivalent
exchange within the UDP protocol itself.

**Consequence:** anyone who obtains the session key — including from SSH-MITM logs —
can decrypt all past and future traffic of that session.  Captured pcap files of a
MOSH session become fully readable offline once the key is known.

Key logged in cleartext
-----------------------

SSH-MITM logs the base64-encoded AES-128 session key as part of normal operation.
The key can be extracted from the log and used with a packet capture to reconstruct
the complete terminal session, including passwords typed during the session.

Keystroke timing in encrypted traffic
--------------------------------------

Even without decrypting the traffic, the timing and size of Client→Server packets
reveals per-keystroke timing with millisecond resolution.  The EchoAck pattern on
the Server→Client side (a second datagram ~50 ms after each keystroke) further
reinforces this signal.  Keystroke timing analysis can be used to infer what was
typed, independent of encryption.

MOSH session persists after SSH ends
--------------------------------------

The SSH connection is closed as soon as the ``MOSH CONNECT`` handshake completes.
The MOSH UDP session then runs independently and can remain active indefinitely,
even if the original SSH client disconnects.  This is relevant for incident response:
terminating the SSH session does not terminate the MOSH session.

Network identification
-----------------------

MOSH server processes bind UDP ports in the range **60000–61000** by default.  MOSH
traffic is therefore easy to identify in network captures or firewall logs by
destination port, even without decryption.  The characteristic pattern of small,
evenly-timed heartbeat packets alternating with larger data bursts also makes MOSH
sessions distinguishable from other UDP protocols.

Nonce reuse risk
-----------------

The AES-OCB nonce is derived solely from the 8-byte sequence number.  The protocol
does not include a session identifier in the nonce.  If two sessions were ever
established with the same key — which should not happen in a correctly functioning
implementation — nonce reuse would completely break AES-OCB confidentiality and
authentication.  This is a theoretical risk but worth noting when evaluating
non-standard Mosh deployments or forks.
