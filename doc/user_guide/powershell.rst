======================================================
:fab:`linux` Intercept PowerShell Remoting (PSRP)
======================================================

`PowerShell remoting over SSH <https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/ssh-remoting-in-powershell>`_
(PSRP over SSH) lets Windows and Linux clients run remote PowerShell sessions
without WinRM by using the SSH subsystem mechanism.
SSH-MITM intercepts these sessions transparently — logging credentials and
relaying the binary PSRP stream verbatim to the real server.


How PowerShell remoting over SSH works
=======================================

The client (``Enter-PSSession``, ``Invoke-Command``, or ``New-PSSession``)
connects to the SSH server and requests the ``powershell`` subsystem.  The
server must have this subsystem registered in ``/etc/ssh/sshd_config``:

.. code-block:: text

    Subsystem powershell /usr/bin/pwsh -sshs -NoLogo

Once the subsystem is granted, both sides exchange PSRP data over the SSH
channel for the full lifetime of the session.

.. _psrp-protocol:

PSRP wire format over SSH
--------------------------

PSRP over SSH does **not** use a raw binary stream.  Instead, each logical
message is wrapped in an XML envelope and the binary payload is base64-encoded
(`MS-PSRP specification §2.2.4, "SSH transport"
<https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/>`_):

.. code-block:: xml

    <Data Stream='Default' PSGuid='00000000-0000-0000-0000-000000000000'>
        AAAAAAAAAAE...BASE64...
    </Data>

Each ``<Data>`` element contains exactly one **PSRP fragment** encoded in
base64.  A fragment has the following 21-byte binary header followed by a
variable-length blob:

.. code-block:: none

    Offset  Size  Field        Description
    ------  ----  -----------  ------------------------------------------
         0     8  ObjectId     uint64 big-endian — groups fragments into
                               one logical message
         8     8  FragmentId   uint64 big-endian — sequence number within
                               the object
        16     1  Flags        bit 0 = start fragment; bit 1 = end fragment
        17     4  BlobLength   uint32 big-endian — length of the blob below
        21     N  Blob         raw bytes of this fragment's payload

Fragments with the same ``ObjectId`` are concatenated in order.  When
``Flags & 0x01`` (start) and ``Flags & 0x02`` (end) are both set on a single
fragment, that fragment is a complete, self-contained message.

The reassembled blob forms a **PSRP message** with a 40-byte header:

.. code-block:: none

    Offset  Size  Field        Description
    ------  ----  -----------  ------------------------------------------
         0     4  Destination  uint32 little-endian (1 = client, 2 = server)
         4     4  MessageType  uint32 little-endian (see table below)
         8    16  RPID         UUID (runspace pool ID)
        24    16  PID          UUID (pipeline ID, or all-zeros)
        40     *  MessageData  CLIXML (UTF-8 XML, optional BOM)

Common ``MessageType`` values:

.. list-table::
   :header-rows: 1
   :widths: 10 35 55

   * - Code
     - Name
     - Content
   * - 0x00010002
     - ``SessionCapability``
     - Protocol version negotiation
   * - 0x00010004
     - ``InitRunspacePool``
     - Pool parameters (min/max threads, ApartmentState, …)
   * - 0x00010007
     - ``RunspacePoolState``
     - ``<I32 N="RunspaceState">N</I32>`` where N: 0=BeforeOpen … 2=Opened … 4=Closed
   * - 0x00021006
     - ``CreatePipeline``
     - ``<S N="Cmd">command text</S>`` inside a nested CLIXML structure
   * - 0x00041002
     - ``PipelineOutput``
     - Serialised result objects in CLIXML
   * - 0x00041007
     - ``ErrorRecord``
     - ``<S N="Message">…</S>`` and stack-trace fields
   * - 0x00041008
     - ``WarningRecord``
     - Plain string
   * - 0x00041009
     - ``PipelineState``
     - ``<I32 N="PipelineState">N</I32>`` where N: 4=Completed, 6=Failed

Analysing sessions with SSH-MITM
----------------------------------

The ``log-session`` plugin is active by default.  It parses the PSRP protocol
on the fly and makes two types of output available: a human-readable transcript
file and a structured JSON log.

**Human-readable transcript file (recommended)**

Pass ``--psrp-transcript-dir`` to write one plain-text file per session:

.. code-block:: bash

    ssh-mitm server --remote-host <target> \
        --psrp-transcript-dir /tmp/psrp-transcripts/

Each file is named ``<session-id>.log``.  See :ref:`logging-transcripts` below
for the full format description.

**Structured JSON log**

When SSH-MITM's output is piped, it automatically switches to JSON format.
Pipe directly to :command:`jq` to filter live:

.. code-block:: bash

    ssh-mitm server --remote-host <target> \
        | jq 'select(.event == "psrp_message")'

To keep a log file and follow it at the same time:

.. code-block:: bash

    # Terminal 1 — start server, write JSON log
    ssh-mitm server --remote-host <target> > sshmitm.log

    # Terminal 2 — follow and filter
    tail -f sshmitm.log | jq 'select(.event == "psrp_message")'

Useful :command:`jq` queries:

.. code-block:: bash

    # Show all executed commands
    jq -r 'select(.message_type == "CreatePipeline")
            | "\(.timestamp)  \(.commands[]?)"' sshmitm.log

    # Show all errors
    jq 'select(.message_type == "ErrorRecord")' sshmitm.log


Prerequisites on the target host
=================================

The SSH server that SSH-MITM forwards to must have PowerShell Core (``pwsh``)
installed and the ``powershell`` subsystem registered in ``sshd_config``.

openSUSE Tumbleweed
-------------------

Register the Microsoft package repository and install PowerShell Core:

.. code-block:: bash

    # Import the Microsoft signing key
    sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc

    # Register the repository (adjust the URL for the current release if needed —
    # see https://learn.microsoft.com/en-us/powershell/scripting/install/install-rhel)
    sudo zypper addrepo https://packages.microsoft.com/rhel/8/prod microsoft-prod
    sudo zypper refresh

    # Install PowerShell Core
    sudo zypper install -y powershell

After installation verify the binary path:

.. code-block:: bash

    which pwsh          # → /usr/bin/pwsh
    pwsh --version      # → PowerShell 7.x.x

Register the subsystem with OpenSSH and restart the service:

.. code-block:: bash

    # Append the Subsystem line if it is not present yet
    grep -q "^Subsystem powershell" /etc/ssh/sshd_config || \
        echo "Subsystem powershell $(which pwsh) -sshs -NoLogo" \
        | sudo tee -a /etc/ssh/sshd_config

    sudo systemctl restart sshd

    # Confirm the line is active
    sudo sshd -T | grep "subsystem powershell"

Ubuntu / Debian
---------------

.. code-block:: bash

    # Install PowerShell Core from the Microsoft repository
    # (see https://learn.microsoft.com/en-us/powershell/scripting/install/install-ubuntu)
    sudo apt-get install -y powershell

    grep -q "^Subsystem powershell" /etc/ssh/sshd_config || \
        echo "Subsystem powershell $(which pwsh) -sshs -NoLogo" \
        | sudo tee -a /etc/ssh/sshd_config

    sudo systemctl restart sshd

Other distributions and Windows
--------------------------------

For other Linux distributions (Fedora, RHEL, Alpine, …) and for Windows Server
(OpenSSH) refer to the
`Microsoft documentation on PowerShell remoting over SSH
<https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/ssh-remoting-in-powershell>`_.
The ``sshd_config`` entry and the SSH-MITM workflow are identical regardless of
the operating system on the target host.


Setting up a local test environment
=====================================

The following steps let you test PowerShell interception on a single
openSUSE Tumbleweed machine without a separate target host.

**Requirements:** PowerShell Core and OpenSSH server installed (see above).

.. code-block:: bash

    # 1 — verify the powershell subsystem is registered (see Prerequisites above)
    sudo sshd -T | grep "subsystem powershell"

    # 2 — start SSH-MITM pointing at localhost port 22
    ssh-mitm server --remote-host 127.0.0.1 --remote-port 22 --listen-port 10022

In a second terminal, open an intercepted PowerShell session:

.. code-block:: bash

    pwsh -Command "Enter-PSSession -HostName 127.0.0.1 -Port 10022 -UserName $USER"

Accept the host-key warning (SSH-MITM presents its own generated key), enter
your password, and you will land in a remote PowerShell session that has been
routed transparently through SSH-MITM.


Intercepting a session against a real target
============================================

1. Start SSH-MITM
-----------------

.. code-block:: bash

    ssh-mitm server --remote-host <target-host>

By default SSH-MITM listens on port **10022**.

2. Connect through SSH-MITM
----------------------------

**From Linux (PowerShell Core):**

.. code-block:: bash

    pwsh -Command "Enter-PSSession -HostName <mitm-host> -Port 10022 -UserName <user>"

Or non-interactively:

.. code-block:: bash

    pwsh -Command "Invoke-Command -HostName <mitm-host> -Port 10022 -UserName <user> -ScriptBlock { hostname }"

**From Windows (PowerShell):**

.. code-block:: powershell

    Enter-PSSession -HostName <mitm-host> -Port 10022 -UserName <user>

3. Check the intercepted credentials
--------------------------------------

SSH-MITM logs the credentials as soon as authentication succeeds:

.. code-block:: none
   :class: no-copybutton

    INFO     Remote authentication succeeded
        Remote Address: <target-host>:22
        Username: testuser
        Password: hunter2
        Agent: no agent
    DEBUG    starting powershell subsystem relay
    ...
    DEBUG    powershell subsystem relay finished


.. _logging-transcripts:

Logging and transcripts
========================

The ``log-session`` plugin is active by default.  It parses the PSRP protocol
and logs every command, output, error, and state-change message.

To write a human-readable transcript file for each session, add
``--psrp-transcript-dir``:

.. code-block:: bash

    ssh-mitm server --remote-host <target> \
        --psrp-transcript-dir /tmp/psrp-transcripts/

Each session produces one file named ``<session-id>.log``:

.. code-block:: none
   :class: no-copybutton

    # PSRP transcript  session=f93cc784-7868-4f52-bfcb-82721024774f
    # started=2026-06-19T05:25:13.019806+00:00
    # timestamp                   direction      type                  detail
    #----------------------------------------------------------------------------------------------------
      2026-06-19T05:25:13.022Z  client→server  SessionCapability
      2026-06-19T05:25:13.324Z  server→client  RunspacePoolState     Opened
      2026-06-19T05:25:14.837Z  client→server  CreatePipeline        Get-Process | Sort-Object | Select-Object
      2026-06-19T05:25:15.138Z  server→client  PipelineOutput        codium
      2026-06-19T05:25:15.139Z  server→client  PipelineOutput        gnome-shell
      2026-06-19T05:25:15.139Z  server→client  PipelineState         Completed
      2026-06-19T05:25:16.247Z  client→server  CreatePipeline        Write-Error 'Kritischer Fehler'
      2026-06-19T05:25:16.349Z  server→client  ErrorRecord           Kritischer Fehler
      2026-06-19T05:25:16.349Z  server→client  WarningRecord         Warnung: Ressource knapp
      2026-06-19T05:25:16.349Z  server→client  PipelineOutput        Alles OK
      2026-06-19T05:25:16.349Z  server→client  PipelineState         Completed
      2026-06-19T05:25:16.752Z  server→client  RunspacePoolState     Closed
    # ended=2026-06-19T05:25:16.853269+00:00

When ``--session-log-dir`` is already configured, the transcript is written
there automatically even without ``--psrp-transcript-dir``.


Extending the forwarder
========================

To inspect or modify the raw PSRP stream, subclass
:class:`~sshmitm.forwarders.powershell.PowerShellForwarder` and override the
data hooks.  ``handle_client_data`` and ``handle_server_data`` receive every
chunk before it is forwarded; the return value is what gets sent on.

**Example — capture the raw wire stream to files for offline analysis:**

.. code-block:: python

    import os
    from sshmitm.forwarders.powershell import PowerShellForwarder

    class RawCapture(PowerShellForwarder):
        def handle_client_data(self, data: bytes) -> bytes:
            with open("/tmp/psrp-client.bin", "ab") as fh:
                fh.write(data)
            return data

        def handle_server_data(self, data: bytes) -> bytes:
            with open("/tmp/psrp-server.bin", "ab") as fh:
                fh.write(data)
            return data

The captured files contain the raw ``<Data>…</Data>`` XML stream and can be
decoded offline:

.. code-block:: python

    import base64, re, struct
    from psrpcore._payload import unpack_fragment, unpack_message

    DATA_RE = re.compile(rb"<Data[^>]*>([^<]*)</Data>")
    HEADER = 21
    fragments = {}

    for match in DATA_RE.finditer(open("/tmp/psrp-server.bin", "rb").read()):
        raw = bytearray(base64.b64decode(match.group(1)))
        if len(raw) < HEADER:
            continue
        blob_len = struct.unpack_from(">I", raw, 17)[0]
        frag = unpack_fragment(raw[:HEADER + blob_len])
        if frag.start:
            fragments[frag.object_id] = bytearray()
        if frag.object_id in fragments:
            fragments[frag.object_id].extend(frag.data)
        if frag.end and frag.object_id in fragments:
            msg = unpack_message(fragments.pop(frag.object_id))
            print(msg.message_type.name, bytes(msg.data)[:120])

Register the plugin in your ``pyproject.toml``:

.. code-block:: toml

    [project.entry-points."sshmitm.PowerShellBaseForwarder"]
    raw-capture = "mypkg.ps_capture:RawCapture"

Activate it with:

.. code-block:: bash

    ssh-mitm server --remote-host <target> --powershell-interface raw-capture

See :doc:`../develop/plugins` for the full plugin development guide.


Limitations
===========

* **PipelineOutput detail** — the ``log-session`` plugin extracts all CLIXML
  scalar values (strings, integers, doubles, booleans, dates, …) from pipeline
  output.  The values are joined with spaces; property names are not included.
  Deeply nested or binary objects may not produce human-readable output.

* **Certificate-based authentication** — if the client is configured to use
  SSH certificate authentication, SSH-MITM can intercept the session only when
  ``--accept-first-publickey`` is used or a matching CA key is available.

* **Known-hosts pinning** — clients that pin the server's host key will reject
  SSH-MITM's generated key.  Remove the old entry from ``~/.ssh/known_hosts``
  before testing, or pass a real host key with ``--host-key``.
