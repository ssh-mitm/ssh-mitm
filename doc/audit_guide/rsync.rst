:fas:`rotate` rsync over SSH
=============================

.. note::

    This page is a placeholder and will be expanded with a full walkthrough
    of intercepting rsync over SSH, including traffic capture and an audit
    scenario.

rsync uses SSH as a transport by default.  SSH-MITM intercepts rsync sessions
using the ``debug_traffic`` plugin:

.. code-block:: bash

    ssh-mitm server --remote-host <target-host> --scp-interface debug_traffic

Pass the SSH-MITM port directly to rsync via the ``-e`` flag:

.. code-block:: bash

    rsync -r -e 'ssh -p 10022 -A' /local/folder/ user@127.0.0.1:/remote/folder/

.. note::

    rsync traffic is captured via the SCP interface plugin because rsync
    commands run as SSH exec requests — the same channel type SCP uses.
