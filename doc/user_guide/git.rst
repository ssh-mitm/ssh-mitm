:fas:`code-branch` Git over SSH
================================

.. note::

    This page is a placeholder and will be expanded with a full walkthrough
    of intercepting Git over SSH, including authentication, traffic capture,
    and an audit scenario.

Git uses SSH as a transport when cloning or pushing via ``ssh://`` or the
``git@host:repo`` shorthand.  SSH-MITM intercepts this traffic using the
``debug_traffic`` plugin, which captures the raw SSH command exchange:

.. code-block:: bash

    ssh-mitm server --remote-host github.com --scp-interface debug_traffic

In most cases git over SSH uses public-key authentication.  The default
``git`` command does not forward the SSH agent, so pass it explicitly via
``GIT_SSH_COMMAND``:

.. code-block:: bash

    GIT_SSH_COMMAND="ssh -A" git clone ssh://git@127.0.0.1:10022/ssh-mitm/ssh-mitm.git

.. note::

    Git traffic is captured via the SCP interface plugin because git commands
    run as SSH exec requests — the same channel type SCP uses.
