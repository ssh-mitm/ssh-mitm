:fas:`plus` Advanced usage cases
================================

Debug git and rsync
-------------------

Sometimes it's interesting to debug ``git`` or ``rsync``.
Starting with version 5.4, SSH-MITM is able to intercept ssh commands like git or rsync.

Performing a ``git pull`` or ``rsync`` with a remote server only executes a remote ssh command and the file transfer is part of the communication.

There is also a new plugin ``debug_traffic`` to debug the traffic of ssh commands.

.. code-block:: none

    $ ssh-mitm server --scp-interface debug_traffic


.. note::

    SCP file transfers are executed as ssh command. This is the reason why the ``debug_traffic`` plugin is implemented as a scp-interface plugin.


Intercept git
"""""""""""""

In most cased, when git is used over ssh, publickey authentication is used. The default git command does not have a forward agent parameter.

To enable agent forwarding, git has to be executed with the ``GIT_SSH_COMMAND`` environment variable.

.. code-block:: none

    # start the ssh server
    $ ssh-mitm server --remote-host github.com --scp-interface debug_traffic

.. code-block:: none

    # invoke git commands
    $ GIT_SSH_COMMAND="ssh -A" git clone ssh://git@127.0.0.1:10022/ssh-mitm/ssh-mitm.git


Intercept rsync
"""""""""""""""

When SSH-MITM is used to intercept rsync, the port must be provided as a parameter to rsync.
Also the agent can be forwarded, if needed.


To sync a local directory with a remote directory, rsync can be executed with following parameters.

.. code-block:: none

    $ rsync -r -e 'ssh -p 10022 -A' /local/folder/ user@127.0.0.1:/remote/folder/
