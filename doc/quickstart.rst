Quickstart
==========

Eager to get started? This page gives a good introduction in how to get started with SSH-MITM.

First, make sure that:

* SSH-MITM is :ref:`installed <Installation of SSH-MITM>`
* SSH-MITM is up-to-date

Let’s get started with some simple examples.


Start the ssh-mitm proxy server
-------------------------------

Starting an intercepting mitm-ssh server with password authentication is very simple.

All you have to do is run this command in your terminal of choice.

.. code-block:: bash
    :linenos:

    $ ssh-mitm --remote-host 192.168.0.x

Now let's try to connect to the ssh-mitm server.
The ssh-mitm server is listening on port 10022.

.. code-block:: bash
    :linenos:

    $ ssh -p 10022 user@proxyserver

You will see the credentials in the log output.


.. code-block:: none
    :linenos:

    2021-01-01 11:38:26,098 [INFO]  Client connection established with parameters:
        Remote Address: 127.0.0.1
        Port: 22
        Username: user
        Password: supersecret
        Key: None
        Agent: None
