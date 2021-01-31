TCP Proxy Server
================

TCP Proxy Server is used to implement port forwarding in ssh-mitm, but can also used
as standalone proxy server for tcp connections.

Start tcp-proxy-server
----------------------

To start the TCP Proxy Server without the SSH-MITM Server, the command ``tcp-proxy-server``
can be used.

Following command redirects the traffic from port 8080 to port 8000 on localhost.

.. code-block:: bash
    :linenos:

    $ tcp-proxy-server -lp 8080 -ti 127.0.0.1 -tp 8000


.. note::

    There are other modules, like the TProxy module, which supports running TCP Proxy Server
    in a transparent mode. Other modules can be used to handle the intercepted traffic.
    Those modules are explained in the next chapters.
