===============
Port Forwarding
===============

Port forwarding via SSH (SSH tunneling) creates a secure connection between a local computer
and a remote machine through which services can be relayed. Because the connection is encrypted,
SSH tunneling is useful for transmitting information that uses an unencrypted protocol, such as IMAP, VNC, or IRC.

Types of Port Forwarding
========================

SSH's port forwarding feature can smuggle various types of Internet traffic into or out of a network.
This can be used to avoid network monitoring or sniffers, or bypass badly configured routers on the Internet.
Note: You might also need to change the settings in other programs (like your web browser) in order to circumvent these filters.

.. warning::

  Filtering and monitoring is usually implemented for a reason. Even if you don't agree with that reason, your IT department might not take kindly to you flouting their rules.

There are three types of port forwarding with SSH:

* **Local port forwarding:** connections from the SSH client are forwarded via the SSH server, then to a destination server
  For example, local port forwarding lets you bypass a company firewall that blocks specific websites.
* **Remote port forwarding:** connections from the SSH server are forwarded via the SSH client, then to a destination server
  For example, remote port forwarding lets you connect from your SSH server to a computer on your company's intranet.
* **Dynamic port forwarding:** connections from various programs are forwarded via the SSH client, then via the SSH server, and finally to several destination servers


Local Port Forwarding
---------------------

Local port forwarding lets you connect **from your local computer** to another server.

For example, say you wanted to connect from your laptop to :samp:`http://docs.ssh-mitm.at` using an SSH tunnel.
You would use source port number :samp:`8443` (the alternate https port), destination port :samp:`443` (the http port), and destination server :samp:`docs.ssh-mitm.at`. :

.. code-block::

  ssh -L 8443:docs.ssh-mitm.at:443 <host>

Where <host> should be replaced by the name of your ssh server. The -L option specifies local port forwarding.
For the duration of the SSH session, pointing your browser at :samp:`https://localhost:8443/` would send you to :samp:`https://docs.ssh-mitm.at/`.

In the above example, we used port 8443 for the source port.
Ports numbers less than 1024 or greater than 49151 are reserved for the system,
and some programs will only work with specific source ports, but otherwise you can use any source port number.

.. figure:: /images/ssh_local_port_forward.png
  :scale: 100

  ..

Remote Port Forwarding
----------------------

Remote port forwarding lets you connect **from the remote SSH server** to another server.

For example, say you wanted to let a developer access your internal file storage (e.g. Nextcloud), using the command-line SSH client.
You would use port number 5900 (the first VNC port), and destination server localhost:

.. code-block::

  ssh -R 8443:filestorage:443 remoteuser@remoteserver

The -R option specifies remote port forwarding.
For the duration of the SSH session, the developer would be able to access
your filestorage (Nextcloud) by connecting the webbroweser to port 8443 on the remoteserver.



.. figure:: /images/ssh_remote_port_forward.png
  :scale: 100

  ..

Dynamic Port Forwarding
-----------------------

Dynamic port forwarding turns your SSH client into a SOCKS proxy server.
SOCKS is a little-known but widely-implemented protocol for programs to request any Internet connection through a proxy server.
Each program that uses the proxy server needs to be configured specifically, and reconfigured when you stop using the proxy server.

.. note::

  Dynamic port forwarding is implemented in the ssh client. The server receives a normal local portforwarding request
  and does require not know anything about dynamic port forwarding.

  The only difference between local port forwarding and dynamic portforwarding is how the port forwarding is configured.
  With local portforwarding you have to know each connection when the ssh client is started.
  Dynamic port forwarding allows you to add new connections, while the client is already connected to the server.

For example, say you wanted Firefox to connect to every web page through your SSH server. First you would use dynamic port forwarding with the default SOCKS port:

.. code-block::

  ssh -D 1080 laptop

The -D option specifies dynamic port forwarding. 1080 is the standard SOCKS port.
Although you can use any port number, some programs will only work if you use 1080.

Next you would tell Firefox to use your proxy:

* go to Edit -> Preferences -> Advanced -> Network -> Connection -> Settings...
* check "Manual proxy configuration"
* make sure "Use this proxy server for all protocols" is cleared
* clear "HTTP Proxy", "SSL Proxy", "FTP Proxy", and "Gopher Proxy" fields
* enter "127.0.0.1" for "SOCKS Host"
* enter "1080" (or whatever port you chose) for Port.

The SOCKS proxy will stop working when you close your SSH session. You will need to change these settings back to normal in order for Firefox to work again.

To make other programs use your SSH proxy server, you will need to configure each program in a similar way.

If you want to use an application which does not support the SOCKS protocol, you can use :samp:`socat` to create a plain socket for a specific connection.


Bastion hosts
=============

The concept of bastion hosts is nothing new to computing.
Baston hosts are usually public-facing, hardened systems that serve as an entrypoint to systems
behind a firewall or other restricted location, and they are especially popular with the rise of cloud computing.

The ssh command has an easy way to make use of bastion hosts to connect to a remote host with a single command.
Instead of first SSHing to the bastion host and then using ssh on the bastion to connect to the remote host,
ssh can create the initial and second connections itself by using ProxyJump.

ProxyJump
---------

The ``ProxyJump``, or the ``-J`` flag, was introduced in ssh version 7.3.
To use it, specify the bastion host to connect through after the ``-J`` flag, plus the remote host:


.. code-block::

  $ ssh -J <bastion-host> <remote-host>

You can also set specific usernames and ports if they differ between the hosts:

.. code-block::

  $ ssh -J user@<bastion:port> <user@remote:port>

.. note::

  ProxyJump is a variation of a local port forward assumes that the
  to-be established connection over the port forward is a ssh connection and therefore uses the master channel
  as a direct-tcpip channel to the jumphost (stdin and stdout are connected to the direct-tcpip channel).
  The jumphost will therefore not receive a formal shell-session channel request.

SSH-MITM is able to intercept those connections and rewrites which allows SSH-MITM to intercept the forwarded connection.
Since the forwarded connection is encrypted it is not possible to read the data sent between the client and the server.

.. note::

  It's possible to rewrite the connection to another SSH-MITM instance. This allows to read the data when using ProxyJump.
  Note: At the moment this is not implemented and requires some code changes and special configuration.


Port forwarding in SSH-MITM
===========================

SSH-MITM supports both local and remote port forwarding.
No further configuration is required for this.


Local port forwading
--------------------

.. figure:: /images/ssh-mitm_client_port_inject.png
  :scale: 100

  ..


Local port forwarding can be established at any time by the man in the middle server.
The corresponding commands are displayed in the output of SSH-MITM.

.. code-block::

  INFO     ℹ a9ed77c5-ef1b-42ec-b0f7-57594f4a7b42 - local port forwading
      SOCKS port: 39859
        SOCKS4:
          * socat: socat TCP-LISTEN:LISTEN_PORT,fork socks4:127.0.0.1:DESTINATION_ADDR:DESTINATION_PORT,socksport=39859
          * netcat: nc -X 4 -x localhost:39859 address port
        SOCKS5:
          * netcat: nc -X 5 -x localhost:39859 address port

Using local port forwarding in SSH-MITM works similarly to OpenSSH's dynamic port forwarding. A SOCKS server is started via which the connections to the remote host are established.

This allows to use an already initiated SSH session to access e.g. an internal network or local services on the remote host.

The easiest way is to use ``socat``. ``socat`` opens a port locally and takes care that the connection via the SOCKS server is established accordingly.

This makes it possible to use any proram over a passed through port with SSH-MITM.


However, it is also possible to let a vulnerability scanner that can communicate via SOCKS scan a network behind it via the connection established by SSH-MITM.


Remote port forwading
---------------------

.. figure:: /images/ssh-mitm_server_port_inject.png
  :scale: 100

  ..

With remote port forwarding it is only possible to connect to the same destination that was defined in the client's remote port forwarding request.

The reason for this is that the client manages the connections and only the already defined connection is known to it. Unlike a server, the client does not allow new connections.

If SSH-MITM detects that a remote port forwarding request has been made, appropriate connection information is output. This information can then be used to establish the connection itself and to use this connection for further tests.

.. code-block::

   created server tunnel injector for host 127.0.0.1 on port 38763 to destination ('google.com', 80)

Any number of connections to the defined destination can be established. Thus, it is possible that the connection can be used by the intercepted client as well as by a vulnerability scanner during an audit.
