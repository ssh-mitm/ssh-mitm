:fas:`book` User guide
======================

The user guide explains the SSH protocol and describes how to use SSH-MITM during security audits.

Introduction
------------

The Secure Shell Protocol (SSH) is a cryptographic network protocol for operating network services securely over an unsecured network.
Its most notable applications are remote login and command-line execution.

SSH applications are based on a client–server architecture, connecting an SSH client instance with an SSH server.
SSH operates as a layered protocol suite comprising three principal hierarchical components:
the transport layer provides server authentication, confidentiality, and integrity;
the user authentication protocol validates the user to the server;
and the connection protocol multiplexes the encrypted tunnel into multiple logical communication channels.

SSH was designed on Unix-like operating systems, as a replacement for Telnet and for unsecured remote Unix shell protocols,
such as the Berkeley Remote Shell (rsh) and the related rlogin and rexec protocols, which all use insecure, plaintext transmission
of authentication tokens.

SSH was first designed in 1995 by Finnish computer scientist Tatu Ylönen. Subsequent development of the protocol suite
proceeded in several developer groups, producing several variants of implementation.
The protocol specification distinguishes two major versions, referred to as SSH-1 and SSH-2.
The most commonly implemented software stack is OpenSSH, released in 1999 as open-source software by the OpenBSD developers.
Implementations are distributed for all types of operating systems in common use, including embedded systems.


Contents
--------

.. toctree::
   :maxdepth: 1

   fingerprint
   authentication
   sshagent
   trivialauth
   advanced-usage
