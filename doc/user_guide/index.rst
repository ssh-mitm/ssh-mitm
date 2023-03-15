:fas:`book` User guide
======================

The user guide provides a comprehensive overview of the SSH protocol and its applications.
It covers the various aspects of SSH-MITM, a tool specifically designed for security audits,
and explains how it can be effectively used to analyze and manipulate SSH sessions.

The guide is aimed at individuals who are involved in security assessments, penetration testing, and vulnerability analysis.

Introduction
------------

The Secure Shell Protocol (SSH) is a widely used cryptographic network protocol for
secure data communication and remote execution of commands. Its most common use cases
are remote login and command-line execution over an unsecured network. SSH applications
consist of an SSH client instance and an SSH server, which work together to ensure secure
transmission of data between the two.

The history of SSH dates back to 1995 when it was first designed by Finnish computer scientist
Tatu Ylönen, as a replacement for Telnet and other unsecured remote Unix shell protocols.
Over the years, SSH has undergone several developments and versions, with the most commonly used
implementation being OpenSSH, released as open-source software by the OpenBSD developers in 1999.
Today, implementations of SSH are available for all types of operating systems, including embedded systems.

When it comes to security audits, you will encounter various protocols that need to be analyzed.
While there are tools available for intercepting and analyzing HTTP and HTTPS traffic,
options for intercepting and manipulating SSH sessions are limited.
This is where SSH-MITM stands out, offering the ability to manipulate SSH sessions.
Unlike other tools that merely function as honeypots, SSH-MITM enables real-time analysis and manipulation of the traffic.

This user guide provides an in-depth understanding of the SSH protocol and its various components.
It explains how SSH-MITM works, its features, and how it can be used during security audits and other
related purposes. In this guide, you will learn about topics such as SSH fingerprints, authentication,
the SSH agent, trivial authentication, transparent proxy mode, and advanced usage cases.


Contents
--------

.. toctree::
   :maxdepth: 1

   fingerprint
   authentication
   sshagent
   trivialauth
   transparent
   advanced-usage
