:fas:`rocket` Get started
==========================

.. image:: _static/ssh-mitm-password.png
    :class: dark-light

The SSH-MITM Quick Start Guide provides a comprehensive overview of the functionality of SSH-MITM,
a man-in-the-middle tool designed for security audits and malware analysis.
In this guide, you will learn how to use SSH-MITM to hijack terminal sessions,
intercept file transfers, and forward ports through intercepted sessions.

SSH-MITM supports both password and public key authentication and automatically detects
the authentication method used by the target server. If public key authentication is not possible,
the tool falls back to password authentication. SSH-MITM also includes a range of features such as public
key authentication support, terminal session hijacking and logging, SCP/SFTP file transfer interception,
port forwarding with SOCKS 4/5 support, MOSH connection interception, client vulnerability audit,
and plugin support for customization.


.. toctree::
   :maxdepth: 1

   installation
   configuration
   terminal_session
   file_transfer
   portforwarding
   faq
