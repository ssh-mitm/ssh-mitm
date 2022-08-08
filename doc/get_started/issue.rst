Reporting an issue
==================

Thank you for providing feedback about SSH-MITM.

Diagnosing an Issue
-------------------

If you find a problem in SSH-MITM, please follow the steps below to diagnose and report the issue.
Following these steps helps you diagnose if the problem is likely from SSH-MITM or from a different project.

1. Try to reproduce the issue in a new environment with the latest official SSH-MITM installed and no extra packages.

   If you are using pip:

     1. create a new environment::

         python3 -m venv new_env

     2. Activate the environment::

         source new_env/bin/activate

     3. Install SSH-MITM::

         python3 -m pip install ssh-mitm

     3. Start SSH-MITM::

         ssh-mitm server

- I cannot reproduce this issue in a clean environment: The problem is probably not in SSH-MITM itself.
- I can reproduce this issue in a clean environment: This might be a problem in SSH-MITM. Go to 2.

2. Disable workarrounds in SSH-MITM and try to reproduce the issue.
   SSH-MITM uses paramiko as SSH library which is not compatible to all clients and servers.
   This helps to find out, if the issue is part of the workarround, which are needed for compatibility with less known clients and servers.

    ssh-mitm --disable-workarounds server

- I cannot reproduce this issue: One of the workarrounds has errors. Go to :ref:`create-issue`.
- I can reproduce this issue with disabled workarrounds: This might be a problem in SSH-MITM or paramiko. Go to :ref:`create-issue`.


You might also check your system for:

- Security software that might be preventing access to files or network interfaces
- Network equipment, routers, or proxies that might be preventing communication between the clients and the servers

.. _create-issue:

Creating an issue
-----------------

* Before creating an issue, search in the issue tracker for relevant issues.
* If you find an issue describing your problem, comment there with the following information instead of creating a new issue.
* If you find a relevant resolved issue (closed and locked for discussion), create a new issue and reference the resolved issue.

To create an issue, collect the following contextual information:

- relevant package and software versions, including:

  - used ``ssh-mitm`` version
  - ssh client version affected (please try to reproduce in OpenSSH client and PuTTY at least)
  - ssh server version affected (please try to reproduce it with the OpenSSH server at least)

- relevant log output and error messages ``ssh-mitm --debug --paramiko-log-level debug server``
- screenshots or short screencasts illustrating the issue

`Create a new issue <https://github.com/ssh-mitm/ssh-mitm/issues/new>`__. Include the contextual information from above. Describe how you followed the diagnosis steps above to conclude this was a SSH-MITM issue.
