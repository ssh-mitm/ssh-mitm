.. _sshmitminstall:

======================================
:fas:`cloud-download-alt` Installation
======================================

Installing SSH-MITM is the first step to leveraging its capabilities for your technical projects.
This guide will provide you with the information and resources you need to get SSH-MITM up and
running on your system, whether it be **Linux** or **Windows**.

SSH-MITM offers flexible and convenient installation options, including pre-built packages for
Windows and package managers such as ``snap``, ``pip``, ``pipenv``, ``AppImage`` or ``Nixpkgs``.

These options provide a simple and efficient way for users to get SSH-MITM installed
and ready to use for various purposes such as malware analysis, forensics, security audits, and more.

Official distributions
======================

Official distributions of SSH-MITM represent the most recent and up-to-date versions of the software,
directly maintained and approved by the SSH-MITM developers. These are the releases that see regular updates,
ensuring users have access to the latest features, security patches, and improvements.

:fab:`ubuntu` snap
------------------

If you use ``snap``, you can install it with:

.. code-block:: none

    $ sudo snap install ssh-mitm


:fas:`cog` AppImage
-------------------

If you use the ``AppImage``, you can install it as:

.. code:: none

    $ wget https://github.com/ssh-mitm/ssh-mitm/releases/latest/download/ssh-mitm-x86_64.AppImage
    $ chmod +x ssh-mitm*.AppImage


:fab:`windows` Windows
-----------------------

If you use ``Windows``, you can download SSH-MITM and start it from the cmd.

:fas:`file-download` `Download Windows executable <https://github.com/ssh-mitm/ssh-mitm/releases/latest/download/ssh-mitm.exe>`_


:fab:`python` pip
------------------

If you use ``pip``, you can install it with:

.. code-block:: none

    $ python3 -m pip install ssh-mitm

If you are using a macOS version that comes with Python 2,
run ``pip3`` instead of ``pip``.

If installing using ``python3 -m pip install --user``, you must add the user-level ``bin`` directory
to your PATH environment variable in order to launch ``ssh-mitm``.
If you are using a Unix derivative (FreeBSD, GNU/Linux, macOS),
you can do this by running ``export PATH="$HOME/.local/bin:$PATH"``.


:fab:`python` pipenv
--------------------

If you use ``pipenv``, you can install it as:

.. code-block:: none

    $ pipenv install ssh-mitm
    $ pipenv shell

When using ``pipenv``, in order to launch ``ssh-mitm``,
you must activate the project's virtualenv.
For example, in the directory where ``pipenv``'s ``Pipfile``
and ``Pipfile.lock`` live (i.e., where you ran the above commands):

.. code:: none

    $ pipenv shell
    $ ssh-mitm server

Alternatively, you can run ``ssh-mitm server`` inside the virtualenv with

.. code:: none

    $ pipenv run ssh-mitm server


Community supported distributions
=================================

Community supported distributions of SSH-MITM, while immensely valuable, might not always be as current as the official ones.
These versions are maintained by the broader community and can sometimes lag behind in incorporating the latest updates.
They might offer unique configurations or adaptations tailored to specific needs, but there could be a trade-off in terms
of having the most recent enhancements.

:fas:`box` Nixpkgs
------------------

For Nix or NixOS is a `package <https://search.nixos.org/packages?channel=unstable&show=ssh-mitm&type=packages&query=ssh-mitm>`_
available. The lastest release is usually present in the ``unstable`` channel.

.. code-block:: none

    $ nix-env -iA nixos.ssh-mitm

Installation problems
=====================

If your computer is behind corporate proxy or firewall, you may encounter
HTTP and SSL errors due to the proxy or firewall blocking connections to widely-used servers.
For example, you might see this error if pip cannot connect to its own repositories:

.. code-block:: none
    :class: no-copybutton

    WARNING: Retrying (Retry(total=4, connect=None, read=None, redirect=None, status=None)) after connection broken by
    'NewConnectionError('<pip._vendor.urllib3.connection.HTTPSConnection object at 0x7ff04f4dbeb0>:
    Failed to establish a new connection: [Errno 101] netork not reachable')': /simple/ssh-mitm/

Here are some widely-used sites that host packages in the Python open-source ecosystems.
Your network administrator may be able to allow http and https connections to these domains:

* pypi.org
* pythonhosted.org
* github.com

Alternatively, you can specify a proxy user (usually a domain user with password),
that is allowed to communicate via network. This can be easily achieved
by setting two common environment variables: ``HTTP_PROXY`` and ``HTTPS_PROXY``.
These variables are automatically used by many open-source tools (like ``pip``) if set correctly.

.. code:: none

    # For Windows
    set HTTP_PROXY=http://USER:PWD@proxy.company.com:PORT
    set HTTPS_PROXY=https://USER:PWD@proxy.company.com:PORT

.. code:: none

    # For Linux / MacOS
    export HTTP_PROXY=http://USER:PWD@proxy.company.com:PORT
    export HTTPS_PROXY=https://USER:PWD@proxy.company.com:PORT

In case you can communicate via HTTP, but installation with ``pip`` fails
on connectivity problems to HTTPS servers, you can disable using SSL for ``pip``.

.. warning:: Disabling SSL in communication is generally not recommended and involves potential security risks.

The approach here is to mark repository servers as trusted hosts,
which means SSL communication will not be required for downloading Python libraries.

.. code:: none

    # Install ssh-mitm (without SSL)
    $ python3 -m pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org ssh-mitm

Using the tips from above, you can handle many network problems
related to installing Python libraries.