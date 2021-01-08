Installation of SSH-MITM
========================

This part of the documentation covers the installation of SSH-MITM.
The first step to using any software package is getting it properly installed.

$ python -m pip install ssh-mitm
--------------------------------

To install SSH-MITM, simply run this simple command in your terminal of choice:

.. code-block:: bash
    :linenos:

    $ python -m pip install ssh-mitm


Get the Source Code
-------------------

SSH-MITM is actively developed on GitHub, where the code is always available.

You can either clone the public repository:

.. code-block:: bash
    :linenos:

    $ git clone git://github.com/ssh-mitm/ssh-mitm.git

Or, download the tarball:

.. code-block:: bash
    :linenos:

    $ curl -L https://github.com/ssh-mitm/ssh-mitm/archive/master.tar.gz | tar xz


Once you have a copy of the source, you can embed it in your own Python package, or install it into your site-packages easily:

.. code-block:: bash
    :linenos:

    $ cd ssh-mitm-master
    $ python -m pip install .
