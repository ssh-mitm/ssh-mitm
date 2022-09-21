.. _develop/setup:

==============================================
:fas:`wrench` Setting up a development install
==============================================

System requirements
===================

SSH-MITM is developed on Linux, but should also run on MaxOS or Windows.

While it should run on other operating systems most advanced features are only supported on Linux.

If you are using Windows, we recommend using `VirtualBox <https://virtualbox.org/>`_ or a similar system to run `Ubuntu Linux <https://ubuntu.com/>`_ for development.

Install Python
--------------

SSH-MITM is written in the `Python <https://python.org>`_ programming language, and
requires you have at least version 3.8 installed locally. If you haven’t
installed Python before, the recommended way to install it is to use
your systems package manager. Remember to get the ‘Python 3’ version,
and **not** the ‘Python 2’ version!

Install git
-----------

SSH-MITM uses `git <https://git-scm.com>`_ & `GitHub <https://github.com>`_
for development & collaboration. You need to `install git
<https://git-scm.com/book/en/v2/Getting-Started-Installing-Git>`_ to work on
SSH-MITM. We also recommend getting a free account on GitHub.com.


Setting up a development install
================================

When developing SSH-MITM, you need to make changes to the code & see
their effects quickly. You need to do a developer install to make that
happen.

.. note:: This guide does not attempt to dictate *how* development
   environments should be isolated since that is a personal preference and can
   be achieved in many ways, for example `tox`, `conda`, `docker`, etc.

1. Clone the `SSH-MITM git repository <https://github.com/ssh-mitm/ssh-mitm>`_
   to your computer.

   .. code:: none

      git clone https://github.com/ssh-mitm/ssh-mitm
      cd ssh-mitm

2. Make sure the ``python`` you installed
   is available to you on the command line.

   .. code:: none

      python -V

   This should return a version number greater than or equal to 3.8.


3. Install the development version of SSH-MITM. This lets you edit
   SSH-MITM code in a text editor & restart the SSH-MITM process to
   see your code changes immediately.

   .. code:: none

      python3 -m pip install --editable .

4. You are now ready to start SSH-MITM!

   .. code:: none

      ssh-mitm server

5. Access SSH-MITM from your local ssh client:

   .. code:: none

      ssh -P 10022 localhost

**Happy developing!**