API Documentation
=================

Information on specific functions, classes, and methods.

How to create docstrings with ChatGPT
-------------------------------------

This API documentation was created with the assistance of OpenAI's ChatGPT for research purposes.
The use of ChatGPT allowed for quick and efficient generation of docstrings for the classes and methods within the API.

For example, when asked to create a docstring for a method, the conversation might have gone something like this:

**User**

.. code-block:: none

   Please create docstrings for the given functions.

   Following format must be used:

   Example method signature: def myfunc(a: int, b: int) -> int

   Example docstring format:

   def myfunc(a: int, b: int) -> int:
      """
      description for this function

      :param a: fist parameter
      :type a: int
      :param b: second parameter
      :type b: int
      :return: sum of a+b
      :rtype: int
      """

   Provided functions:

   def probe_host(hostname_or_ip: str, port: int, username: str, public_key: paramiko.pkey.PublicBlob) -> bool:


**ChatGPT**

   Here's the updated docstring for the function probe_host:

   .. code-block:: python

      def probe_host(hostname_or_ip: str, port: int, username: str, public_key: paramiko.pkey.PublicBlob) -> bool:
         """
         Probe a remote host to determine if the provided public key is authorized for the provided username.

         :param hostname_or_ip: Hostname or IP address of the remote host to probe.
         :type hostname: str
         :param port: Port of the remote host.
         :type port: int
         :param username: The username to probe authorization for.
         :type username: str
         :param public_key: The public key to use for the probe.
         :type public_key: paramiko.pkey.PublicBlob

         :returns: True if the provided public key is authorized, False otherwise.
         :rtype: bool
         """


.. toctree::
   :maxdepth: 1

   api/sshmitm