API Documentation
=================

Information on specific functions, classes, and methods.

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

      def handle_mosh(session: Session, traffic: bytes, isclient: bool) -> bytes:
         """
         Handle encrypted traffic from Mosh, a mobile shell that serves as a replacement for ssh.

         :param session: A Session object representing the Mosh connection.
         :type session: Session
         :param traffic: Encrypted traffic from Mosh.
         :type traffic: bytes
         :param isclient: A boolean value indicating whether the current session is a client session.
         :type isclient: bool
         :return: The processed traffic.
         :rtype: bytes
         """


.. toctree::
   :maxdepth: 1

   api/sshmitm