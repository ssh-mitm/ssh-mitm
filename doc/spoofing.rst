Spoofing Concepts
=====================

When running a ssh-mitm server transparency has to be taken under serious considerations. Representing yourself
as a seamless counterpart to the real thing can be a very difficult task with many pitfalls. Just the slightest
indication of malicious activity can tip a user of and reveal a mitm operation for what it really is.

SSH-MITM Fingerprints
----------------------

SSH clients keep track of trusted servers by verifying a fingerprint with the user, storing
identity and public key material in the ``known_hosts`` file (or any other decentralized local database)
when connecting for the first time.


.. note::

    The ssh trust on first use concept is an artifact dating back to a more simpler time. Then it was
    considered a definite step up to its counterparts in terms of security. Now it is frowned upon by
    many people who value their security dearly. With the now readily available Public Key Infrastructure (PKI)
    of the internet there is really no excuse to not verify the identity of the server you are connecting
    to using certificates instead of the lousy fingerprint that no one checks anyway.

    These security considerations are shared by the official
    `Secure Shell RFC 4251 <https://tools.ietf.org/html/rfc4251>`_ sections 4.1. Host Keys and 9.3.8. Man-in-the-middle.
    Additionally protection can
    also be supplied by the network infrastructure in form of network segmentation, zero trust,
    VPNs and so on.


This way of handling trust can have multiple implications for an operating mitm server which is trying to audit
ssh connections:

- the mitm server wants the user to associate his public key with the identity of the actual remote host

OR if the remote host is already known

- it wants to pass through the connection to the remote host and not alert the user of the mitm operation


Under normal circumstances a ssh-mitm server cannot possibly know which of these scenarios is the case
before it is already to late. Luckily the friendly folks at MITRE ATT&CK® have found an information
leak in the OpenSSH Client software that we can use to our advantage.


CVE-2020-14145: OpenSSH Client Information leak
------------------------------------------------



