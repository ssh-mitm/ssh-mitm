:fas:`fingerprint` SSH Fingerprints
===================================

With SSH, unlike HTTPS secured websites, there are no central certificate providers to ensure that you are connecting to the correct server.

In most cases, a new key is automatically generated during installation. When a client connects to this server for the first time, the offered key is still unknown and you are asked if you want to connect to the server.

.. warning::

    The fingerprint ensures that you do not connect to a wrong server. One of the most common reasons for unknown fingerprints is the reinstallation of a system where new keys are generated.

    However, it can also be a Man in the Middle attack, where the connection was redirected to another server.

    For this reason, the fingerprint must always be compared against a trusted source.




Checking the fingerprint
------------------------

The first time you connect to a server, you will be asked if you want to connect to the server.

.. code-block:: none

    $ ssh github.com
    The authenticity of host 'github.com (140.82.121.3)' can't be established.
    RSA key fingerprint is SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8.
    Are you sure you want to continue connecting (yes/no/[fingerprint])?

In this case, the SSH client wants to connect to Github.com and you are asked if you want to continue with the connection.

You should not simply confirm this query, but compare the fingerprint with a trusted source. Github has published the fingerprints at the following address: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints

If the SSH client offers the possibility to enter a fingerprint, this method is always preferable. You just have to copy the fingerprint from the website and paste it into the terminal.

The reason is that if you compare fingerprints manually, errors can occur and you confirm a similar fingerprint and connect to the wrong server.

.. warning::

    If the fingerprint is unknown, you should ask the server administrator for the correct fingerprint.

    You can also contact support if the server is a rented server. They should be able to give you information. However, don't let support trick you into simply accepting the connection and insist that the fingerprint be provided to you in writing via a trusted source.


Warning for changed fingerprints
--------------------------------

However, for all further contacts from now on, the ssh program uses asymmetric cryptography to ensure that the server also has the correct private key that matches the public one stored in the ~/.ssh/known_hosts file, and refuses to establish the connection if in doubt. Here is a sample output:

.. code-block:: none
    :class: no-copybutton

    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
    Someone could be eavesdropping on you right now (man-in-the-middle attack)!
    It is also possible that a host key has just been changed.
    The fingerprint for the ED25519 key sent by the remote host is
    SHA256:2iJAHZZHlYMrlrBGw3t7Ma62TuZ0p7p+av3O4W+cpHY.
    Please contact your system administrator.
    Add correct host key in /home/tux/.ssh/known_hosts to get rid of this message.
    Offending ECDSA key in /home/tux/.ssh/known_hosts:6
      remove with:
      ssh-keygen -f "/home/tux/.ssh/known_hosts" -R 172.217.22.227
    ED25519 host key for 172.217.22.227 has changed and you have requested strict checking.
    Host key verification failed.

There are several reasons for changed fingerprints. One of the most common is the reinstallation of a system. However, this can also be a sign that you are connecting to the wrong server.

If you get a warning, you should contact the server administrator or support and ask if the server has been reinstalled or the keys have been regenerated. If this is the case, get the latest fingerprints in writing again via a trusted source.

If the fingerprint has changed for a legitimate reason, you can remove the old fingerprint with the following command:

.. code-block:: none

    $ ssh-keygen -f <DATEI> -R <HOST>

So in the above example

.. code-block:: none

    $ ssh-keygen -f "/home/tux/.ssh/known_hosts" -R 172.217.22.227


Determine fingerprint of the server
-----------------------------------

 Determining the fingerprint after a new installation can be a particular challenge. This is especially true for automatically installed systems.

If it is a virtual machine, you often have the option to start a terminal session in the administration interface. Such administration interfaces are usually secured by HTTPS and thus the connection should be trustworthy.

The fingerprint of a server can be determined afterwards in a local terminal with the system program ssh-keygen.

MD5 and SHA256 are supported as formats for the fingerprints. Currently SHA256 is being used more and more, but MD5 fingerprints can still be found in some cases. For this reason, the fingerprints should be determined in both formats.

.. code-block:: none

    $ ssh-keygen -f /etc/ssh/ssh_host_ecdsa_key.pub -l -E md5
    $ ssh-keygen -f /etc/ssh/ssh_host_ecdsa_key.pub -l -E sha256

In most cases, multiple keys are generated for an SSH server. The following one-liner determines the SHA256 fingerprints for all keys.

.. code-block:: none

    $ find /etc/ssh/ -name 'ssh_*.pub' -exec ssh-keygen -f {} -l -E sha256 \;

Analogously, you can also calculate the MD5 fingerprints:

.. code-block:: none

    $ find /etc/ssh/ -name 'ssh_*.pub' -exec ssh-keygen -f {} -l -E md5 \;

SSHFP Records - The fingerprint in DNS
--------------------------------------

 SSHFP records are special entries in the DNS zone of a domain. Thus, a basic requirement is that a DNS name exists for the server to which you want to connect.

Another requirement is that the DNS zone is protected by DNSSEC. If the zone is not protected by DNSSEC, an SSHFP record does not provide any security gain.

Server configuration
""""""""""""""""""""

On a server the SSHFP records can be created with the following command:

.. code-block:: none

    $ ssh-keygen -r examplehost.example.org
    examplehost.example.org IN SSHFP 1 1 d004948e1d359f2a267f03a599c3efe5d8285ae1
    examplehost.example.org IN SSHFP 1 2 f94a95111db1158903bc23e61f75843d029f9d3edabfd74c200f201d4b80b330
    examplehost.example.org IN SSHFP 3 1 3b355dc1e3a508e4594e7f8aa30d315d820eb602
    examplehost.example.org IN SSHFP 3 2 cacc4090df702522c977ea5dac7bb5d64b9b0968ca63879cc821f8b2b4b099d7
    examplehost.example.org IN SSHFP 4 1 4a1923a588b2426b6353699dfe9a69102fd5a29d
    examplehost.example.org IN SSHFP 4 2 67be5c3169884615436ec3068cb08d150466e1fae39c18cd4952d2594ad1d512

These DNS records can then be stored in the DNS zone. The zone file must then be re-signed.

To check whether the new DNS records work, you can check this with the program dig.

.. code-block:: none

    $ dig SSHFP examplehost.example.org +short

Client configuration
""""""""""""""""""""

By default, the OpenSSH client does not check the fingerprint against an SSHFP record. For this reason, the following entry must be added to the .ssh/config configuration file:

.. code-block:: none

    VerifyHostKeyDNS yes

If you then connect to the new server, you no longer need to confirm the fingerprint.

Troubleshooting
"""""""""""""""

If the SSH client still asks for confirmation, it may be because DNSSEC is not being used or has been configured incorrectly.

.. code-block:: none
    :class: no-copybutton

    The authenticity of host 'examplehost.example.org (192.0.2.123)' can't be established.
    ECDSA key fingerprint is SHA256:MH85JK0yq+JNl1lPKUlxit+dGFqWMS/MmohcINp/e9Q.
    Matching host key fingerprint found in DNS.
    Are you sure you want to continue connecting (yes/no/[fingerprint])?

In this case, the fingerprint must still be checked against a trusted source.

However, the fingerprint stored in the DNS is no longer considered trustworthy in this case. The reason for this is that the integrity of the DNS zone is no longer guaranteed due to an incorrect DNSSEC configuration.


SSH-MITM - attacks on the fingerprint verification
--------------------------------------------------

There are SSH clients that have a flawed fingerprint check and are thus vulnerable to man in the middle attacks. An example of this is the SFTP implementation of Midnight Commander.
This vulnerability was discovered and fixed only after 9 years. See  :doc:`CVE-2021-36370 </vulnerabilities/CVE-2021-36370>`

However, most programs do not have fingerprint verification vulnerabilities. As long as the fingerprint is checked, it is not possible to connect to an unknown server.

In many cases, the vulnerability is not the program, but the user who does not properly check the fingerprint against a known value. There can be many reasons for this.

Many users do not know what the fingerprint means. There are tutorials on the Internet that do not describe what the fingerprint is, but only write that you simply have to confirm this query with "yes" to establish the connection.

It also often happens that the fingerprint is not known and cannot be checked against a trusted source. These could be new systems that generate a random key on first launch.

Systems such as a development server may have it reinstalled frequently. This causes the fingerprints to change which leads to users being used to accepting unknown fingerprints.

However, previous studies (Peter Gutmann, Do Users Verify SSH Keys? / Konrad Rieck (Fuzzy Fingerprints Attacking Vulnerabilities in the Human Brain, 2002) ) have shown that users verify a fingerprint in very few cases. In the study by Peter Gutmann, IT departments were asked how often the user asked the IT department for the new fingerprint after a new installation. The study showed that this was almost never the case.

In cases where the fingerprint is checked, it is very efficient to generate an SSH key with a similar hash value as the one of the target computer.  The longer and more complex a fingerprint becomes, the more likely it is that only parts of the fingerprint are compared. This results in a fingerprint that is actually wrong being considered correct. This technique is known as fuzzy fingerprinting.


Fuzzy Fingerprints
""""""""""""""""""

.. note::

    Fuzzy fingerprints are not implemented in SSH-MITM

In many cases, an attacker is not in possession of the private key for the server. An attack on the encryption algorithms can also only be implemented efficiently for very old and weak algorithms.

Konrad Rieck (Fuzzy Fingerprints Attacking Vulnerabilities in the Human Brain, 2002) describes in his work a method how a user can be tricked into accepting a wrong fingerprint during a manual check.

Many clients still use MD5 to represent the fingerprint. However, MD5 is no longer considered secure enough because hash collisions cannot be ruled out. For this reason, there is an increasing switch to SHA256.

The advantage of SHA256 is that it is much more resistant to collisions. However, it also makes the fingerprint longer and more difficult to read. The more complex and longer a fingerprint is, the more often only individual parts are checked.

In his work, Konrad Rieck describes that most users only compare the beginning and the end of a hash value. Users with more experience also checked parts in the middle. However, it was observed that very few compared the full hash value.

Based on these observations, it is possible to generate fingerprints that are very similar to a known fingerprint. When creating a fingerprint, care must be taken to incorporate the observed behavior of the users into the generation of the key.

Because many users only check the beginning and the end, it is more important that these have the same byte sequence as the original fingerprint. Parts in the middle are checked less often, which is why they do not necessarily have to be the same.


The following example shows a 2-byte fingerprint.

+---------------------------------+
| **Fingerprint Type**            |
+----------------------+----------+
| Target fingerprint   | **5BE4** |
+----------------------+----------+
| Fuzzy fingerprint    | **5EB4** |
+----------------------+----------+

To improve the fingerprint, similar characters can also be used. Certain characters can be perceived differently by a user or, depending on the character set, can also be confused.

The more extensive the character set with which the fingerprint can be represented, the easier it is to find an optically similar fingerprint.

With a SHA256 hash, however, this is no longer represented in hex format, but as Base64.

.. code-block:: none
    :class: no-copybutton

    SHA256:G+rKuLGk+8Z1oxUV3cox0baNsH0qGQWm/saWPr4qZMM

With Base64 encoding the characters A-Z, a-z, 0-9, + and / can be used. At the end of the string a = can be used.

This extended character set offers the advantage that there are substantially more similar characters.

With fuzzy fingerprints, it is relatively easy to trick a user connecting to a server for the first time into accepting a wrong fingerprint.

Sergey Dechand et al described in "An Empirical Study of Textual Key-Fingerprint Representations" that with a hexadecimal setting over 10% of the attacks failed to detect the wrong fingerprint. Other methods, such as Base32 had a slightly better error rate of 8.5%.

Base64, which is used for SHA256 fingerprints, was not evaluated in this work, which is why no statement can be made for this.




Recognizing clients with known fingerprints
"""""""""""""""""""""""""""""""""""""""""""

If the client is already in possession of a fingerprint, the received fingerprint is compared with it. If the fingerprints do not match, a warning is issued and the connection is terminated.

However, a Man in the Middle attack should remain undetected for as long as possible. For this reason, it is necessary to prevent the warnings generated by the client.

RFC-4253 defines how the key exchange works. A list of supported algorithms is sent to the server. The first entry defines the preferred algorithm.

This behavior can be used to find out whether a client has already stored a fingerprint for the current connection or not.

In a Man in the Middle attack, this knowledge can be used to not intercept clients that would issue a warning or to pass the connection through to the actual destination server.

An exemplary key exchange with and without a known fingerprint could look as follows:


+------------------------+------------------------+
| New Fingerprint        | Known Fingerprint      |
+========================+========================+
| ssh-ed25519            | ssh-rsa                |
+------------------------+------------------------+
| ecdsa-sha2-nistp256    | ssh-ed25519            |
+------------------------+------------------------+
| ecdsa-sha2-nistp384    | ecdsa-sha2-nistp256    |
+------------------------+------------------------+
| ecdsa-sha2-nistp521    | ecdsa-sha2-nistp384    |
+------------------------+------------------------+
| ssh-rsa                | ecdsa-sha2-nistp521    |
+------------------------+------------------------+
| ssh-dss                | ssh-dss                |
+------------------------+------------------------+

If the fingerprint is not known, the list is sent to the server with a predefined sequence.
However, if the client has already saved a fingerprint for the server, the last used algorithm used is put first.


Testing with SSH-MITM
"""""""""""""""""""""

SSH-MITM has the possibility to check on an incoming connection if a client has a known fingerprint or not.

For this SSH-MITM must be started without additional parameters.

.. code-block:: none

    $ ssh-mitm
    [INFO]  connected client version: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
    [INFO]  openssh: Client has a locally cached remote fingerprint!


Mitigation
""""""""""

Depending on which client is used, it must be configured differently:

* **Dropbear:** not vulnerable
* **OpenSSH:** :doc:`CVE-2020-14145 </vulnerabilities/CVE-2020-14145>`
* **PuTTY:** :doc:`CVE-2020-14002 </vulnerabilities/CVE-2020-14002>`
