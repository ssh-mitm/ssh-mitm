.. _auth-testing:

:fas:`flask` Testing Authentication Methods
===========================================

This guide explains how to configure a local OpenSSH server and a test user so that
each SSH authentication method can be exercised against SSH-MITM in passthrough mode.
All examples assume the test user is named ``sshtest`` and SSH-MITM listens on port
``10022`` while the target sshd runs on port ``22``.

.. tip::

    For most development and CI testing, the built-in mock server is the simpler
    choice — no root access, no system configuration, no test user required::

        python -m sshmitm.mockserver

    It provides ready-made users for all four authentication methods.  Use the
    OpenSSH setup below when you need to test against a real ``sshd``, require
    SFTP or port-forwarding support, or want production-realistic behaviour.

.. admonition:: :fas:`scale-balanced` Legal Notice
   :class: legal-notice

   Only run these tests on systems you own or have explicit written permission to test.


Prerequisites
-------------

Create a dedicated test user that will be used across all scenarios:

.. code-block:: none

    $ sudo useradd -m -s /bin/bash sshtest

Start SSH-MITM in passthrough mode pointing at the local sshd:

.. code-block:: none

    $ ssh-mitm server --remote-host 127.0.0.1 --remote-port 22

All client commands below connect to SSH-MITM on port ``10022``.  To verify a
method against sshd directly, omit ``-p 10022``.


.. _auth-testing-none:

**none** authentication
-----------------------

The ``none`` method authenticates a user without any credential.  OpenSSH accepts
it when ``PermitEmptyPasswords yes`` is set and the account has no password hash in
``/etc/shadow``.  Because PAM is invoked in the background, it also needs the
``nullok`` option so that an empty password is not rejected at the PAM layer.

sshd configuration
""""""""""""""""""

Create a drop-in file (adjust the path for your distribution):

.. code-block:: none

    $ echo "PermitEmptyPasswords yes" | sudo tee /etc/ssh/sshd_config.d/none-auth-test.conf
    $ sudo systemctl reload sshd

PAM configuration
"""""""""""""""""

If ``/etc/pam.d/sshd`` does not exist, create it.  The critical part is ``nullok``
on the ``pam_unix`` line — without it PAM rejects empty passwords even when the
shadow entry is blank:

.. code-block:: none

    # /etc/pam.d/sshd
    auth        required    pam_unix.so nullok try_first_pass
    account     include     common-account
    password    include     common-password
    session     include     common-session

User setup
""""""""""

Remove the password hash so the account has no password:

.. code-block:: none

    $ sudo passwd -d sshtest

Verify the shadow entry — the second field must be empty:

.. code-block:: none

    $ sudo getent shadow sshtest
    sshtest::20599:0:99999:7:::

Testing
"""""""

Direct against sshd:

.. code-block:: none

    $ ssh -o PreferredAuthentications=none -o StrictHostKeyChecking=no \
          sshtest@127.0.0.1
    Authenticated to 127.0.0.1 ([127.0.0.1]:22) using "none".

Via SSH-MITM (passthrough mode, no extra flags required):

.. code-block:: none

    $ ssh -o PreferredAuthentications=none -o StrictHostKeyChecking=no \
          -p 10022 sshtest@127.0.0.1
    Authenticated to 127.0.0.1 ([127.0.0.1]:10022) using "none".

SSH-MITM log excerpt:

.. code-block:: none
    :class: no-copybutton

    INFO  Remote auth-methods: ['none']
    INFO  Remote authentication succeeded
          Remote Address: 127.0.0.1:22
          Username: sshtest
          Agent: no agent

.. note::

    ``--force-none-auth`` makes SSH-MITM accept ``none`` on the client side
    regardless of whether the remote server supports it — useful when the target
    sshd is not under your control.  For a proper end-to-end test where sshd
    performs the actual authentication, use the passthrough setup above.


.. _auth-testing-password:

**password** authentication
----------------------------

Password authentication is enabled by default in OpenSSH.  The client sends the
password in plain text inside the encrypted channel; SSH-MITM can read and log it.

sshd configuration
""""""""""""""""""

Ensure password authentication is active (it is on by default):

.. code-block:: none

    # /etc/ssh/sshd_config.d/password-auth-test.conf
    PasswordAuthentication yes

User setup
""""""""""

Set a password for the test user:

.. code-block:: none

    $ sudo passwd sshtest

Testing
"""""""

Direct against sshd:

.. code-block:: none

    $ ssh -o PreferredAuthentications=password sshtest@127.0.0.1

Via SSH-MITM:

.. code-block:: none

    $ ssh -o PreferredAuthentications=password -p 10022 sshtest@127.0.0.1

SSH-MITM log excerpt:

.. code-block:: none
    :class: no-copybutton

    INFO  Remote authentication succeeded
          Remote Address: 127.0.0.1:22
          Username: sshtest
          Password: secret
          Agent: no agent


.. _auth-testing-publickey:

**publickey** authentication
-----------------------------

Public key authentication relies on asymmetric cryptography.  The client signs a
challenge with its private key; the server verifies the signature against the stored
public key.  SSH-MITM intercepts the session by requesting the client's agent and
using it to authenticate against the remote server.

sshd configuration
""""""""""""""""""

Public key authentication is enabled by default:

.. code-block:: none

    # /etc/ssh/sshd_config.d/pubkey-auth-test.conf
    PubkeyAuthentication yes

User setup
""""""""""

Generate a key pair (no passphrase for automated testing) and install the public key:

.. code-block:: none

    $ ssh-keygen -t ed25519 -f ~/.ssh/id_test_ed25519 -N ""
    $ sudo -u sshtest mkdir -p /home/sshtest/.ssh
    $ cat ~/.ssh/id_test_ed25519.pub | sudo tee /home/sshtest/.ssh/authorized_keys
    $ sudo chmod 700 /home/sshtest/.ssh
    $ sudo chmod 600 /home/sshtest/.ssh/authorized_keys
    $ sudo chown -R sshtest:sshtest /home/sshtest/.ssh

Testing
"""""""

Direct against sshd:

.. code-block:: none

    $ ssh -i ~/.ssh/id_test_ed25519 -o StrictHostKeyChecking=no sshtest@127.0.0.1

Via SSH-MITM — use agent forwarding so SSH-MITM can authenticate against the remote:

.. code-block:: none

    $ ssh-add ~/.ssh/id_test_ed25519
    $ ssh -A -o StrictHostKeyChecking=no -p 10022 sshtest@127.0.0.1

SSH-MITM log excerpt:

.. code-block:: none
    :class: no-copybutton

    INFO  Remote authentication succeeded
          Remote Address: 127.0.0.1:22
          Username: sshtest
          Agent: available

Without agent forwarding SSH-MITM cannot complete the remote authentication.  In that
case configure a honeypot fallback (see :doc:`/audit_guide/authentication`).


.. _auth-testing-kbdint:

**keyboard-interactive** authentication
-----------------------------------------

Keyboard-interactive is a challenge–response protocol (RFC 4256).  The server sends
one or more prompts; the client answers each one.  In the simplest case a single
password prompt is used, making it functionally similar to password authentication
from the user's perspective.

sshd configuration
""""""""""""""""""

.. code-block:: none

    # /etc/ssh/sshd_config.d/kbdint-auth-test.conf
    KbdInteractiveAuthentication yes

PAM configuration
"""""""""""""""""

Keyboard-interactive is driven by PAM.  The default ``common-auth`` stack works for
a single password prompt.  The ``nullok`` option is only needed if the test account
has no password.

User setup
""""""""""

Set a password (keyboard-interactive does not work with empty passwords in the
typical PAM stack):

.. code-block:: none

    $ sudo passwd sshtest

Testing
"""""""

Direct against sshd:

.. code-block:: none

    $ ssh -o PreferredAuthentications=keyboard-interactive sshtest@127.0.0.1

Via SSH-MITM:

.. code-block:: none

    $ ssh-mitm server --remote-host 127.0.0.1 --remote-port 22
    $ ssh -o PreferredAuthentications=keyboard-interactive \
          -p 10022 sshtest@127.0.0.1

.. note::

    SSH-MITM forwards keyboard-interactive challenges transparently, including
    multi-step challenge–response (e.g. TOTP) and multi-round iterative exchanges
    as defined in RFC 4256.  The built-in mock server (``python -m sshmitm.mockserver``)
    provides ready-made users for both single-round and iterative keyboard-interactive
    authentication for testing.


.. _auth-testing-gssapi:

**gssapi-with-mic** authentication
-------------------------------------

GSSAPI authentication (RFC 4462, typically Kerberos-backed) is not proxied
by SSH-MITM for interception — it only matters here as the target of the
standalone audit tool documented at :doc:`/vulnerabilities/CVE-2026-60000`
(``ssh-mitm audit gssapi-usercheck`` / ``gssapi-usercheck-verify-patch``).
The setup below configures a local ``sshd`` to test against directly; there
is no passthrough-mode step.

Two configurations are possible depending on whether a full Kerberos
infrastructure is available. Both produce identical results for the audit
commands — the underlying oracle triggers before any keytab is consulted.

Simple setup (no Kerberos infrastructure)
""""""""""""""""""""""""""""""""""""""""""

Sufficient to reproduce the username-validity signal itself:

.. code-block:: none

    # /etc/ssh/sshd_config.d/gssapi-test.conf
    GSSAPIAuthentication yes
    GSSAPIStrictAcceptorCheck no

.. code-block:: none

    $ sudo systemctl restart sshd

Install ``libkrb5`` so the Kerberos OID is offered as a mechanism (no KDC or
keytab needed):

.. code-block:: none

    # Debian / Ubuntu
    $ sudo apt install libkrb5-3
    # RHEL / Fedora
    $ sudo dnf install krb5-libs
    # openSUSE
    $ sudo zypper install krb5

Full Kerberos setup
""""""""""""""""""""

Reflects a production Kerberos environment (``GSSAPIStrictAcceptorCheck
yes`` with a working keytab):

.. code-block:: none

    $ MYHOSTNAME=$(hostname)

    $ sudo tee /etc/krb5.conf <<EOF
    [libdefaults]
        default_realm = TEST.LOCAL
        dns_lookup_realm = false
        dns_lookup_kdc = false

    [realms]
        TEST.LOCAL = {
            kdc = localhost
            admin_server = localhost
        }

    [domain_realm]
        localhost = TEST.LOCAL
        .localhost = TEST.LOCAL
        ${MYHOSTNAME} = TEST.LOCAL
        .${MYHOSTNAME} = TEST.LOCAL
    EOF

    $ sudo kdb5_util create -s -r TEST.LOCAL -P changeme
    $ sudo kadmin.local -q "addprinc -randkey host/localhost@TEST.LOCAL"
    $ sudo kadmin.local -q "addprinc -randkey host/${MYHOSTNAME}@TEST.LOCAL"
    $ sudo kadmin.local -q "ktadd -k /etc/krb5.keytab host/localhost@TEST.LOCAL"
    $ sudo kadmin.local -q "ktadd -k /etc/krb5.keytab host/${MYHOSTNAME}@TEST.LOCAL"
    $ sudo chmod 640 /etc/krb5.keytab
    $ sudo systemctl enable --now krb5kdc

.. code-block:: none

    # /etc/ssh/sshd_config.d/gssapi-test.conf
    GSSAPIAuthentication yes
    GSSAPIStrictAcceptorCheck yes

.. code-block:: none

    $ sudo systemctl restart sshd

.. note::

    ``sshd`` uses ``gethostname()`` to look up its own service principal in
    the keytab — a mismatch between the configured realm and the actual
    hostname causes ``gss_acquire_cred()`` to fail for every user, making
    the audit commands report every username as ``NOT FOUND`` regardless of
    validity.

Testing
"""""""

.. code-block:: none

    $ ssh-mitm audit gssapi-usercheck --host 127.0.0.1 --username sshtest nonexistent

    $ ssh-mitm audit gssapi-usercheck-verify-patch --host 127.0.0.1

See :doc:`/vulnerabilities/CVE-2026-60000` for what the results mean.

GSSAPI cleanup
""""""""""""""

.. code-block:: none

    $ sudo systemctl stop krb5kdc
    $ sudo systemctl disable krb5kdc
    $ sudo rm -f /etc/krb5.keytab /etc/krb5.conf
    $ sudo rm -f /etc/ssh/sshd_config.d/gssapi-test.conf
    $ sudo systemctl restart sshd


Cleanup
-------

Restore the system to its original state after testing:

.. code-block:: none

    $ sudo rm -f /etc/ssh/sshd_config.d/none-auth-test.conf
    $ sudo rm -f /etc/ssh/sshd_config.d/password-auth-test.conf
    $ sudo rm -f /etc/ssh/sshd_config.d/pubkey-auth-test.conf
    $ sudo rm -f /etc/ssh/sshd_config.d/kbdint-auth-test.conf
    $ sudo rm -f /etc/pam.d/sshd
    $ sudo systemctl reload sshd
    $ sudo userdel -r sshtest
