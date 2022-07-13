SSH-MITM - ssh audits made simple
=================================

.. image:: https://pepy.tech/badge/ssh-mitm
   :target: https://pepy.tech/project/ssh-mitm
.. image:: https://www.codefactor.io/repository/github/ssh-mitm/ssh-mitm/badge
   :target: https://www.codefactor.io/repository/github/ssh-mitm/ssh-mitm
.. image:: https://img.shields.io/github/license/ssh-mitm/ssh-mitm?color=%23434ee6
   :target: https://github.com/ssh-mitm/ssh-mitm/blob/master/LICENSE

ssh man-in-the-middle (ssh-mitm) server for security audits supporting **publickey authentication**, **session hijacking** and **file manipulation**



How Does It Work?
-----------------

**You're only a few simple steps away**


.. grid:: 3

   .. grid-item-card::  :fas:`download;sd-text-primary` Install SSH-MITM

      .. raw:: html

            <p>
                  To install SSH-MITM, simply run this command in your terminal of choice:<br/>
                  <code>
                     $ sudo snap install ssh-mitm
                  </code>
            </p>
            <p><a href="https://snapcraft.io/ssh-mitm">
                  <img alt="Get it from the Snap Store" src="https://snapcraft.io/static/images/badges/en/snap-store-black.svg" />
            </a></p>


   .. grid-item-card:: :fas:`network-wired;sd-text-warning` Connect to the network

      .. raw:: html

         <p>
               To start an intercepting mitm-ssh server on Port 10022,
               all you have to do is run a single command.<br/>
               <code>$ ssh-mitm server --remote-host 192.168.0.x:PORT</code>
         </p>
         <p>
               Now let's try to connect to the ssh-mitm server.<br/>
               <code>$ ssh -p 10022 user@proxyserver</code>
         </p>

   .. grid-item-card:: :fas:`check;sd-text-success` Hijack SSH sessions

        .. raw:: html

            <p>
                  When a client connects, the ssh-mitm starts a new server, which is used for session hijacking.<br/>
                  <code>[INFO]  created injector shell on port 34463</code>
            </p><p>
                  To hijack this session, you can use your favorite ssh client.
                  All you have to do is to connect to the hijacked session.<br/>
                  <code>$ ssh -p 34463 127.0.0.1</code>
            </p>


Frequently Asked Questions
--------------------------

.. dropdown:: Why have you created SSH-MITM?

   During an audit, you will find various protocols.
   For example there are many tools, which allows to intercept HTTP and even HTTPS traffic.
   There are some tools, which allows to intercept ssh sessions, but none of them allows to manipulate the data.
   This is the reason, why SSH-MITM was created.

.. dropdown:: Does this tool break the encryption of SSH and does this mean that SSH is insecure?

    **SSH is secure!**

    SSH-MITM does not break the encryption. SSH is secure, as long, as you verify the fingerprint.
    SSH-MITM is only able to intercept a session if the fingerprint was accepted.
    If a user does not accept the fingerprint, SSH-MITM is not able to read or modify any data,
    except the plain text parts of the protocol.


.. dropdown:: Requesting extra features

   * Open an issue ticket or vote for an existing one. This probably won't have very much effect; if a huge number of people vote for something then it may make a difference, but one or two extra votes for a particular feature are unlikely to change our priority list immediately. Offering a new and compelling justification might help.
   * Offer us money if we do the work sooner rather than later. This sometimes works, but not always. The SSH-MITM team all have full-time jobs and we're doing all of this work in our free time; we may sometimes be willing to give up some more of our free time in exchange for some money, but if you try to bribe us for a big feature it's entirely possible that we simply won't have the time to spare - whether you pay us or not. (Also, we don't accept bribes to add bad features, because our desire to provide high-quality software to the users comes first.)
   * Offer to help us write the code. This is probably the only way to get a feature implemented quickly, if it's a big one that we don't have time to do ourselves.

.. toctree::
   :maxdepth: 1
   :hidden:

   user_guide
   ssh_vulnerabilities
