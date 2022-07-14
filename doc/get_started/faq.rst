Frequently Asked Questions (FAQ)
================================

Below are some frequently asked questions.
Click on a question to be directed to relevant information in our documentation or our GitHub repo.

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
