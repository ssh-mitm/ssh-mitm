<div class="objectives-box" markdown="1">

- Query the SSH **user validity oracle** (CVE-2016-20012) to test username/key combinations without completing a login
- Fetch public keys directly from a GitLab-style profile URL and test them with `check-publickey`
- Map which keys grant lateral access across an infrastructure

</div>

<div class="note-box" markdown="1">
SSH servers must answer "would this key be valid for this user?" before asking the client to prove it holds the private key. An attacker uses this to probe any number of username/key pairs without completing authentication. OpenSSH documents this as the **user validity oracle** (CVE-2016-20012).
</div>

<div class="scenario-box" markdown="1">
In an earlier chapter you intercepted an SSH exec command from mmorgan on web01:

    git clone git@logfilegit.logfileinc.internal:mmorgan/dev-server-config.git

Logfile Inc. runs **LogfileGit** — an internal Git platform that publishes SSH keys on every user profile, just like GitHub or GitLab. Those keys are the same ones developers use to authenticate to servers.

Browse the platform, collect mmorgan's keys, and find out which servers they can reach.
</div>
