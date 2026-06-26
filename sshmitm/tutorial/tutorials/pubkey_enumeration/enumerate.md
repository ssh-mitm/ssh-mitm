<div class="scenario-box" markdown="1">
mmorgan has three SSH keys registered on LogfileGit — one per device. Each key may grant access to different servers in the Logfile Inc. infrastructure. Your goal: find which key unlocks the **web server**.
</div>

The command below fetches mmorgan's keys directly from [{git_server_url}/mmorgan.keys]({git_server_url}/mmorgan.keys) and queries the web server's user validity oracle for each one — without completing a login:

    ssh-mitm check-publickey \
      --host 127.0.0.1 --port {web_port} \
      --username mmorgan \
      --public-keys {git_server_url}/mmorgan.keys

<div class="task-box" markdown="1">
Run the command. The output groups results into **Accepted** and **Not accepted** sections. Copy the `SHA256:...` fingerprint from the accepted key and enter it in the field above.

**Bonus:** Run the same command against port `{database_port}` to map database access.
</div>

<div class="note-box" markdown="1">
SSH servers must answer key validity queries before asking the client to sign anything — this is the **user validity oracle**. It allows probing any number of username/key pairs without authentication. OpenSSH limits probes per connection (`MaxAuthTries`, default 6); `check-publickey` opens a fresh connection per batch if needed.
</div>
