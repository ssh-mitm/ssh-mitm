.. _upstream-contributions:

:fas:`code-branch` Upstream Contributions
============================================

Not every result of this research is a vulnerability. Auditing OpenSSH's
authentication and sandboxing code also produced direct hardening
contributions to OpenSSH itself, credited to Manfred Kaiser and listed here
for completeness even though they carry no CVE.

.. list-table::
   :header-rows: 1

   * - Commit
     - Change
   * - `7ab700f170 <https://github.com/openssh/openssh-portable/commit/7ab700f1706b154d4bc5cf66e19c05be6d9b1fc1>`__
     - Made a failure to set ``SECCOMP`` or ``NO_NEW_PRIVS`` fatal instead of
       silently continuing with a weaker sandbox. Credited as
       *"Prompted by manfred.kaiser@ssh-mitm.at"*.

       A minor, unrelated finding from the same audit pass was also fixed in
       passing: commit `4f4aeee6ed <https://github.com/openssh/openssh-portable/commit/4f4aeee6edaa248f1e7ce22ee3f35ce183eabf38>`__,
       authored directly by Manfred Kaiser, removed a duplicate
       ``SC_ALLOW(__NR_clock_gettime64)`` entry from the seccomp filter — the
       syscall was already permitted under its own ``ifdef`` guard elsewhere,
       so this was a cleanup with no security impact.
