# Omarchy lock PAM privilege mismatch

## Summary

An earlier `t2-touchid-linux` Omarchy password PAM template could not unlock T2
keybags from Omarchy's lock screen. This was an integration bug in this
repository, not evidence that Omarchy incorrectly drops privileges. The
current template no longer invokes the incompatible helper.

Omarchy 4.0.1 runs each lock-screen `PamContext` in a subprocess owned by the
desktop user. The earlier `pam/omarchy-lock-password` template invoked a
root-only helper from that context:

```text
auth optional pam_exec.so quiet expose_authtok seteuid /usr/local/sbin/t2-pam-unlock
```

`install.sh` installs `/usr/local/sbin/t2-pam-unlock` as `root:root` mode
`0700`. The helper must also read root-only configuration and runtime keybag
state and open root-only `/dev/t2-aks`. `pam_exec.so seteuid` does not grant
root privileges; in this context it executes with the unprivileged caller's
effective identity. Execution therefore fails with `EACCES`.

## Observed evidence

The lock-screen password remained usable, but the journal recorded:

```text
pam_exec(omarchy-lock-password:auth): execve(/usr/local/sbin/t2-pam-unlock,...) failed: Permission denied
pam_exec(omarchy-lock-password:auth): /usr/local/sbin/t2-pam-unlock failed: exit code 13
```

The lock then reported successful password authentication because the
`pam_exec` entry is `optional`. This preserves password fallback, but the T2
keybags are not unlocked by that password.

## Impact

- Password unlock of the Omarchy lock screen still works.
- On a fresh boot in manual keybag-unlock mode, entering the lock-screen
  password did not unlock the T2 keybags as the earlier README claimed.
- Fingerprint authentication remains unavailable until the keybags are
  unlocked through another privileged path.
- Sudo PAM can execute the same helper because sudo's PAM stack runs in a
  privileged process; this does not prove the unprivileged lock path works.

The separate `omarchy-lock-fingerprint` PAM service does reach fprintd. A
fingerprint capture failure observed during the same session is a distinct
BiometricKit/runtime issue and should not be attributed to this permission
failure.

## Reproduction

1. Use Omarchy's Quickshell lock implementation with
   `/etc/pam.d/omarchy-lock-password` containing the repository's optional
   `t2-pam-unlock` hook.
2. Confirm `/usr/local/sbin/t2-pam-unlock` is `root:root` mode `0700`.
3. Lock the session and authenticate with the correct password.
4. Inspect the user journal for `pam_exec(omarchy-lock-password:auth)`.
5. Observe `execve` failing with `Permission denied` while password
   authentication itself succeeds.

## Unsafe non-solutions

- Do not make the shell helper setuid; setuid bits on interpreted scripts are
  unsafe and generally ignored.
- Do not make the helper or T2 state world-readable or world-writable.
- Changing the helper to mode `0755` is insufficient because its configuration,
  keybag state, and `/dev/t2-aks` dependencies correctly remain root-only.
- Do not move the macOS password through argv, environment variables, logs, or
  persistent plaintext storage.

## Safe directions

The lock-screen password hook and its README claim have now been removed.
Manual keybag unlock and the encrypted system credential are compatibility
paths. The installed Linux-native service activates its own saved authority
without this lock-password hook.

A future lock-password integration needs a narrow privileged broker that:

- accepts requests only for the configured local desktop account;
- receives the PAM authentication token over a protected, non-argv channel;
- validates peer credentials and request lifetime;
- reads the root-only boot-specific handles itself;
- permits only the two required keybag unlock operations;
- clears secrets immediately and emits no secret-bearing diagnostics; and
- always leaves password authentication independent and usable.

The existing encrypted system credential service avoids this unprivileged PAM
boundary for compatibility authority. The native product uses its activation bundle;
see [architecture](ARCHITECTURE.md).
