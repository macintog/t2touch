# First-run activation after identity creation

An affected first install can create and save its Linux-owned identity, then
stop with `AKS registration is not ready for user activation`. Systemd reports
that a dependency job for `fprintd.service` failed. The earlier kernel log says
the created-handle cleanup returned `-13` and requires reconciliation after
reboot. Do not discard the saved identity or restart creation.

The cause was a transport admission mismatch. Creation and replacement use a
nonzero generated 64-bit session. Their cleanup reused an unload validator
that additionally required session 1. The local rejection left the exported
handle owned and marked provisioning unsafe; the next activation process
correctly refused it. Cleanup now matches the exact kernel-owned session and
handle, with the existing phase, poisoning, and one-attempt controls intact.

Interrupted replacement recovery had the same mismatch at another boundary:
its exact journal-authorized identity-open request was rejected by the normal
saved-keybag loader's session-1 validation. Both kernel admission layers now
accept that request only in the armed recovery phase, for its bound session
and account UUID. Ordinary saved-keybag loading retains its original contract.
The request does not authorize creating or deleting an identity.

After this recovery, a separate first-enrollment startup gate could still stop
fprintd: automatic external-deletion reconciliation required an enrollment
authority before the first fingerprint could be enrolled. Reconciliation now
returns a no-op only when the account has no authority manifest, mutation
history, Catacomb state, or retained enrollment journals. Existing or dangling
authority manifests and retained state still go through reconciliation. The
external-deletion diagnostic stage is also registered so a child failure keeps
its bounded stage and exit status instead of being masked by `ValueError`.

## Recover an affected installation

Use the corrected source. The resident transport must not be unbound or force
unloaded. Run:

```bash
./install-omarchy.sh --prepare-transport-update
```

This preserves private identity state and prepares the transport update.
Restart when convenient, then run:

```bash
./install-omarchy.sh
```

First-run resumes the saved provisioning journal. Do not remove that journal,
the user mapping, activation bundles, or credentials to force a fresh attempt.
After installation succeeds, use the normal enrollment command when ready at
the sensor. The recovery restart activates the transport change and clears the
failed kernel owner; it is not an extra prerequisite for fingerprint testing.

## Adjacent installer portability

Boot image regeneration uses `limine-mkinitcpio` when available, avoiding
Omarchy's interactive `mkinitcpio` redirection question. Other mkinitcpio-based
systems retain `mkinitcpio -P`; failures propagate rather than being answered
or ignored. No boot selection or firmware registration policy is changed.

User service files use the desktop account's resolved primary numeric group,
which need not have the same name as the account. Hardware identity checks,
account-generation checks, and ambiguous-state rejection are unchanged.
