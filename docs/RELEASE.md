# Experimental release checklist

## Product contract

- [ ] A fresh supported Omarchy installation completes `./install-omarchy.sh`
      without a reboot or manual service sequencing.
- [x] `t2touch enroll` shows the polished percentage-driven TUI and creates the
      lowest vacant slot among neutral `Finger 1` through `Finger 5`, without
      renumbering existing slots.
- [x] That fingerprint immediately authenticates through fprintd, sudo,
      graphical PolicyKit, and the Omarchy lock screen.
- [x] Any enrolled fingerprint works; supported named deletion, including the
      final named slot, completes in the running system.
- [x] Password fallback remains available.
- [x] Reinstall updates userspace in the running session when the resident
      transport matches; a changed transport is staged only across a planned
      kernel restart because SEP pins its PCI/DMA owner.
- [x] Uninstall restores PAM, disables future transport startup, stops the
      userspace integration, and preserves private state for a later reinstall;
      a transport already pinned by SEP remains safely resident until the next
      ordinary power cycle.

## Release validation

- [x] Targeted product tests pass (130 focused deletion-path tests).
- [x] Full Python test suite passes (1,173 tests, one intentional skip).
- [x] ShellCheck passes installed shell scripts.
- [x] Userspace tools and the DKMS module build without warnings.
- [x] Privacy checks find no private biometric identifiers, keybags, credentials,
      machine-local paths, or private media.
- [x] The installed doctor reports no unexpected failure on the reference Mac.
- [x] The README commands and support limits match the shipped behavior.

## Outstanding acceptance gate

The repository now supplies a package-managed DKMS replacement when the
ordinary `linux-t2` package lacks the required typed `applesmc` SEP boot-state
publisher. The remaining release gate is to repeat the exact public quick start
from a clean, fully updated supported Omarchy volume. This is an acceptance
gate, not a reason to weaken the live-driver check or add manual service
sequencing.

## Updated reference-machine acceptance — 2026-09-14

After updating to Omarchy `4.0.3-1`, the exact documented
`./install-omarchy.sh` entry point completed with exit status 0 on the
`MacBookPro16,1` reference system. It required no reboot, module unload, PCI
unbind, manual service sequencing, password entry, or fingerprint operation.
The installed daemon and product CLI matched the candidate source byte for
byte; the doctor passed every check; fprintd reported an enrollable empty
inventory; and the mutation registry reported no pending operation.

The included applesmc source applies to the current public
`linux-t2 7.2.4.arch1-2` package source and builds against the reference
`7.1.8.arch1-3` headers. An isolated DKMS add/build/install produced the
expected `updates/dkms/applesmc.ko` with all three typed boot-state parameters,
and an isolated DKMS removal removed that module while preserving source. The
reference system already boots a capable applesmc, so this run did not replace
its live driver or claim the still-pending clean-volume first activation.

## Uninstall and reinstall acceptance — 2026-09-14

With the reference system in a clean, empty-inventory state, `./uninstall.sh`
restored the original PAM files, removed the product commands, units, future
transport startup, on-disk transport module, and owned boot configuration. It
preserved the root-private configuration, encrypted credential, user keybag,
provisioning journal, and identity state for a later reinstall. As required by
the transport safety contract, the SEP-pinned live transport remained resident;
the uninstaller did not unload it or unbind PCI devices.

The exact documented `./install-omarchy.sh` entry point then completed with exit
status 0 in the same running session. It rebuilt and installed Omarchy's
`linux-t2` unified kernel image, and inspection of that image confirmed that
`t2-sep-boot-state.conf` and both transport configuration files are present.
All four product services returned active and enabled, DKMS reported the
transport installed for the running kernel, the doctor passed every check,
fprintd reported an enrollable empty inventory, and every mutation queue was
empty and unblocked. No reboot, password entry, manual service sequencing, or
fingerprint operation was used.

## Publication

- [x] Review the final diff, privacy boundary, and licenses.
- [ ] Push t2touch and t2touch-mini to their public GitHub repositories.
- [ ] Tag `v0.1.0`.
- [ ] Mark both releases experimental and name the hardware model actually tested.
