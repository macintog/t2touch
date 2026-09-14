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
- [ ] Uninstall restores PAM, disables future transport startup, stops the
      userspace integration, and preserves private state for a later reinstall;
      a transport already pinned by SEP remains safely resident until the next
      ordinary power cycle.

## Release validation

- [x] Targeted product tests pass (130 focused deletion-path tests).
- [x] Full Python test suite passes (1,172 tests, one intentional skip).
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

## Publication

- [x] Review the final diff, privacy boundary, and licenses.
- [ ] Push t2touch and t2touch-mini to their public GitHub repositories.
- [ ] Tag `v0.1.0`.
- [ ] Mark both releases experimental and name the hardware model actually tested.
