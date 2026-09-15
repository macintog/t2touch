# Product roadmap

t2touch is an experimental Omarchy integration validated on one MacBookPro16,1.
The [README](README.md#what-has-been-proven) describes the tested scope.

## Implemented

- Omarchy dependency installation, T2 interface detection, and Linux-owned authority setup.
- Packaged applesmc boot-state prerequisite for kernels that lack the publisher.
- Percentage-driven enrollment through `t2touch enroll` and standard fprintd clients.
- Any-enrolled-finger authentication through fprintd, sudo, PolicyKit, and the lock screen.
- Five stable neutral slots, lowest-vacancy allocation, and named deletion through an empty inventory.
- Privacy-safe `status`, `list`, and `count` commands backed by the caller-bound fprintd inventory.
- Confirmed, freshly authorized fingerprint purge with durable partial-progress resume.
- Password fallback, reversible PAM installation, and private-state preservation on uninstall.
- Same-session userspace reinstall when the resident transport matches.
- Readiness messages in compatible Omarchy lock and permission dialogs.
- Dynamic native DRM selection when a fallback framebuffer would otherwise be included.
- Reduced redundant inventory work: measured reader readiness improved from about 7.3 to 3.8 seconds on the reference laptop.

The applesmc prerequisite needs one restart when absent. A different resident
transport requires a planned kernel restart before installation can proceed.

## Support gaps

- Validation on additional Intel T2 Mac models and bridgeOS versions.
- Distribution packages that do not require a source checkout.
- A guided importer for machines retaining macOS Touch ID state.
- Persistence of Linux-only additions across a later macOS boot.
- Multiple Linux desktop users.
- Graphical settings integration and deep-sleep recovery.
- Kernel-upgrade coverage through DKMS CI and real hardware.
- Faster, more consistent permission-dialog response; the latest successful test still needed multiple touches.
- Qualification across display topologies and future Omarchy QML versions.
- Automatic rollback/removal of the optional desktop changes during uninstall.
- An untouched final-source clone/install/enroll replay and broader upgrade coverage.

Private-state purge and a single global biometric-policy toggle are not
exposed. Broader support or a release tag does not follow from
the single-machine demonstration alone.
