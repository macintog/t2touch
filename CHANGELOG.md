# Changelog

This file records notable user-facing changes to t2touch. Release versions use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html), and the structure
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

### Fixed

- Require clean, valid, unambiguous terminal match evidence, and allow image
  quality retries before the final result. Revalidate the caller's claim after
  the touch wait before reporting authentication success.
- Subscribe to D-Bus caller departures before exposing the service, and retain
  enrollment and deletion ownership through repeated cancellation and cleanup.
- Reap verification and feedback helpers on failure or cancellation, continue
  draining diagnostics when optional feedback fails, and bound the retained
  diagnostic tail.
- Identify the ACM endpoint and request correctly in transport timeout logs.

## 0.0.2 - 2026-09-15

### Fixed

- Prevent a cold, unloaded bridgeOS Catacomb from being mistaken for an
  external fingerprint deletion. Startup now restores the committed
  Linux-owned state before comparing fingerprint inventories.
- Stop before loading a user Catacomb when the restored master does not
  advertise that user. A failed restore no longer falls through to destructive
  external-deletion reconciliation or prunes the local fingerprint inventory.

### Changed

- Report an allowlisted, privacy-safe `restore-user-not-advertised` reason when
  the restored master and saved user generation disagree.
- Document cross-volume boots with different t2touch revisions as a possible
  source of bridgeOS and saved-state generation drift.

This release preserves the divergent generation for diagnosis. It does not
make `fprintd` start when the restored master still lacks the selected user.

## 0.0.1 - 2026-09-15

Initial proof-of-concept release. The [README](README.md) describes its full
scope, setup, commands, safeguards, and known limitations. Validation covers
one `MacBookPro16,1`; keep password authentication available.

### Added

- Omarchy installation with a reversible PAM and service integration, plus a
  DKMS `applesmc` boot-state prerequisite for kernels that need it.
- Standard `fprintd` enrollment, verification, and named single-fingerprint
  deletion backed by Apple T2 Touch ID.
- Journaled, fail-closed enrollment and identity persistence with guarded
  post-reboot reconciliation.
- Reader-readiness feedback for supported Omarchy lock and PolicyKit dialogs,
  with password fallback kept available.
- Dynamic DRM selection that excludes a boot framebuffer only when a connected
  native display is available.
- Privacy-safe diagnostics, contributor guidance, and redacted research tools.
