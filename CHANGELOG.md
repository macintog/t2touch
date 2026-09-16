# Changelog

This file records notable user-facing changes to t2touch. Release versions use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html), and the structure
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

## 0.0.6 - 2026-09-16

This release improves enrollment recovery, upgrades on running T2 systems,
and fingerprint authentication prompts.

### Changed

- Mark the live PAM placement prompt with `◎` when the reader is ready for
  a finger. The preparation message remains separate, and password prompts
  are unchanged.
- Request elevation through `sudo` when `t2-touchid-doctor` is run as a normal
  user, so it can produce a complete diagnostic report. Preserve `--json`
  output and the normal authentication flow.

### Fixed

- Build the bundled `applesmc-t2touch` prerequisite against the MacBookPro15,2
  test system's 6.19.11 T2 kernel headers by replacing unavailable
  `kzalloc_objs` calls with equivalent `kcalloc` allocations. Contributed by
  Brett Kulp in [PR #2](https://github.com/macintog/t2touch/pull/2).
- Permit a userspace upgrade when T2 reports `BootPolicyReboot` and the
  existing installation has a matching resident transport, an intact private
  configuration, and every prerequisite service active. Fresh setup and
  transport replacement still require a ready boot-policy result.
- Allow enrollment recovery to proceed past earlier attempts that stopped
  before starting or completed rollback. Journals that still need identity
  reconciliation continue to block new enrollment.
- Clarify boot-policy recovery guidance: preserve diagnostics when a normal
  reboot does not clear `BootPolicyReboot`, rather than repeatedly rebooting
  or treating an SMC reset as an established remedy.

## 0.0.5 - 2026-09-15

### Added

- Add privacy-safe `t2touch list`, `t2touch count`, and `t2touch status --json`
  output backed by the caller-bound fprintd inventory.
- Add `t2touch purge` with destructive confirmation, fresh PolicyKit
  authorization, an ordered outer mutation journal, exact resume validation,
  and redacted partial-completion reporting.

### Changed

- Render `t2touch status` from validated neutral handles instead of passing
  through localized `fprintd-list` text.
- Reduce Touch ID preparation latency with a generation-bound inventory cache
  and a rotating prewarmed native matcher. Measured median list-to-reader-armed
  time fell from 5.049 seconds to 2.214 seconds while each match still rebuilds
  its authorization and hardware state.
- Add privacy-safe preparation timing events and a reusable latency probe for
  distinguishing inventory, authorization, hardware, and match phases.

### Fixed

- Refresh fingerprint inventory after purge or other mutations through separate
  administrative helpers, including changes that do not advance account authority.
- Report an empty fingerprint inventory successfully in list, count, and status
  commands instead of treating fprintd's `NoEnrolledPrints` response as a failure.
- Explain the active local session requirement before SSH deletion attempts and
  distinguish authorization denial or cancellation from incomplete deletion.
- Confirm the empty final inventory after successful purge and clearly report
  an already empty inventory as having nothing to delete.
- Send expected typed D-Bus errors, including empty inventory, without logging
  them as failed asynchronous callbacks.

- Block and drain inventory, warmup, and matcher work across authenticated
  system sleep transitions so no new Touch ID hardware phase starts while the
  host is entering sleep.
- Validate and bound resident matcher replies while preserving exact terminal
  verdicts, cancellation, exclusive ownership, and crash recovery.

## 0.0.4 - 2026-09-15

### Fixed

- Recover the current SEP-owned BioLockout record when switching Linux volumes
  leaves the local saved record behind, allowing fingerprint enrollment to
  proceed after the stale record is rejected.
- Preserve compatible Linux account generations when enrollment and deletion
  pass to their workers, preventing unchanged Btrfs accounts from being rejected
  as `account-changed`.
- Reject malformed BioLockout load outputs, including empty values of the wrong
  type, before treating state restoration as successful.

### Changed

- Include bounded, privacy-safe authorization failure reasons in enrollment
  worker diagnostics.
- Update protocol research with shared findings on fingerprint lifecycle and
  identity authorization, including evidence limits and unresolved behavior.

## 0.0.3 - 2026-09-15

### Added

- Explicit AKS identity-create v4 support for MacBookPro16,2 with bridgeOS
  23P2048, contributed by [@tonibergholm](https://github.com/tonibergholm) in
  [PR #1](https://github.com/macintog/t2touch/pull/1). Version 5 remains the
  default; see the [setup and hardware coverage](docs/MACBOOKPRO16_2.md).
- Add `t2-native-authority-rebind` for moving a complete Linux-native
  authority between installations. It preserves the source mapping and
  enrollment lineage while binding it explicitly to the destination account.

### Fixed

- Preserve an existing native account migration binding when another publication
  attempt fails, and reject authorization sessions when a compatible account
  binding changes or is removed.
- Remove the native authority rebind command during uninstall.
- Preserve existing Linux account bindings across Btrfs kernel filesystem-ID
  changes by deriving the prior stable value from persistent filesystem and
  subvolume identity while accepting mappings written with the Linux 7.2
  device-derived value; account replacement checks remain enforced.
- Diagnose a T2 identity activated by another OS installation as a foreign live
  authority instead of reporting it as a generic external-deletion failure.
- Restore the committed master and user on the same pristine cold connection
  even when the master does not yet advertise the user. Reject partially
  restored master-only state as a fresh cold start.
- Publish committed BioLockout state after terminal-identity enrollment
  recovery, and make the desktop Python runtime accessible under a restrictive
  installer umask.
- Keep recovery-only installation paused across reboot and automatic service
  activation until normal installation explicitly resumes setup.
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
