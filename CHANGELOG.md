# Changelog

This file records notable user-facing changes to t2touch. Release versions use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html), and the structure
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

## 0.0.9 - 2026-09-17

This release makes Touch ID ready sooner, fixes false failures when the same
finger is touched twice, and adds safeguards against losing fingerprints
during recovery.

### Fingerprint recovery

Recovery could not restore the reference machine's existing fingerprints after
a cold reset, even though the saved files remained intact. We do not yet know
whether those fingerprints can be recovered. Resetting and enrolling again
worked, and the new enrollment survived a T2 and host reboot. The recovery
code involved is also present in `0.0.8`. See the
[recovery findings](docs/RECOVERY_RELEASE_GATE.md).

### Recovery safeguards

- Stop automatic startup from saving hardware state when its fingerprint list
  differs from this installation's saved list. Two cloned installations with
  the same account credentials were found to hold different saved archives.
- Stop when firmware rejects a saved master archive. An empty master reported
  in state 3 no longer overrides that rejection.
- Require explicit consent to fingerprint loss before recovery recreates or
  removes T2 components, including when resuming an interrupted operation.
- Distinguish malformed replies from explicit firmware rejections. A historical
  user-load failure without a recorded firmware status cannot authorize a reset
  to an empty fingerprint inventory.
- Keep installation paused while recovery is incomplete, and recognize journals
  created by the direct canonical-recovery command.

### Changed

- Stop installing the machine-wide s2idle override. Install and uninstall
  archive only the exact, unchanged T2Touch-owned sleep-policy file; modified
  files and conflicting backups are preserved with a warning. Interrupted
  retirement can resume safely. Subsequent sleep requests follow remaining
  systemd and kernel policy, which may select deep sleep. This is not a suspend
  repair: neither mode is qualified on the reference machine. Review the
  [migration guidance](docs/SLEEP_POLICY.md) before upgrading.
- Report effective sleep configuration and kernel mode in doctor diagnostics,
  with an explicit warning that resume remains unqualified.
- Reduce the wait for Touch ID to become ready from a historical **5.06 seconds
  to 0.31 seconds** on the reference MacBookPro16,1: about **4.74 seconds less
  waiting (94%)**. Both measure direct verification through reader readiness,
  but were recorded in different sessions and kernel versions. The latest
  controlled comparison measured 1.69 → 0.31 seconds (81% less time).
  Reusable identity preparation moves work out of each request while keeping
  caller authorization and biometric matching fresh. These are readiness
  measurements, not touch-to-result or full-login timings. See the
  [measurement record](docs/evaluations/touchid-prepared-identity-2026-09-17.md)
  for the historical baseline, validation, and limits.

### Fixed

- Accept consistent repeated results for the same attested finger instead of
  turning a successful double touch into a failure. Retain callbacks received
  during export and cleanup, acknowledge each once, and durably publish every
  accepted result. Conflicting, unbound, or unpersisted results still fail.
- Release idle prepared AKS/ACM ownership for authorized peer operations,
  including the C helper used by password-fallback callers, so retained
  preparation does not leave them reporting a busy device. Active requests
  retain exclusive ownership; matching and caller authorization remain fresh.
- Receive complete bridgeOS diagnostic archives whether the RemoteXPC stream
  announcement was already consumed or remains in the stream. Validate gzip
  integrity and retain data in a final HTTP/2 frame before publishing a capture.
- Disable TCP write batching before BridgeXPC HELO, retain fragmented RSD
  discovery headers, and reject malformed service ports without letting a
  failed optional hint save invalidate live discovery.
- Fail closed on partial-frame timeouts while preserving retryable idle waits.
  Validate callback and reply envelope versions and routing consistently.
- Serialize BioLockout generation publication and reduce each commit to one
  retained-history scan, preserving append-only generations, collision checks,
  all four durability flushes, and previous-generation recovery.

### Limitations

- Preparation still takes time at service startup. The readiness figures
  measure requests after startup, not cold service-start latency.
- The fixed 500 ms post-cancel quiet period remains. Reader-readiness gains
  are not measurements of physical-touch-to-result or full-login latency.
- After the reboot, the newly enrolled finger matched and an unenrolled finger
  was rejected. Repeated cold cycles, interrupted writes, and use across cloned
  installations remain untested with that enrollment.
- One transient post-reboot reconciliation failure remains unexplained despite
  subsequent successful startup and physical controls. Keep password fallback
  and a recovery terminal available; no additional hardware is qualified.

## 0.0.8 - 2026-09-17

This release adds archive-preservation guards and resumable journaled recovery.
Subsequent reference-machine evidence shows that retained archive files do not
guarantee usable fingerprints after recovery. See the
[recovery findings](docs/RECOVERY_RELEASE_GATE.md).

### Fixed

- Normalize the saved master Catacomb enrollment count to the exact stable live
  identity count during external-inventory reconciliation. Previously a stale
  local count could be paired with a freshly exported master secret and a
  reconciled user archive: authentication continued in the warm bridgeOS
  session, but the mismatched pair could reject the user archive after reboot.
- Preserve an incompatible enrolled archive by default during retained-master
  recovery. Empty-generation reprovision now requires a separate explicit
  fingerprint-loss-and-reenrollment acknowledgement; installs and upgrades
  never provide it automatically. When no fingerprints remain, skip fingerprint
  PAM immediately instead of delaying the password prompt.
- Admit completed, typed external-inventory and native-state recovery journals
  as mapping-bound mutation authority. Their retained audit evidence no longer
  prevents a later authorized fingerprint enrollment.
- Reconcile the bridgeOS 23P6068 canonical-master load when it returns a
  nonzero reply but independently changes the exact cold master from state 1
  to state 3. Never replay that load; continue to the saved user only after the
  journal and a stable zero-identity, zero-group master-only readback prove the
  observed transition. All other nonzero replies remain terminal.
- Correct retained-master recovery after hardware showed that bridgeOS rejects
  a direct saved-user load from the clean state-3 master-only surface. Normal
  startup now fails closed with a specific reason. An explicit acknowledged
  command runs the observed pre-client component-admission sequence under the
  installer recovery hold, journals every non-retryable boundary, verifies the
  exact saved identities, persists dirty Catacombs, restores BioLockout, and
  requires clean final readback.
- Keep the matching SEP-pinned transport resident when preparing recovery for
  a validated completed installation. Do not request first-run provisioning or
  replacement gates that would force an impossible live module unload.
- Recover the exact empty loaded-user state that bridgeOS can produce after
  accepting retained-master component preparation. The same typed journal now
  removes only that proven-empty user once, persists and confirms the dirty
  master, and recreates the missing components. If bridgeOS again exposes an
  empty loaded user, derive the recorded retained-master candidate offline and
  require a different Linux boot with a truly cold state-1 surface. Restore the
  canonical enrolled master and its matching saved user there; hardware proved
  that an exported empty-generation master cannot accept the enrolled user.
  Upgrade an already-rejected derived-master journal through a second cold
  boundary without replaying the rejected command. Accepted commands remain
  non-replayable across failures.
- Resume a journaled management operation with a new activation-journal file
  after its prior activation reached verified ready state. Keep the original
  activation evidence and the policy-bound operation ID instead of failing on
  the existing filename; unresolved activation histories still block.

### Limitations

- This remains experimental authentication software. Keep password fallback and
  a recovery terminal available; these changes do not qualify additional models.

## 0.0.7 - 2026-09-16

This release focuses on reliable fingerprint authentication, recoverable
upgrades, and tighter handling of privileged operations.

### Fixed

- Restore fingerprint authentication for authorized desktop clients, including
  lock-screen and PolicyKit prompts, after service hardening restricted caller
  inspection. Validate the login1 sleep-inhibitor descriptor before matching.
- Keep sleep/resume races from cancelling a newly warmed matcher. Move slow
  account and journal checks off the D-Bus event loop, revalidate claims after
  those checks, and return a D-Bus error when a method is cancelled.
- Reconcile fingerprints added or replaced by another operating system within
  the already-authorized account. Preserve surviving neutral handles and live
  templates; retain backups and block interrupted or racing state saves.
- Repair completed Linux-native installations whose older userspace leaves the
  service chain unhealthy. Recovery still requires an intact installed product,
  matching transport identities, and validated private provisioning authority.
- Preserve verified transport-update authority across preparation and reboot,
  including recovery from earlier updates that removed their own readiness
  evidence. Make interrupted preparation and PAM rollback safely retryable.
  Fresh, partial, or unidentified installations remain blocked.
- Check T2 hardware before staging applesmc or changing boot configuration.
  Build DKMS modules before enabling dependent services, and preserve an
  existing installation when a replacement build fails.
- Refuse unfamiliar PAM stacks on first installation unless explicitly forced;
  recognize current stock Arch sudo and Omarchy lock-password variants.
  Preflight Omarchy UI restoration and roll back partial writes.
- Repair torn journal tails consistently across typed readers. Persist mutation
  intent before dispatch and prune only old, fully resolved activation journals;
  retain incomplete, blocked, and malformed recovery records.
- Reject unvalidated biometric endpoint discovery instead of saving a bad port.
  Fail closed on ambiguous transport replies and device removal, and preserve
  DMA buffers when firmware may still own them.
- Reject overlong AKS secrets instead of silently truncating them; protect and
  clear secret buffers, tighten helper file handling, and keep account-binding
  secrets out of PolicyKit command-line details.
- Explain a full fingerprint inventory and required first-install logout.
  Accept `N`, `finger-N`, and `Finger N` deletion arguments; return exit status
  `2` when purge confirmation is declined. Improve narrow-terminal, `NO_COLOR`,
  and Ctrl-C handling, and add doctor `--no-sudo` for unelevated diagnostics.

### Changed

- Restrict daemon and prerequisite service privileges while retaining the
  capabilities needed for caller authorization, AKS access, and module loading.
  Bound reader claims and direct verification results to their requesting client.
- Install research launchers under `/opt/t2-touchid/bin` instead of placing them
  on PATH. Remove their legacy PATH copies during upgrade and clean up remaining
  product helpers and generated configuration during uninstall.
- Require Linux 6.12 or newer headers for the DKMS transport. Installer exit
  status `3` identifies a required reboot, with the next step printed on stdout.
- Pin runtime and Python build-backend dependencies with SHA-256 locks, including
  interpreter-specific dependencies for Linux Python 3.12 and 3.14. Install
  pymobiledevice3 from the bundled wheel. See
  [dependency provenance](docs/PROVENANCE.md).

### Limitations

- This remains experimental authentication software. Keep password fallback and
  a recovery terminal available; these changes do not qualify additional models.
- An enrolled fingerprint can authorize enrollment and deletion through the
  configured PolicyKit PAM stack. That existing trade-off is unchanged; see
  [the security model](SECURITY.md).

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
  unprepared transport replacement still require a ready boot-policy result.
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
