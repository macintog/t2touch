# Upstream status reconciliation

This document reconciles the status table in `macintog/t2touch` at upstream
commit `ea46d8a0aef3e73b0e2f747aa18721dbcd265bce` with the Linux-native E4 work
integrated on this branch on 2026-09-13.

## Current validation scope

The acceptance target is greenfield Linux-native bring-up through the installed
upstream workflow, with no imported macOS state or archived research identity
as an input. The completed scope and engineering evidence are summarized in
the [integration follow-up](research/integration-followup.md).

The table below separates prior compatibility results, native research
hardware proof, source integration, and installed greenfield evidence. The
blank-state first-run lifecycle, first and additional standard
`fprintd-enroll`, unattended subsequent-boot activation/E4 publication, stock
listing and positive/negative verification, origin-neutral rename and named
deletion with survivor proof, and sudo/PAM fingerprint plus password fallback
are proven on the reference machine. Compatibility restoration was not a
prerequisite.

## Identity model

There is one reconciled fingerprint set for the selected Linux user. Authority
mode chooses how that user's Apple/AKS identity is activated; it does not
create a second fingerprint type. The inventory, canonical fprint labels,
matching, rename, enrollment, and deletion code never select an identity by
macOS-versus-Linux origin. An existing fingerprint and a newly enrolled one
therefore have identical Linux behavior and can be matched or individually
deleted through the same interfaces.

Fresh configurations select `linux-native`. An upgraded configuration with no
selector is assigned `macos-control-oracle`, preserving its established
keybag/Catacomb authority. Switching authority is explicit and whole-user;
the installer never silently replaces existing fingerprints or credentials.

## Reconciled upstream claims

| Upstream claim at `ea46d8a` | Integrated result | Remaining gate |
| --- | --- | --- |
| fprintd/PAM verification works | Preserved for compatibility authority; native E4 enters the same fprintd facade. Stock positive/negative verification, real sudo/PAM fingerprint success, and password fallback with fprintd unavailable passed on the greenfield authority | Broader machine/bridgeOS coverage |
| Linux enrollment is a separate root CLI and one identity was proven | The stable CLI is authority-aware. Native clean-state first enrollment and uninterrupted additional enrollment are both hardware-proven | Broader machine/bridgeOS coverage |
| Single deletion is exposed but had never been hardware-tested | D217 proved exact command `0x0d`, survivor persistence, forward-only recovery, and post-reboot closure; subsequent integration proved the final named identity through clean empty reconciliation | Broader machine/bridgeOS coverage; batch deletion remains unexposed |
| Native `fprintd-enroll` / `fprintd-delete` are default-off and uninstalled | Standard enrollment and named single-deletion are connected to installed, caller-bound transient workers. First and additional enrollment, named and final delete, survivor and empty-state proof, rename, and automatic later-boot closure passed live | Broader machine/bridgeOS coverage; batch deletion remains unexposed |
| ACM is only an opt-in transient-context experiment | The normal Linux-native transport service now owns ACM registration and platform metadata. Native E4 retains persistent activation material across enrollment, matching, additional enrollment, and deletion | Installed service ownership and multi-user activation remain gates |
| Adaptive Catacomb persistence lacks a dedicated live control | Unchanged. The journaled opt-in post-match service remains available | A dedicated live adaptive-update control is still open |
| Multi-user operation is not exposed | Unchanged | Design and live proof of multiple concurrently mapped Linux users |
| A later macOS boot removed a Linux-only identity | Unchanged | Cross-OS host-Catacomb synchronization before claiming dual-boot persistence |
| `s2idle` works and `deep` breaks transport | Unchanged | Kernel/transport resume work for deep sleep |

## Product integration boundary

- `t2-fprintd.py` resolves exactly one runtime authority and one current
  reconciled projection. It never replays a cached transport endpoint after an
  ambiguous authentication result.
- Native verification always asks the same owner to accept the complete
  reconciled enrolled set. A client-supplied numbered handle is validated as
  presentation syntax, not used to restrict which enrolled fingerprint can
  unlock. Success is reduced back to the actual matched neutral handle only
  when the live identity is unambiguous.
- Standard enrollment and deletion retain the D-Bus caller, Linux account
  generation, PolicyKit grants, mapping generation, boot UUID, Bridge runtime
  generation, and one journal operation across the transient worker handoff.
- Native enrollment adds to an existing reconciled set when E4 authority is
  present; the same worker also owns the one valid empty pre-E4 bootstrap. It
  does not require or replace a compatibility fingerprint.
- Native deletion resolves a canonical name against the same fresh inventory,
  journals before dispatch, and reconciles either exact survivors or the clean
  empty state before reporting completion. Compatibility deletion remains available through its
  existing slot-based management command.
- The installer enables the common transport/readiness/fprintd chain in both
  modes. Native mode additionally installs a hard first-run identity/mapping/
  activation-bundle gate and automatic activation-aware post-reboot
  dispatcher. Only compatibility mode requires the macOS keybag-load and stored-credential
  units; native steady state uses its E4 activation bundle instead. A
  compatibility installation that does not provision the optional encrypted
  credential can still use the stable root enrollment command, but unattended
  standard-client enrollment fails closed.

The broker/product boundary and transaction ordering learned from pinned
T1Bridge are adapted where their semantics agree. T1 USB transport and T1
payload layouts are not copied into the T2 implementation.

## Pending upstream issues resolved incidentally

The greenfield audit closes several items that were pending or understated in
the upstream README, while keeping their live release claims separate:

- the native mutation facade and caller-bound workers are installed rather
  than default-off research drop-ins;
- first enrollment no longer has a circular dependency on an existing E4
  fingerprint authority;
- normal native service startup owns ACM and platform metadata instead of
  treating endpoint 10 only as an opt-in diagnostic;
- a blank install has a product-owned, multi-boot identity and activation
  lifecycle rather than a manual research sequence;
- first-run is ordered ahead of biometric readiness so their shared operation
  lock cannot make unattended native activation lose a boot-time race;
- first-run no longer discards every child-owner explanation: it exposes only
  a bounded printable final parser/validation error while rejecting opaque or
  control-bearing stderr;
- completed native enrollment/rename/delete journals have an automatic
  activation-aware post-reboot dispatcher that hard-gates fprintd;
- a committed E4 whose authority publication was interrupted is recovered as
  host-only publication under the operation lock, without replaying activation,
  inventory, verification, or mutation; exact temporary bytes and protected
  readback remain mandatory;
- post-reboot failures retain bounded allowlisted stage, exception/cause, and
  numeric status evidence instead of collapsing every failure to one opaque
  message;
- first enrollment seeds the same append-only rolling BioLockout authority
  consumed by matching, so first- and later-origin identities use one runtime
  restore path;
- installed transient workers use the project virtual environment and module
  root, and signal-free pidfd polling preserves caller binding across UIDs;
- the standard enrollment facade transports the native parser's authoritative
  monotonic percentage rather than presenting a fixed capture count;
- standard enrollment treats client-supplied anatomy tokens only as request
  syntax and allocates one durable neutral Finger N handle at the authorized
  worker boundary; failed/cancelled captures do not consume a number, while
  rename and deletion advance completed-handle history before it can vanish;
- explicit caller cancellation reconciles an unchanged inventory without
  starting Catacomb persistence, and progress arriving after removal re-arms
  the touch cue instead of stranding the UI in a false preparing state;
- same-boot validation of an additional fingerprint forwards the pinned Linux
  UID into the native matcher and retains paired root-private diagnostics;
- native sudo/PAM readiness is based on exact E4 authority, not compatibility
  keybag marker files;
- native named deletion has the ACM device and memory-lock capability required
  by its proven owner; and
- archived D124/replacement evidence is no longer a vanilla runtime
  prerequisite.

The greenfield run additionally resolved first-run issues not visible in
the upstream manual workflow: systemd credential fallback now uses a valid
reserved sentinel that mutation paths reject, and a disabled schema-2 mapping
with a durably committed bundle resumes fresh-boot handle reconciliation rather
than bypassing it. The reboot-required classification is bound to the creation
boot UUID, preventing automatic reboot loops after a genuine recovery failure.
The transport loader now uses the same typed state machine to retain the kernel
replacement gate for that exact recovery phase; it no longer drops authority
merely because bundle publication already advanced the mapping to schema 2.

Exact single-identity deletion is hardware-proven, resolving upstream's
"never hardware-tested" note. Final-identity forward recovery to a clean empty
inventory is also hardware-proven. Batch delete-all, dedicated adaptive-update
controls, multi-user operation, deep sleep, and cross-macOS persistence remain
open by design.

## Still deliberately unsupported

- batch delete-all, whole-user deletion, and cross-user
  administration;
- guessing physical fingers from legacy labels;
- retrying any ambiguous biometric mutation or authentication verdict;
- claiming a Linux-created identity survives a subsequent macOS boot;
- deep-sleep recovery without reboot; and
- release-level hardware support beyond the documented reference machines.

## Source-cache checkpoint

Before this reconciliation, both `upstream/main` and a direct
`macintog/main` ref were fetched and pruned to `ea46d8a`. The external-research
watch refreshed all 21 registered sources with zero fetch errors and no new
leads. The t2linux feature page changed content but still reports T2 Secure
Enclave support as unavailable; that project-level matrix does not yet reflect
this repository's machine-specific research proof.

After integration and test repair, both GitHub refs were fetched and pruned a
second time. They remained byte-identical at `ea46d8a`; that commit is the
current branch merge-base, with the rebased native history above it. No second
rebase was required. A final forced pass over all 21 external sources completed
with zero errors and zero new leads. The t2linux page digest changed again, but
direct inspection confirmed that its T2 Secure Enclave row still says "Not
working" and describes its Touch ID role; the project-status conclusion above
is unchanged.

The configured upstream cache and direct `macintog/main` cache were refreshed
again on 2026-09-14 immediately before the final release work; both still
resolve to `ea46d8a`. The branch merge-base is that exact commit, so there are
no newer upstream commits to rebase onto. T1Bridge's previously refreshed local
GitHub cache remains at `02885e4`.
