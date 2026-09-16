# Enrollment research

This directory publishes the current reverse-engineering findings for native
Touch ID enrollment, identity management, multi-user mapping, Catacomb
persistence, and recovery on Intel Macs with an Apple T2.

- [FINDINGS.md](FINDINGS.md) documents protocol layouts, authorization,
  persistent state, and recovery requirements.
- [EVIDENCE_COLLECTION.md](EVIDENCE_COLLECTION.md) explains the remaining
  evidence gaps and how to collect data for each one later.
- [MACOS_ENROLLMENT_UX_REFERENCE.md](MACOS_ENROLLMENT_UX_REFERENCE.md)
  documents the preserved macOS enrollment recording and the user-interaction
  semantics it should contribute to a future Linux frontend.
- [`scripts/`](scripts/) contains collection and preflight helpers. They do not
  enroll, delete, load, confirm, or repair biometric state.

## Contents

- [Collecting evidence from macOS](#collecting-evidence-from-macos)
- [Inspecting a Catacomb component on Linux](#inspecting-a-catacomb-component-on-linux)
- [Archive compatibility check](#archive-compatibility-check)
- [Implemented layers](#implemented-layers)
- [Limits](#limits)
- [Privacy and legal notice](#privacy-and-legal-notice)

## Collecting evidence from macOS

The recommended macOS entry point is
[`scripts/collect-all-macos-evidence.sh`](scripts/collect-all-macos-evidence.sh),
which produces one private archive for later offline analysis.

For the narrower selector-42 caller-identity diagnostic, use
[`scripts/collect-aks-caller-identities-macos.sh`](scripts/collect-aks-caller-identities-macos.sh).
It copies only likely Apple system caller executables and their public
code-signing metadata. It does not read a password, keybag, Catacomb, or
fingerprint. Its output is still private research evidence because Apple
binaries must not be committed or redistributed.

The smaller
[`scripts/collect-aks-platform-identities-macos.sh`](scripts/collect-aks-platform-identities-macos.sh)
records the boot-scoped audit-session and process-unique values for currently
running candidate callers. Its output is private and non-replayable; the script
exists to test relationships and field semantics, not to mint credentials.

## Inspecting a Catacomb component on Linux

After transferring an archive privately, inspect a Catacomb component on Linux
without printing its UUIDs:

```sh
enrollment_research/scripts/inspect-catacomb.py path/to/user_000001f5.cat
```

The JSON inventory reports identity labels, counters, creation times, owner
UID, and schema version. UUID output is deliberately opt-in with
`--include-identifiers`; never paste that form into a public issue or log.

## Archive compatibility check

To exercise the strict encoder and an independent semantic reader against the
complete private capture without printing names or UUIDs, run:

```sh
t2-catacomb-fixture-check /path/to/t2-enrollment-evidence.tar.gz \
  --apple-user-id 501
```

The checker is offline and non-mutating. It requires a private mode-0600
archive, reads components directly from the tar stream, and emits only counts
and compatibility booleans.

## Implemented layers

Each layer is hardware-free and separately tested. None of them can start a
live enrollment on its own.

The append-only journal has a typed enrollment layer. It rejects skipped or
reordered start/continue/cancel/terminal milestones, stale concurrent appends,
changed connection generations, boot or mapping reuse, exhausted capacity, and
untyped generic records. A journal produced by the standalone baseline command
is intentionally not mutation-ready because that command closes its inventory
connection. The privileged broker described below instead collects E0 and
executes E1 through final reconciliation under one connection lease.

A synchronous operation core composes the typed journal and pure event machine
through a dependency-injected transport. Tests cover start rejection,
disconnect, progress/continue, duplicate delivery, cancellation, request
erasure, stale E0 generations, provisional identity, and journal failure after
device dispatch. The core itself has no socket or CLI; the privileged broker
supplies its generation-pinned live adapter, keeps it inside the authorized ACM
callback, and continues through E3 reconciliation before reporting completion.

The persistence journal enforces the recovered component order between E2 and
E3. Successful enrollment binds an immutable user/master batch followed by a
mandatory separate bio-lockout batch; terminal failure permits only a single
bio-lockout refresh batch. It requires prepare and complete
intent/observations, records only secure-blob and final-file digests, forces
early confirms before advancing, and forces host batch commit before the final
confirm. It cannot become `persistence-ready` until stable SEP/host generation
equality and independent archive read-back are journaled. No raw secure blob
may enter the journal. The dependency-injected operation core executes this
ordering against fake transport and temporary host-store interfaces, wipes its
secure and encoded buffers, and freezes post-dispatch transport, codec,
host-store, journal, or read-back ambiguity as outcome-unknown. Concrete
generation-pinned Catacomb and bio-lockout adapters are composed only by the
explicitly gated broker. The Linux-local store also rehearses a real process
exit at the durable `prepare/` to `commit/` boundary. It fsyncs that
root-directory rename before any old component is removed, and fsyncs both
directories after each subsequent cross-directory promotion. Reopening the
store after the child exits proves the validated `commit/` transaction rolls
forward to one complete new generation.

The matching daemon disassembly also fixes the reply contract precisely:
prepare `0x3d` returns exactly one 32-bit expected secure-blob length, complete
`0x3e` returns a variable blob that must equal that length, and confirm `0x3f`
returns no payload. `t2_catacomb_protocol.py` enforces those rules as a pure,
non-sending codec for opaque 4-byte v1 and 24-byte v2 component descriptors.
The final SEP component hash is therefore evidence from independent stable
read-back, not a value invented from the confirm reply.

The hardware-free `t2_catacomb_bridge.py` adapter joins that codec to the
already-recovered Bridge command boundary through dependency injection. It
requires one exclusive, generation-pinned lease and exact event-free Bridge
replies, enforces one-way prepare/complete/confirm state, and poisons itself
after any possibly dispatched ambiguity. It intentionally contains no socket,
connection discovery, authorization callback, or user-facing route. Tests show
that its malformed/disconnected path also freezes the outer persistence journal
as outcome-unknown rather than retrying a component.

The pure E3 reconciliation layer is executable too. Given already-collected
host and same-connection SEP snapshots, it rejects mapping or binding drift,
removed or multiple identities, changed existing entity numbers, component
metadata changes, Catacomb UUID changes, and host/SEP disagreement. Identity
success additionally needs the completed typed persistence history and an exact
match to its reconciliation snapshot plus advanced user/master/bio-lockout/SEP
state. A reported failure without persistence can reconcile only against an
unchanged snapshot; the finalizer's bio-lockout-only path permits just that
component to refresh. If failure nevertheless left one new UUID, the journal
records the stable read-back as provisional E2 success before attempting E3.
The classifier itself remains pure; collection, writes, and hardware commands
are owned by the surrounding broker composition.

The privileged experimental broker supplies the collector around this pure
layer. Its recovery-only mode accepts exactly one outcome-unknown enrollment,
opens a fresh Bridge generation, and appends a distinct no-change E3 milestone
only when the stable host/SEP snapshot still equals E0. It refuses automatic
recovery if a new identity or any persistent delta is visible, and the live
path refuses a new operation while an earlier journal is unfinished. For the
narrower case where a terminal enrollment event was rejected locally after SEP
had already created one identity, the separately acknowledged
`--recover-observed-identity` mode can complete persistence. It requires a
terminal-stage outcome-unknown journal and a fresh double collection proving
exactly one new configured-user built-in identity, agreement between per-user
and global SEP inventories, unchanged host files, the same SEP Catacomb UUID
with a terminal secure-state hash advance, unchanged mapping/account/keybag
bindings, and no removal. The journal binds persistence to that fresh recovery
connection before any Catacomb mutation. Every other delta remains manual and
fail-closed. If a Catacomb confirm reply is lost or locally rejected, recovery
does not blindly replay it. For the proven early-confirm case it requires the
staged file to match the journal and a fresh state read to show that component
clean with the next required component still dirty. Only then can persistence
resume at the following component on the fresh connection. The bridge's exact
nil sentinel is valid for zero-capacity confirm replies, but never for prepare
or complete replies that requested output bytes. After a successful mutation,
the Linux-local Catacomb—not the older copied macOS archive—is the current host
baseline for a later enrollment. The archive remains the immutable recovery
reference; opening advanced local state requires strict decoding, unchanged
account/keybag bindings, and equality with a fresh stable SEP identity
inventory. This prevents both accidental rollback to the backup and false
rejection of a legitimate second enrollment.

E4 post-reboot verification is both a typed journal gate and a read-only broker
mode, `--verify-post-reboot`. A successful enrollment can cross it only on a
genuinely new Linux boot and Bridge connection while reproducing the E3
snapshot, mapping, account/bag, identity, protocol, host/SEP equality, and
keybag-ready state. The verifier opens the already-mutated local Catacomb
directly; it never restores the original backup over it. Failed enrollment
transactions cannot manufacture E4, and the repository does not trigger the
required reboot. A successful E3 awaiting E4 blocks another enrollment so its
exact snapshot cannot be displaced before verification.

## Limits

The following remain disabled or unverified:

- exhaustive command-level and crash-recovery fault coverage;
- creation of new AppleKeyStore/OpenDirectory/APFS users from Linux;
- whole-biometric-user removal with command `0x48`;
- writing Linux-generated Catacombs back into macOS; and
- transparent continuation of enrollment across suspend or reconnect.

## Privacy and legal notice

Catacomb files, keybags, account/persona inventories, raw UUIDs, and diagnostic
captures are private security material. The repository intentionally contains
none of them. Collector output is ignored by Git, created with restrictive
permissions, and must be reviewed and sanitized before sharing.

Apple binaries and firmware are not redistributed here. Obtain them from
software installed on hardware you control or from Apple's official restore and
update packages, subject to the terms that apply to you.

This is experimental research, not a supported enrollment implementation. Keep
password login and macOS recovery available, and never test destructive paths
against the only enrolled finger or only usable account.
