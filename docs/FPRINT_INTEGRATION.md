# Proper fprint integration design

This document records the implemented boundary between the proven T2 mutation
brokers and the standard fprint D-Bus API, plus the remaining installed-machine
release controls. It is deliberately stricter than a subprocess wrapper:
`fprintd` is privileged, so forwarding a label or username from D-Bus directly
to a root command would lose the caller identity and turn presentation data
into authority.

The upstream ABI reference is the freedesktop.org
[`net.reactivated.Fprint.Device`](https://fprint.freedesktop.org/fprintd-dev/Device.html)
interface.

## Contents

- [Implemented verification boundary](#implemented-verification-boundary)
- [Upstream mutation lifecycle to preserve](#upstream-mutation-lifecycle-to-preserve)
- [Required caller and authorization boundary](#required-caller-and-authorization-boundary)
- [Mutation worker boundary](#mutation-worker-boundary)
- [Enrollment status translation](#enrollment-status-translation)
- [Deletion policy](#deletion-policy)
- [Delivery status](#delivery-status)
- [Release expansion](#release-expansion)

## Implemented verification boundary

The repository implements the verification path:

1. Every list or verify transaction refreshes the redacted, stable,
local/live-reconciled identity projection. 2. A complete projection exposes
every unique durable neutral `finger-N` handle. 3. Both `any` and an existing
numbered request authenticate against the complete enrolled set; the number is
presentation and management metadata, never an anatomy claim or match
restriction. 4. Verification repeats the private per-user and global SEP
inventories on the same Bridge connection and reconciles the committed local
Catacomb. 5. A successful match resolves to exactly one actual neutral handle.
The service emits `VerifyFingerSelected("any")` before capture and that handle
through `VerifyFingerMatched` after success; ambiguous events fail closed.
6. The backend repeats both SEP identity views and rereads the local Catacomb
after matching. A state change invalidates the verdict.

No Apple user ID, identity UUID, Catacomb bytes, or biometric payload crosses
the public result boundary.

## Upstream mutation lifecycle to preserve

- `EnrollStart` requires a claimed device and either a neutral numbered request
  or one legacy stock-client anatomy token; `any` is invalid. The token is
  syntax only and is never retained as identity metadata.
- Enrollment is asynchronous. Nonterminal feedback uses `EnrollStatus` with
  `done=false`; terminal outcomes use `done=true`, after which the client calls
  `EnrollStop`.
- `EnrollStop` must cancel an active transaction without replaying an ambiguous
  command.
- `DeleteEnrolledFinger` deletes one named identity for the currently claimed
  user. `DeleteEnrolledFingers2` deletes all identities for that claimed user.
- `ListEnrolledFingers` must raise `NoEnrolledPrints` for an empty inventory,
  not manufacture a compatibility slot.

The T2 broker has journaled enrollment, single-identity deletion, rename,
cancellation, outcome-unknown recovery, local Catacomb persistence, and
post-reboot verification. The fprint facade reaches mutations through
caller-bound transient workers; authority-specific post-reboot proof is
automatic.

## Required caller and authorization boundary

For every mutation, a claim is bound to the unique system-bus sender that
created it. The adapter resolves that sender to stable kernel
process credentials and an authenticated active local session, then keep the
following evidence together for the claim lifetime:

- system-bus unique name;
- Linux UID and account-generation digest;
- process identity/start time or pidfd-backed equivalent;
- session identity and active/authenticated state;
- Linux boot and broker runtime generations;
- exact protected mapping generation and requested capability;
- one bounded PolicyKit authorization ID for the exact operation.

`Release`, `VerifyStart`, `EnrollStart`, `EnrollStop`, and deletion must accept
only the same live claim owner. A caller-supplied username, fprint finger name,
slot number, or D-Bus well-known name is never sufficient authority. The
existing `t2_user_policy`, `t2_polkit_grant`, account-generation, session,
mapping, and readiness types should remain the source of these checks.

The complete claim and authorization boundary is implemented. A sender-aware
dbus-next dispatcher
preserves the immutable system-bus unique sender in task-local context. During
`Claim`, the service asks the bus daemon for `GetConnectionCredentials`,
requires `UnixUserID`, `ProcessID`, and `ProcessFD`, validates that the
received descriptor is a pidfd for that exact PID, and pins the process
UID/start time. Every claim-scoped call must retain both the exact sender and
the live pinned process identity. The pidfd is then duplicated into the
existing libsystemd session collector and joined to a protected local-account
generation. A normal user may use the existing unique same-UID active-session
fallback. A setuid-root PAM client is accepted only with the exact four-UID
shape `real=user; effective=saved=filesystem=root`; its real UID is pinned
alongside the bus UID and start time. Because sudo's PAM helper is not itself
registered with logind, it may use the unique same-real-UID
active-local-session fallback; it cannot select another UID or an ambiguous
session. An all-root client still requires a direct pidfd-to-session binding
and can never borrow an arbitrary session. The process credentials, session,
and account generation are all revalidated on every claim-scoped call. Claims
are serialized so a concurrent claim cannot pass while evidence collection is
suspended. `NameOwnerChanged` cleanup cancels active verification, closes the
pidfd, and releases the claim when that connection disappears. This prevents a
second allowed D-Bus connection from using a claim by repeating its username
and prevents PID reuse from rebinding an existing claim. Protected mapping and
bounded PolicyKit binding remain required before mutation is enabled.

The claim derives an independently owned `AuthorizationSession` from the same
pidfd/session/account snapshot for a mutation request. This is
strictly self-service: the D-Bus process UID must equal the claimed Linux UID,
and the process must not carry the setuid-root PAM marker. A privileged PAM
claim may continue through verification, but cannot be converted into mutation
authority. The derived session retains the existing revalidation and bounded
PolicyKit collector. `t2_fprint_broker` can hand that session to the existing
joined broker through a mutually exclusive, pre-created authorization path. It
permits only the exact `enroll`, `rename`, and `delete-one` operations, forces
modification policy on, and closes the derived session even if the broker fails
before entering it. The resulting authority carries a fail-closed pre-dispatch
guard which repeats caller, mapping, keybag, runtime-generation, and
grant-expiry checks immediately before SEP mutation. `EnrollStart` and named
deletion reach this adapter only through their explicit worker clients; the
installed service constructs both clients.

## Mutation worker boundary

Before any worker is exposed, `t2-native-first-run.service` composes the
already-proven native owners into a fail-closed product lifecycle. A blank
state creates and different-boot verifies the initial saved identity; the next
stage publishes a schema-2 activation bundle and deliberately requires another
boot; the final stage independently activates and enables that bundle. The
normal transport loader derives its one-shot provisioning/replacement kernel
gates from those exact persistent phases. Archived research manifests and
research configuration toggles are not runtime inputs.

The long-lived fprint facade does not receive or retain the macOS password.
Compatibility-authority enrollment needs ACM password binding, so its
short-lived operation-scoped worker receives the encrypted system credential
through systemd's credential mechanism. Linux-native schema-2 enrollment uses
its E4 activation material and receives no password credential. In both modes,
the worker receives a typed authorization binding and canonical finger name
over a bounded local socket—not command-line arguments—and independently
revalidates:

1. the caller/claim binding and PolicyKit grant; 2. the enabled target mapping
and `enroll` or `identity-management` capability; 3. keybag, alias, Catacomb,
operation-lock, and mutation-journal readiness; 4. a fresh same-connection E0
inventory; 5. exact target resolution under that lock.

The worker owns the operation lock and one Bridge generation for the mutation.
The D-Bus facade only translates typed progress/results. Closing the client or
calling `EnrollStop` sends a typed cancellation request; it never kills and
blindly retries the worker. An interrupted or transport-ambiguous operation is
journaled as outcome-unknown and reconciled read-only before any new mutation.

The internal T2 consumer side is implemented and attached to the installed
enrollment path. `t2_recovery_anchor` writes an
operation-scoped, immutable, root-private tar archive of the validated
committed Linux-local Catacomb before any mutation; the existing version-1
baseline journal records this genuine backup, so no legacy `backup_references`
field is repurposed. Publication is exclusive, fsynced, single-link, idempotent
only for byte-identical state, and followed by a second store read.
`LiveUserReconciliationSession` releases enrollment material only after the
broker's repeated stable reconciliation, retains the same operation lock and
Bridge lease, and requires the anchored account/keybag to equal the protected
mapping.

`t2_fprint_enrollment_consumer` then composes that exact lease and anchor with
the existing ACM coordinator, journal, persistence finalizer, cancellation
predicate, feedback stream, Linux boot, operation ID, and mapping generation.
It accepts only an `operate`-stage, self-service, canonical-name enrollment
authority and passes the broker's fresh pre-dispatch guard directly to E1.
Inside the worker-held machine operation lock, the consumer also projects the
broker's same-generation reconciled identity inventory. It requires a complete
canonical projection and proves the requested finger name is absent before it
creates a recovery anchor, ACM context, journal, or enrollment command. The
facade's earlier projection check is therefore feedback, not trusted mutation
authority. The short-lived worker boundary is implemented and selected by the
installed daemon's explicit enrollment flag.
`t2_fprint_worker_launcher` creates one root-private operation socket and
starts a hardened transient service with `LoadCredentialEncrypted`; its argv
contains only the random socket path. `t2_fprint_worker_protocol` transfers
exactly one live pidfd plus canonical finger, account, and login-session
evidence over bounded Unix seqpackets. The worker independently reconstructs
the pinned authorization session before PolicyKit, mapping, Bridge, or T2
access. The compatibility branch accepts only an enabled
`host-encrypted-credential` mapping; the native branch reconstructs or loads
the selected E4 authority without a credential.

`t2_system_credential` first proves password fallback against the positive
runtime keybag, then supplies the 16-byte ACM external form and password to the
new stdin-only AKS command. Plaintext is confined to the transient worker and
its child tool, wiped from mutable buffers, suppressed from stdout/stderr, and
never reaches fprintd. Progress is identifier-free; cancel, peer close, or
facade task cancellation sets one cooperative predicate and waits for the
journaled terminal response. `t2_fprint_worker_client` revalidates the original
claim before and after worker launch and retains completion until stop.

The credential-free `t2-touchid-post-reboot` oneshot dispatches automatic
post-reboot proof to the configured authority owner. The compatibility branch
runs before fprintd, selects exactly one
eligible reconciled enrollment, label-rename, or single-delete journal,
reproduces the derived runtime authority plus its disabled protected-map,
account, and keybag bindings, checks both the positive runtime handle and
special alias, and collects stable local/host/SEP state on a fresh Bridge
generation. It then appends only that journal's typed
terminal proof: `E4_POST_REBOOT_VERIFIED`, `RENAME_POST_REBOOT_VERIFIED`, or
`DELETE_POST_REBOOT_VERIFIED`. It has no password credential and no enrollment,
rename, delete, or persistence command path. Installed `EnrollStart` and named
deletion run only through the workers and leave any unresolved E3 journal
blocking until this verifier closes it on a later boot.

Linux-native E4 keeps its explicit enrollment and identity-management
post-reboot verifiers because those paths must reactivate the E4 bundle through
AKS and ACM. The dispatcher now invokes those exact owners, pins the original
journal caller UID as their trusted service caller, and validates their typed
terminal proof. `fprintd` hard-requires that oneshot, native first-run, and
common biometric readiness, so a failed E3-to-E4 proof blocks the consumer.

E4 verification and runtime-authority publication are separate durable steps.
If verification committed E4 but the authority manifest did not commit, the
next native dispatcher invocation selects that state separately and performs
only host publication under the shared operation lock. Recovery requires one
exact schema-2 first-enrollment E4 journal, its unchanged mapping/account/
identity/hash bindings, no later or unfinished mutation, and no valid different
authority. It never invokes activation, inventory, enrollment, or matching.
An interrupted temporary manifest is reused only when its bytes exactly equal
the manifest derived from that E4 journal; collisions remain fail-closed. The
published authority is then loaded through the normal protected readback and
must resolve to the expected mapping and operation-derived journal.

Service failures emit one bounded redacted JSON diagnostic. Its stage is from
a fixed allowlist covering candidate selection, configuration/mapping,
activation, inventory, journal append, authority publication, and final
authority readback; it includes only exception/cause classes and a numeric
errno or child exit status when available. Raw stderr, paths, identifiers, and
payloads are not copied into the service journal. The service still exits
nonzero, so the existing fprintd dependency gate is unchanged.

The audited service boundaries are summarized in
[`SERVICE_INTERFACE_AUDIT.md`](SERVICE_INTERFACE_AUDIT.md).

## Enrollment status translation

The existing enrollment parser already distinguishes finger presence, lift,
quality guidance, progress, terminal identity, failure, and cancellation.
Translation should be deterministic:

| T2 broker transition | fprint status | done |
| --- | --- | --- |
| accepted progress stage | `enroll-stage-passed` | false |
| retryable quality failure | the closest documented retry status | false |
| lift/place required | `enroll-remove-and-retry` | false |
| independently proven duplicate identity | `enroll-duplicate` | true |
| lock-held stable capacity exhausted before dispatch | `enroll-data-full` | true |
| reconciled identity and committed Catacomb | `enroll-completed` | true |
| cancelled/reconciled failure | `enroll-failed` | true |
| unresolved or malformed outcome | `enroll-unknown-error` | true |

The facade must not invent a fixed enrollment-stage count from variable T2
progress. `num-enroll-stages` therefore remains undefined (`-1`). The native
parser's bounded monotonic percentage is authoritative and travels separately
in worker-update schema 2. The facade publishes it as the additive integer
property `t2-enroll-progress` (`-1` before native progress is known); standard
fprint status semantics remain unchanged. Update-schema 1 is still accepted
without percentage for a bounded rolling upgrade, but new workers emit schema
2 and successful completion is exactly 100.

The facade also emits the historical
`org.freedesktop.DBus.Properties.PropertiesChanged` signal whenever
`finger-present` or `finger-needed` changes. These Boolean notifications are
best-effort UI feedback only: D-Bus delivery failure cannot cancel, retry, or
reinterpret a journaled biometric operation. Verification marks `finger-needed`
while its match task is active and clears it on every terminal, cancellation,
and stop path. Enrollment derives both properties from its typed worker stream.
Its raw compatibility layer advertises those same five historical properties
through `Introspect`; a generic desktop client therefore sees the same property
contract that `Get` and `GetAll` actually serve.

The pure `t2_fprint_enrollment_runtime` translator enforces the proven subset
of this table. It emits `enroll-stage-passed` only for strictly increasing,
bounded T2 progress; suppresses duplicate progress; maps quality guidance only
to the documented fprint vocabulary; and reports completion only after the
typed coordinator result proves policy, persistence, and final reconciliation.
Regressed progress, identity/terminal events that bypass final reconciliation,
or incomplete success become fail-closed errors. The facade also serves the
complete historical property set through `Get` and `GetAll`; stage count stays
`-1`, while finger-present/needed state and native percentage are driven by the
worker stream.
The worker preserves a stable lock-held capacity refusal as `enroll-data-full`
before recovery anchoring or SEP dispatch. No recovered T2 event yet
distinguishes an already-enrolled physical finger from a generic reconciled
failure, so source deliberately does not emit `enroll-duplicate` until that
outcome can be independently proven.

The D-Bus facade has the tested final adapter around that stream. When an
explicit client is supplied, canonical `EnrollStart` passes the exact pinned
claim to it, updates the historical properties, emits ordered `EnrollStatus`,
keeps verify/enroll mutually exclusive, and makes `EnrollStop`, `Release`,
sender departure, and terminal grace expiry wait for worker reconciliation.
Before it can launch the worker, `EnrollStart` collects a fresh projection
under the biometric operation lock. It refuses incomplete legacy or duplicate
labels, then forwards request syntax unchanged. The authorized native or
compatibility worker alone chooses the lowest vacant slot from the lock-held
reconciled five-slot inventory; retained identities are never renumbered. A
collection failure, malformed result, or claim change during the asynchronous
check also fails closed before any mutation client is called. The daemon's
explicit `--enable-native-enrollment` process flag constructs this exact worker
client, and the installed systemd unit supplies it. The installed
`t2-touchid-fprint-enrollment-gate` is read-only and combines the exact stack,
mapping, AKS observer, canonical projection, journal-clear, and
effective-daemon state with explicit attestations for the live fallback,
two-finger, and worker-negative controls. It can report readiness but cannot
install the separate research drop-in or dispatch a mutation.

On a clean native installation there is deliberately no E4 fingerprint
authority before the first enrollment. The facade and detached worker share
one exact `native_enrollment_context()` resolver. Only a complete,
mapping-enabled provisioned authority with no runtime enrollment authority and
empty Catacomb/mutation/activation roots projects as an empty inventory for
`ListEnrolledFingers` and `EnrollStart`; verification remains E4-only. Any
partial or stale pre-E4 state fails closed.

Incomplete legacy labels have a read-only migration bootstrap rather than a
guessing rule. `t2_fprint_match_gate.prepare_slots` joins every opaque SEP
identity to the same ephemeral slot ordering used by the identity-management
preflight, after exact repeated local/per-user/global reconciliation. The probe
selects all identities, reports only the matched slot, and repeats the
inventory and local-component attestation after the scan. The installed
`t2-touchid-identify-finger` wrapper exposes that slot with an explicit
`mutation_performed: false` result. It cannot assign an anatomical name; the
operator may separately invoke the acknowledged, journaled rename transaction.
That transaction refuses a numbered handle already assigned to another
identity and reports the resulting neutral projection completeness without
exposing an identity identifier. The installed
`plan-fprint-rename` path performs the same fresh target and projection
calculation without creating a journal or sending a mutation, and
`rename-fprint` refuses any name outside the neutral `finger-N` vocabulary.

`t2_fprint_enrollment_controller` supplies that stream boundary without
starting a real mutation. It runs the synchronous journaled worker in a
separate thread, delivers each translated update back onto the D-Bus event loop
in order, and retains the completed transaction until `EnrollStop`. Stop,
release, and even accidental asyncio task cancellation set the worker's
cooperative cancel predicate and wait for its reconciled terminal result; they
never kill the worker thread or replay a command. Worker, feedback, or result
failures terminate as `enroll-unknown-error`.

After an immediate E3 success, E4 still requires a reboot. The boot-time
authority dispatcher completes that proof automatically when every binding and
digest reproduces exactly. Failure remains visible in its private
systemd journal and leaves the blocking E3 journal untouched; desktop-visible
failure feedback remains best-effort. The installed automatic path and its
standard-client enrollment, deletion, rename, and survivor controls passed on
the reference machine.

## Deletion policy

The installed facade exposes `DeleteEnrolledFinger` through its injected
credential-free worker client. It binds the method to the exact claim owner,
rejects `any`, requires a fresh complete projection and an enrolled canonical
name, refuses the final remaining identity, and keeps
verification/enrollment/deletion mutually exclusive. Release or D-Bus peer loss
waits for deletion reconciliation; it never cancels and replays an ambiguous
command. Success requires an exact typed result proving the named mutation
reconciled locally; under compatibility authority the automatic post-reboot
verifier later supplies its different-boot proof.

The deletion worker is implemented as a separate credential-free transient
service. Its distinct seqpacket protocol transfers exactly one live caller
pidfd plus claim evidence and rejects enrollment packets. Inside the broker's
operation lock and Bridge generation, `prepare_deletion_material` re-reads the
committed Catacomb, reproduces the cached private SEP snapshot digest, freezes
an immutable recovery anchor, and resolves the requested canonical name to one
private UUID. The consumer records that target before command `0x0d`, shares
the management CLI's persistence/reconciliation tail, and returns only an exact
reconciled completion. Peer loss after handoff cannot cancel or replay the
deletion.

Because neither the native worker nor the older management rename/delete CLI
reads or verifies the macOS password, their durable baselines record
`password_fallback_verified: false`. The generic journal schema preserves that
truthful Boolean while enrollment creation and the typed enrollment reader
still require it to be true. Thus no credential-free identity-management path
can manufacture an enrollment-only password attestation or weaken the
enrollment boundary.

`t2_fprint_delete_worker_client` is wired only by the explicit
`--enable-native-deletion` process flag. The installed unit supplies that flag
and the separate enrollment flag; each path still requires its own transient
worker, caller binding, and journaled reconciliation.

Both hardened transient launchers explicitly set the root-owned installed
module path `/opt/t2-touchid/src` and execute their entry points with the
installed `/opt/t2-touchid/.venv/bin/python`. This is part of the packaging
contract, not caller-controlled state: omitting the module path caused the
first standard enrollment request to stop before physical readiness, while an
installed smoke gate then proved that the system interpreter also lacks the
required `dbus_next` package. The enrollment and deletion launcher contracts
pin both dependencies so an installed daemon cannot pass its preflight and
then fail only after transient-service dispatch.

The worker's kernel-pinned caller liveness check uses nonblocking pidfd polling,
not `pidfd_send_signal(pidfd, 0)`. The latter is signal-permission-gated across
UIDs and caused the installed hardened root worker to stop at `pin-caller` with
`IPCSessionError`/`PermissionError` before sensor readiness. Granting
`CAP_KILL` merely to ask whether the caller exited would unnecessarily broaden
the worker. A pidfd becomes readable when its process exits, so polling retains
the same race-resistant liveness decision without signal authority; the worker
still revalidates PID, UID, start time, session, account, and PolicyKit state.
The initially suspected `CAP_SYS_PTRACE` addition did not change the failure
and was removed from both enrollment and deletion workers.

The companion enrollment TUI is presentation only; `/usr/bin/fprintd-enroll`
still owns the standard D-Bus request. It adapts T1Bridge's compact Apple-like
overlay style while deriving touch and lift cues solely from the facade's live
`finger-needed` and `finger-present` properties. Its percentage bar consumes
the native backend's monotonic `t2-enroll-progress` property, not a fixed
capture count. Retry and terminal results are explicit, and raw client output
is not rendered. The alternate-screen terminal remains on its final result
until closed, rather than returning to a held shell prompt.

Do not implement bulk deletion as a loop over the single-delete API. A crash
would create a partially deleted set with unclear client semantics. Keep
`DeleteEnrolledFingers` and `DeleteEnrolledFingers2` fail-closed until there is
an explicit batch journal, deterministic recovery, and a tested policy for the
last remaining identity.

## Delivery status

The reference-machine gates for caller binding and pre-dispatch denial,
cancellation/recovery, first and additional enrollment, fresh list/verify,
reboot persistence, selected non-final deletion with survivor proof,
unattended startup, sudo/PAM fingerprint success, and password fallback have
passed. Authentication is deliberately set-wide: a client-supplied numbered
handle is presentation syntax and must exist, but any enrolled fingerprint can
satisfy the verification transaction. The facade reports the actual matched
neutral handle without treating the requested label as an anatomical or
origin-specific restriction.

## Release expansion

The reference-machine greenfield acceptance sequence is complete. Keep batch
and final-identity deletion disabled until they have a separate atomic journal
and recovery design. Remaining work is release engineering: broader hardware
coverage, review of the complete patch against upstream, and packaging/CI—not
another fingerprint enrollment on this machine.
