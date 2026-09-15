# Proper fprint integration design

This document records the implemented boundary between the proven T2 mutation
brokers and the standard fprint D-Bus API, including installed service contracts.
It is deliberately stricter than a subprocess wrapper:
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
- [Authentication semantics](#authentication-semantics)
- [Support limits](#support-limits)

## Implemented verification boundary

The repository implements the verification path:

1. A successful list exposes the complete reconciled neutral `finger-N`
   inventory. Simultaneous list requests may share only a currently running
   collection. Native presentation metadata may remain cached while protected
   account authority, committed Catacomb metadata, and mutation-journal metadata
   are unchanged. Separate administrative mutations invalidate reuse on the next
   access; compatibility authority always collects fresh state.
2. The same caller may pass its single-use list projection to its next
   `VerifyStart`. Without that projection, verification collects one. Release,
   enrollment, and deletion invalidate this presentation state.
3. Both `any` and an existing numbered request authenticate against the complete
   enrolled set. The number is management metadata, never anatomy or a match
   restriction.
4. Native verification still repeats the private per-user and global SEP
   inventories on the same Bridge connection and reconciles the committed local
   Catacomb. Reusing presentation metadata does not authorize a match.
5. After `VerifyStart` returns, the actual `match_armed` event sets
   `finger-needed` and emits `VerifyFingerSelected("any")`. A successful match
   resolves to exactly one neutral handle, emitted through `VerifyFingerMatched`;
   ambiguous events fail closed.
6. The backend repeats both SEP identity views and rereads local Catacomb state
   after matching. A state change invalidates the verdict. Optional sound work
   cannot delay readiness or the terminal result.

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

Before exposing workers, `t2-native-first-run.service` composes native owners
into a fail-closed lifecycle. Blank state creates and persists the selected
identity, then verifies its saved activation bundle through a fresh exclusive
userspace owner before enabling the account. Normal first enrollment likewise
finishes fresh-owner proof and authority publication in the current session.
Historical different-boot stages remain relevant to recovery and later startup;
they do not impose a reboot on every new installation or enrollment.

A missing applesmc boot-state publisher or a changed resident transport may
still require a planned kernel restart. The installer does not force a reboot,
unload live applesmc, or unbind the SEP-pinned transport to manufacture the
required state. Archived research manifests are not runtime inputs.

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
rename, delete, or persistence command path. The compatibility workers leave unresolved E3 journals blocking until the
applicable verifier closes them. The native installed path also supports
same-session fresh-owner completion; service names containing “post-reboot” do
not make a reboot a universal completion requirement.

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

The service layers and their ownership are summarized in
[architecture](ARCHITECTURE.md).

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
reinterpret a journaled biometric operation. Verification marks `finger-needed` only when the reader reports `match_armed`,
and clears it on every terminal, cancellation, and stop path. Enrollment derives both properties from its typed worker stream.
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

The installed first-enrollment path completes persistence, fresh-owner
verification, and authority publication before returning success in the current
session. Historical E3/E4 records include different-boot proof; boot-time
reconciliation remains available for eligible journals and subsequent starts.
A proof failure leaves the operation blocked and visible in the private journal.

## Deletion policy

The installed facade exposes `DeleteEnrolledFinger` through its injected
credential-free worker client. It binds the method to the exact claim owner,
rejects `any`, requires a fresh complete projection and an enrolled canonical
name, permits the final named identity to reconcile an empty inventory, and keeps
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

Both transient launchers use the root-owned installed module path
`/opt/t2-touchid/src` and interpreter `/opt/t2-touchid/.venv/bin/python`.
Those paths are fixed by packaging, not supplied by the caller.

Caller liveness uses nonblocking pidfd polling. A pidfd becomes readable when
its process exits, so the worker can detect exit without signal authority.
It also revalidates PID, UID, start time, session, account, and PolicyKit state.

The installed enrollment TUI is a direct D-Bus client. It owns its claim and
operation, handles service-owner loss, and takes touch/lift cues from live
`finger-needed` and `finger-present` properties. Its progress display follows
`t2-enroll-progress`; it does not infer progress from a fixed capture count.
Standard fprintd clients independently exercise the same service boundary.

Do not implement bulk deletion as an unjournaled loop over the single-delete
API. The product `t2touch purge` command owns an explicit outer batch journal,
records each next handle before calling the reconciled single-delete path, and
requires a complete matching projection when it resumes. It reports partial
completion rather than claiming atomic rollback.

`DeleteEnrolledFingers` and `DeleteEnrolledFingers2` remain fail-closed at the
fprintd boundary. Enabling them still requires binding the claimed D-Bus user
and caller lifetime to the product batch broker; the presence of an internal
batch journal alone does not establish that client authorization contract.

### Product deletion authorization ordering

`t2touch delete finger-N` authorizes `/usr/local/sbin/t2-touchid-delete` through
pkexec before opening any biometric connection or taking the operation lock.
The existing identity-management action requires fresh `auth_self` authorization for an active
local user; it does not retain an authorization cache. The isolated Python
helper requires root, validates pkexec's original UID against the protected
native configuration, and accepts only one neutral finger handle. It then uses
`run_delete` with the existing administrative authority, mapping capability,
exact-inventory, global-lock, mutation-journal and reconciliation checks.
Terminal cancellation after authorization cannot interrupt that transaction.

`t2touch purge` uses the separate root-owned `t2-touchid-purge` helper and
`org.t2linux.touchid.purge` action. The CLI asks for destructive confirmation
before pkexec; the helper then holds one global operation lock and sleep
inhibitor across the batch. Each child deletion has its ordinary private
mutation journal, while the outer `delete-batch` journal records ordered neutral
handles, completed count, and any pending handle. A new invocation must use
`--resume`; it obtains fresh authorization and refuses an inventory delta that
is not the exact pending deletion.

This ordering avoids recursively asking the reader to authenticate deletion
while its D-Bus claim and global operation lock are already held. Existing
low-level `DeleteEnrolledFinger` clients remain supported, but their interactive
authorization can fall back to a password while holding the reader. The product
command takes the corrected path. This change does not alter sudo PAM,
Polkit's general PAM stack, desktop locking, or enrollment policy.


## Authentication semantics

Authentication is deliberately set-wide: a client-supplied numbered
handle is presentation syntax and must exist, but any enrolled fingerprint can
satisfy the verification transaction. The facade reports the actual matched
neutral handle without treating the requested label as an anatomical or
origin-specific restriction.

## Support limits

The installed native lifecycle is proven on the reference machine. Batch
deletion remains disabled; named final-fingerprint deletion is supported.
Broader hardware coverage, multi-user operation, deep sleep, and cross-macOS
persistence remain unproven. The [README](../README.md#what-has-been-proven)
describes the supported installation path and tested scope.
