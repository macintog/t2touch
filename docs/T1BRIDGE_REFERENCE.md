# T1Bridge reference and reuse map

T1Bridge is the closest public end-to-end implementation in the same Apple
biometric protocol family. Consult it before designing or extending enrollment,
matching, Catacomb persistence, fingerprint-client integration, device-loss
handling, service ordering, or packaging. The purpose is to reuse established
answers where the protocols agree while preserving the T2-specific evidence
gates in this repository.

T1Bridge is one member of the public sources listed in the
[research credits](research/artifacts-and-method.md#research-credits). That
reference set also distinguishes independent T2 verification and transport
work from this project's native activation and enrollment contribution.

Upstream: <https://github.com/standardagents/t1bridge>

Baseline reviewed here: commit
[`7003b8d`](https://github.com/standardagents/t1bridge/tree/7003b8d)
(`main`, reviewed 2026-09-06). The 2026-09-12 daily check found current `main`
at `02885e4b3c51bc7ae609681495b5b22dd0f529ae`, with signed release `v0.1.9`
at `379f65310bc27059c923da0da6b86fa7a6e6d4f1`. Since the prior check, upstream
added recovery when enrollment finds a stopped failed keybag relay, complete
signed-repository publication staging, redacted relay diagnostics, ambient-
light integration, and reporting of SEP cleanup failure alongside an original
operation error. It did not change the saved-user-secret construction,
operation-`0x21` activation layout, Catacomb transaction, or fingerprint wire
protocol. The relay recovery is an **adapt-now** input for standard T2 service
integration; D178-D218 have since closed the native activation and enrollment
discriminators. The explicit dual operation/cleanup
error is already the required failure shape of the T2 ACM lifecycle and is
retained as a comparison check, not copied code. At the beginning of work on
this project, check upstream at most once per calendar day before relying on
behavior that may have changed, and record the newer commit and relevant diff.
An optional local checkout is a convenience, never a runtime or build
dependency.

The 2026-09-13 21-source check found no changed tracked source. D207 separately
re-read pinned commit `7003b8d9f791` for its minimum-prefix enrollment witness
and fresh identity-list rule; D218 adapted that ordering and proved it on T2
without adopting T1 payloads or transport.

## Evidence boundary

T1Bridge is implementation evidence and limited hardware evidence, not proof
that T1 and T2 are interchangeable. Its public release reports working Touch ID
on two MacBookPro13,3 machines, while its detailed fresh-install and complete
published-package operation matrix remains open. One MacBookPro14,3 enrollment
failure is also undiagnosed. Its release checklist says the complete
source/history provenance review remains pending. Inspect and attribute code
before adapting it; do not treat the squashed public history as provenance
proof.

Both projects are GPL-2.0-only, but license compatibility does not remove the
need to preserve applicable notices and identify adapted code.

## What the projects demonstrably share

The projects expose the same Mesa/BiometricKit command family.
The overlap is strong enough to make T1Bridge useful as a protocol and lifecycle
cross-check:

| Operation | Shared command or event | T2 extension or qualification |
| --- | --- | --- |
| Start, continue, cancel enrollment | `0x03`, `0x0e`, `0x0c` | T2 uses the protocol-v2 68-byte start request and richer event state. |
| Enrollment status and completion | `0xe3ff8001`, `0xe3ff8003` | T2 also handles auxiliary v2 events and group-aware identity records. |
| Start match and identity removal | `0x04`, `0x0d` | T2 match results and selected-identity inputs have v2 layouts. |
| Catacomb ID, hash, state | `0x38`, `0x3a`, `0x3c` | T2 additionally has group state through `0x50`. |
| Save and load Catacombs | `0x3d`–`0x40` | T1 uses v1 user descriptors; T2 uses 24-byte v2 component descriptors. |
| Per-user identities | `0x42` | T2 also validates global v2 identities through `0x51`. |
| Protected user/system policy | `0x2e`–`0x2f`, `0x43`–`0x44` | Values and prerequisites must still be established on the active bridgeOS build. |

The corresponding sources are T1Bridge
[`commands.rs`](https://github.com/standardagents/t1bridge/blob/7003b8d/crates/t1-bridge/src/commands.rs),
[`enroll_workflow.rs`](https://github.com/standardagents/t1bridge/blob/7003b8d/crates/t1-bridge/src/enroll_workflow.rs),
and [`catacomb.rs`](https://github.com/standardagents/t1bridge/blob/7003b8d/crates/t1-bridge/src/catacomb.rs),
versus this project's
[`t2_enrollment_protocol.py`](../src/t2_enrollment_protocol.py) and
[`t2_catacomb_protocol.py`](../src/t2_catacomb_protocol.py).

Shared numeric commands establish a comparison point, not wire compatibility.
Never substitute a T1 payload size, identity record, user descriptor, firmware
status, retry rule, or transport assumption without T2 evidence.

## Layer-by-layer correlation

### Enrollment transaction

T1Bridge's standard enrollment composition already answers several generic
questions that should not be redesigned casually:

- reserve durable recovery storage before sensor mutation;
- check capacity before starting capture;
- check an existing finger for duplication without relabeling it;
- bind the returned opaque identity to a standard finger label;
- persist label metadata atomically with the Catacomb generation; and
- re-read the complete physical identity set after commit and require exactly
  the prior set plus the returned identity.

Reference:
[`standard_enrollment.rs`](https://github.com/standardagents/t1bridge/blob/7003b8d/crates/t1-daemons/src/enrollment_transaction/standard_enrollment.rs).
T1Bridge's enrollment wait loop is sensor-event-driven: each qualifying service
callback causes exactly one protocol continue command, with no human keyboard
acknowledgement between captures. Its Touch Bar overlay also supplies a useful
minimal Enrollment/Retry/Success vocabulary, backend-owned progress, automatic
activation for an authorized operation, and cosmetic failure isolation. Its
standard overlay is activated inside an already user-initiated request; it is
not evidence that an unattended caller may consume Mesa's first-touch window.
D192 adapts those product invariants without copying the beta implementation
blindly. T2 keeps progress monotonic if the backend regresses, preserves an
explicit Q/Escape enrollment cancellation path, and adds accessible textual
brief-touch/lift guidance that distinguishes presence from accepted progress.
The D191 hardware trace and operator observation establish that sensor contact
is a fraction-of-a-second touch, never a sustained hold: status 63 must cue an
immediate lift while still leaving progress unchanged.
During bring-up, T2 deliberately does not adopt cosmetic-failure independence:
losing safety-critical capture guidance remains a fail-closed outcome.
T1Bridge `02885e4` also sends best-effort cancel after a start may have reached
Mesa and after every later primary failure, without replacing the primary
error. T2 **adapts** this cleanup invariant for local same-generation
protocol/callback failures: it durably records a `primary-failure` cancel
intent and accepted T2 command-`0x0c` reply before recording outcome unknown.
It does not weaken T2's poisoned-transport rule or infer cleanup success after
connection, transport, or journal loss; those cases still require fresh
inventory reconciliation.
It retains T2-specific journaling, duplicate-event protection, BioLockout,
group/global inventory, E3, and outcome-unknown reconciliation. Compare
[`t2_enrollment_operation.py`](../src/t2_enrollment_operation.py),
[`t2_enrollment_finalizer.py`](../src/t2_enrollment_finalizer.py), and
[`t2_enrollment_reconciliation.py`](../src/t2_enrollment_reconciliation.py)
before adding another enrollment abstraction. T1 command payloads, USB
transport, secrets, event framing, and Touch Bar-specific state transport
remain rejected as T2 authority.

The standard-fprintd companion applies the same decision at pinned T1Bridge
commit `02885e4b3c51bc7ae609681495b5b22dd0f529ae`. It **adapts** the compact
Enrollment/Retry/Success vocabulary, neutral `220/220/220` foreground, blue
`64/156/255` progress, dark-blue track, green success, and arrow/check visual
grammar into a persistent terminal presentation. It also adapts the smooth,
backend-owned progress principle: T2's native parser supplies a monotonic
0–100 percentage, the detached worker carries it in its versioned update
protocol, and the facade exposes it through the additive
`t2-enroll-progress` property. The companion renders that authoritative value
directly; it does not derive a percentage from a fixed capture count. It
**retains** T2's event-authoritative brief-touch and immediate-
lift cues, audible actionable transitions, terminal fail-closed state, and
standard `fprintd-enroll` ownership. It **rejects** the T1 Touch Bar framebuffer,
Inter raster masks, touch gestures/cancellation, T1 protocol payloads, and
cosmetic-failure isolation. No T1Bridge source is a runtime dependency.

### Catacomb persistence and recovery

T1Bridge implements a durable user-then-master paired transaction: stage and
sync each opaque export before its native confirmation, preserve the previous
active pair until final promotion, and distinguish an uncertain final directory
sync from a clean failure. It also couples the label manifest to the same
generation.

References:
[`catacomb_session.rs`](https://github.com/standardagents/t1bridge/blob/7003b8d/crates/t1-daemons/src/catacomb_session.rs),
[`catacomb_store.rs`](https://github.com/standardagents/t1bridge/blob/7003b8d/crates/t1-daemons/src/catacomb_store.rs), and
[`catacomb_restore.rs`](https://github.com/standardagents/t1bridge/blob/7003b8d/crates/t1-daemons/src/catacomb_restore.rs).
Our journaled v2 component batches, independent archive read-back, BioLockout
component, and E3/E4 comparison remain stricter T2 requirements. Reuse ordering
and failure classifications where they agree; do not replace those requirements
with T1's two-component model.

### SEP and operation ownership

T1Bridge uses one shared keybag-relay lease and exclusive enrollment/match
leases. It verifies relay health, arranges recovery before stopping it, acquires
SEP boundedly, and restores the relay on success, error, cancellation, timeout,
or teardown. Its standard broker also serializes all fingerprint work through
one scheduler.

References:
[`architecture.md`](https://github.com/standardagents/t1bridge/blob/7003b8d/docs/architecture.md),
[`sep_lifecycle.rs`](https://github.com/standardagents/t1bridge/blob/7003b8d/crates/t1-daemons/src/sep_lifecycle.rs), and
[`auth_scheduler.rs`](https://github.com/standardagents/t1bridge/blob/7003b8d/crates/t1-daemons/src/auth_scheduler.rs).
This validates the ownership shape, not its transport. T1 talks to SEP over a
USB/usbfs relay; T2 owns PCI/BCE mailbox DMA on endpoints 7 and 10 and must keep
its descriptor, poison, and reboot-only replacement rules.

### Persisted identity activation

T1Bridge correctly establishes the high-level lifetime used after reboot:
load the saved user blob, retain its positive handle, bind/promote the user
alias, resolve state, unlock, and then release the handle. T2 D160/D161 hardware
results confirm that skipping the reload/rebind sequence fails, while also
showing that the raw T1 unlock credential itself is not portable. D190/D191
further confirm that a clean reboot may leave the negative alias absent: this
is an instruction to perform the same load/rebind lifetime, not a quarantine
condition or reason to require the alias before positive-handle load.

T1Bridge persists a separate random 32-byte user secret beside its blob and
uses it to verify the promoted biometric keybag into a fresh ACM context. Its
enrollment path then installs a passphrase credential, proves the enrollment
policy against the live keybag UUID, and lends that authorized external form
to Mesa. The D137 T2 request-10 identity instead stores only the exported
keybag, but D163 proves its transient type-5 *creation* context is not by itself
a valid operation-`0x18` login credential. D166 recovers the missing portable
distinction from the exact T2 identity verifier: option `0x100` interprets its
secret field as an ACM reference containing type-5 password data, verifies the
extracted password against the simultaneously owned positive handle, and adds
the validated keybag credential to its optional authorization context. D167's
hardware result falsified using one reference for both roles. D168 separated
them but destroyed the input context before verification; SEP status `-1`
proved that the external form did not survive that deletion. D169 keeps the
input live while creating a distinct policy-1007 target. The verifier reads the
first and authorizes the second; only that target is policy-checked and consumed
against the bound negative alias, then both contexts are destroyed in reverse
order.

Decision: **adapt** T1Bridge's load/bind/resolve/unlock/release lifetime.
Also **adapt** its distinction between keybag-creation material and an
authorized enrollment credential. The exact random 32-byte value, T1 payloads,
and USB transport remain **rejected** as T2 authority. The separate persisted-
secret concept is now **adapted as a lifecycle requirement**: matching T2 SEP
code proves D137 derived its verifier from the raw creation-time external
reference, while D170 reconstructed the inner password. The T2 plan selects
its own exact mechanism: persist the creation-time 16-byte external form, then
install those bytes as type-5 data in a fresh live input context so normal
identity option `0x100` extracts the original KDF input. This is not T1's
32-byte secret or wire format. The fixed T2 `0x18` codec, operation-`0x21`
positive-load-handle binding, one-shot rule, independent read-back, and
immediate cleanup remain authoritative here.

### Standard fingerprint integration

This is the largest solved product gap relative to this repository. T1Bridge
implements a root broker protocol and a libfprint driver for capabilities,
open, list, enroll, verify, identify, delete, progress, cancellation, and typed
terminal results. A committed metadata catalog maps standard finger labels to
opaque Mesa identities, retains unlabeled legacy identities as hidden recovery
anchors, and revalidates the owner through NSS. Its fprintd patch prevents
fprintd's software duplicate scan from conflicting with device-native duplicate
detection.

References:
[`standard_fingerprint_protocol.rs`](https://github.com/standardagents/t1bridge/blob/7003b8d/crates/t1-daemons/src/standard_fingerprint_protocol.rs),
[`standard_identity_catalog.rs`](https://github.com/standardagents/t1bridge/blob/7003b8d/crates/t1-daemons/src/standard_identity_catalog.rs),
the [libfprint driver patch](https://github.com/standardagents/t1bridge/blob/7003b8d/packaging/arch/libfprint-t1bridge/0001-Add-T1Bridge-fingerprint-driver.patch),
and the [fprintd duplicate-detection patch](https://github.com/standardagents/t1bridge/blob/7003b8d/packaging/arch/fprintd-t1bridge/0001-Honor-driver-native-duplicate-detection.patch).

Native T2 E4 and direct positive/negative controls are complete. Prefer
adapting this broker/driver boundary over expanding the current
verification-only D-Bus facade ad hoc. Keep this project's stronger
Linux account-generation binding, PolicyKit/session authorization, and
E4-native authority checks.

### Device loss and dynamic endpoints

T1Bridge monitors the exact admitted NCM interface, shares cancellation across
SEP and Bridge operations, and duplicates the BridgeXPC socket so cancellation
can wake a blocked read immediately. It does not trust root USB hotplug alone.
That is a useful analogue for T2's dynamic RemoteXPC port and generation-pinned
Bridge owner.

Reference:
[`architecture.md`](https://github.com/standardagents/t1bridge/blob/7003b8d/docs/architecture.md#guarded-device-lifecycle).
For T2, fresh RemoteXPC discovery and the current Bridge generation remain the
authority; a T1 configuration-selector rebind is not a T2 recovery action.

### Services, PAM, and packaging

T1Bridge provides a useful next-stage product layout: minimal privileged
services, socket activation, explicit readiness dependencies, dynamic udev
discovery, DKMS packaging, a read-only status command, ordinary `pam_fprintd`,
and password fallback. E4, positive/negative controls, and continuous
additional enrollment are now complete, so these should inform the next T2
integration while unproven services remain disabled in the research boot.

References:
[`systemd/`](https://github.com/standardagents/t1bridge/tree/7003b8d/systemd),
[`packaging/arch/`](https://github.com/standardagents/t1bridge/tree/7003b8d/packaging/arch),
and [`security-review/v1.md`](https://github.com/standardagents/t1bridge/blob/7003b8d/docs/security-review/v1.md).

## T2 work T1Bridge does not replace

Do not use T1Bridge as authority for:

- typed T2 EFI boot-state publication or bridgeOS startup;
- PCI/BCE mailbox framing, DMA registration, or endpoint-7/10 lifetime;
- AKS protocol-v2 primary identity, create/export/load, or Linux-native mapping;
- v2 global identities, groups, device inventory, and 24-byte components;
- BioLockout persistence and T2 E3/E4 reconciliation;
- T2 dynamic RemoteXPC discovery, CDC-NCM recovery, or deep-S3 behavior; or
- a clean-wipe claim without imported Apple state. T1Bridge requires preserved
  machine-specific EFI/FDR data, whereas the T2 target deliberately does not.

T1Bridge also does not solve suspend/resume; both projects currently fail
closed and use reboot as the known recovery boundary.

## Required reuse workflow

Before implementing or substantially revising a covered layer:

1. Identify the matching T1Bridge source above and inspect it at the recorded
   commit or a newly recorded upstream commit.
2. Compare contracts and failure behavior, not only names or command numbers.
3. Classify the relevant approach as **adopt**, **adapt**, or **reject**.
4. Record the classification and the T2-specific reason in the change, research
   log, or decision record. A rejection needs evidence, not preference.
5. Preserve attribution and licensing for adapted code.

This review is not a new hardware gate and does not justify speculative ports.
It is a bounded design check intended to prevent duplicate implementation work.
