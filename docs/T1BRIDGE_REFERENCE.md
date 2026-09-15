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

The comparisons below are pinned to
[`7003b8d9f791`](https://github.com/standardagents/t1bridge/tree/7003b8d9f791)
and, where identified,
[`02885e4b3c51`](https://github.com/standardagents/t1bridge/tree/02885e4b3c51bc7ae609681495b5b22dd0f529ae).
They describe those source versions, not a claim about the latest release.
T1Bridge is not a runtime or build dependency of t2touch.

## Evidence boundary

T1Bridge is comparison evidence, not proof that T1 and T2 are interchangeable.
The pinned sources use the
[MIT license](https://github.com/standardagents/t1bridge/blob/02885e4b3c51bc7ae609681495b5b22dd0f529ae/LICENSE);
t2touch's integration is GPL-2.0-only. Preserve the applicable notices and
identify any adapted code. Similar names and opcodes do not establish matching
payloads, credentials, transport lifetimes, or hardware behavior.

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
T2 adapts the event-driven capture model. It keeps progress monotonic if the
backend regresses, preserves an
explicit Q/Escape enrollment cancellation path, and adds accessible textual
brief-touch/lift guidance that distinguishes presence from accepted progress.
T2 sensor contact is a brief touch, not a sustained hold: status 63 must cue an
immediate lift while still leaving progress unchanged.
T2 does not adopt cosmetic-failure independence:
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
the standard fprintd service boundary through its direct D-Bus client. It **rejects** the T1 Touch Bar framebuffer,
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

T1Bridge uses a saved-user-blob lifecycle: load the blob, retain its positive
handle, bind/promote the user alias, resolve state, unlock, and release the
handle. T2 also needs a fresh load/bind lifetime; an absent negative alias after
boot does not by itself imply corrupt saved state.

The credential representations differ. T1Bridge persists a separate random
32-byte user secret. T2 preserves the 16-byte creation-time ACM external form,
then installs those bytes as type-5 data in a fresh live input context. AKS
option `0x100` extracts that input and verifies it against the owned positive
handle. The verifier authorizes a distinct `TouchIdEnrollment` target context.
Both contexts must remain alive while the original input reference is used for
T2 operation `0x18`; deleting the input or substituting the target reference
changes the credential contract.

Reuse the load/bind/resolve/unlock/release lifetime and the distinction between
creation material and enrollment authorization. Do not copy T1's secret size,
payloads, or USB transport. The T2 derivation and request sequence are detailed
in [identity and authorization](research/identity-and-authorization.md).

### Standard fingerprint integration

T1Bridge implements a root broker protocol and a libfprint driver for capabilities,
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

Native T2 E4 and direct positive/negative controls are complete. The installed
T2 facade now implements verification, enrollment, and named deletion through
separate authorized workers. T1Bridge remains a useful broker/driver reference;
any future integration must preserve this project’s Linux account-generation
binding, PolicyKit/session authorization, and native authority checks. See
[the current fprintd contract](FPRINT_INTEGRATION.md).

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

T1Bridge separates privileged services, socket activation, readiness,
udev discovery, DKMS packaging, status reporting, and PAM fallback. These are
useful design comparisons. t2touch already installs its own native service
chain and PAM integration; its [architecture](ARCHITECTURE.md) describes the
actual T2 dependencies.

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

The referenced T1 lifecycle does not establish T2 suspend/resume behavior.
T2 sleep and recovery limits are documented in [Troubleshooting](TROUBLESHOOTING.md).

## Comparing a new implementation

Inspect the relevant source at a pinned commit, compare its contracts and
failure behavior, and explain which parts transfer to T2. Preserve attribution
for adapted code and validate differences in credentials, framing, ownership,
and persistence independently. A useful reference does not remove the need for
T2-specific evidence.
