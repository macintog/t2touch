# T2 SEP staged transport

This file retains low-level interfaces and the staged research history. For the
installed product, use [architecture](../docs/ARCHITECTURE.md) and the current
[fprintd contract](../docs/FPRINT_INTEGRATION.md). Historical different-boot
procedures and default-off research gates are not the normal install sequence;
the installed unit enables its authorized enrollment and named-deletion workers.

This module is the write-capable successor to `t2-sep-probe`, but defaults to
observation-only behavior. In its default mode it claims PCI function
`106b:1802`, maps BAR4, and reads the two mailbox status registers. It performs
no DMA allocation and no MMIO writes.

## Contents

- [Safety and build](#safety-and-build)
- [Kernel transport](#kernel-transport)
  - [OOL registration (`register_ool=1`)](#ool-registration-register_ool1)
  - [The `/dev/t2-aks` exchange device](#the-devt2-aks-exchange-device)
  - [The `/dev/t2-acm` endpoint-10 device](#the-devt2-acm-endpoint-10-device)
- [AppleKeyStore commands (`t2-aks-tool`)](#applekeystore-commands-t2-aks-tool)
- [ACM authorization research](#acm-authorization-research)
- [Verification and the fprintd facade](#verification-and-the-fprintd-facade)
  - [fprint projection and presentation](#fprint-projection-and-presentation)
  - [Identity-resolution authority](#identity-resolution-authority)
  - [Caller ownership](#caller-ownership)
  - [Adaptive template persistence](#adaptive-template-persistence)
- [Identity management](#identity-management)
- [Enrollment core](#enrollment-core)
  - [Protocol, journal, and operation](#protocol-journal-and-operation)
  - [Bridge adapter and inventory](#bridge-adapter-and-inventory)
  - [Catacomb persistence](#catacomb-persistence)
  - [Reconciliation and finalization](#reconciliation-and-finalization)
  - [The `t2-touchid-enroll` frontend](#the-t2-touchid-enroll-frontend)
  - [Live run history](#live-run-history)
- [Native fprint enrollment and deletion (staged)](#native-fprint-enrollment-and-deletion-staged)
- [Multi-user policy and broker (non-exposed)](#multi-user-policy-and-broker-non-exposed)
  - [Mapping, account evidence, and administration](#mapping-account-evidence-and-administration)
  - [Policy resolution and PolicyKit grants](#policy-resolution-and-policykit-grants)
  - [Broker transaction and IPC](#broker-transaction-and-ipc)
  - [Socket-activation candidates](#socket-activation-candidates)
  - [Keybag activation](#keybag-activation)
- [Research notes](#research-notes)

## Safety and build

Read this section before loading the module.

After either buffer is successfully registered, the module pins itself in
memory. SEP retains the DMA address and Apple exposes no matching unregister
control message; freeing that memory while SEP is live would be unsafe. A
reboot clears the registration and unloads the module.

Build with `make`. Do not load both this module and `t2_sep_probe` together.
The currently loaded registration-only revision is pinned; testing a rebuilt
revision requires a reboot rather than an unload.

## Kernel transport

The module claims PCI function `106b:1802` and provides the SEP endpoint-7 path
that everything else here depends on.

### OOL registration (`register_ool=1`)

The explicit `register_ool=1` mode mirrors the recovered Apple transport setup
for AppleKeyStore endpoint 7:

- enables a 44-bit coherent DMA mask and PCI bus mastering;
- allocates separate 16 KiB, page-aligned input and output buffers;
- sends endpoint-0 `SET_REMOTE_DMA_IN` and `SET_REMOTE_DMA_OUT` control calls;
- validates the matching transaction tag and zero SEP result.

The installer supplies `probe_capabilities=1`, which issues exactly one
read-only opcode `0x4d` capability query after both OOL registrations succeed.
The recovered v1 request is 92 bytes and uses SHA-256 truncated to 16 bytes for
its integrity field. It does not request a fingerprint, modify SKS lock state,
or read/write enrollment records. A failed negotiation leaves `/dev/t2-aks`
disabled rather than exposing an exchange device whose requests will time out;
the pinned DMA registration then requires a reboot before another attempt.

### The `/dev/t2-aks` exchange device

The experimental `macos_app_version=0x100` option sends one recovered
endpoint-0 `START_VERSIONED_APPS` command before endpoint-7 OOL registration.
Matched BridgeOS exposes the same action as
`seputil --launch-macos-app 100`; the command is fixed to the recovered
eight-byte layout and is not a generic raw mailbox interface. A missing reply
is outcome-ambiguous and requires reboot rather than retry.

The optional `xart_os_uuid=UUID` option reproduces the immediately following
matched BridgeOS boot-policy step. It allocates the vendor-sized 32 KiB xART
send/receive buffers, registers them for fixed endpoint 16, and submits only
xART command 8 with the canonical UUID's 16 bytes. Matching bridgeOS prefers an
APFS volume-group UUID and otherwise supplies the boot partition UUID. The
installer therefore uses the GPT PARTUUID of the Linux `/boot` partition; it
does not substitute a filesystem or hardware UUID. A missing or error reply
ends that boot generation; neither the command nor its DMA registrations are
retried before reboot. See [`../linux_native/XART_IDENTITY.md`](../linux_native/XART_IDENTITY.md).

The installed transport service blacklists PCI modalias autoload because that
path can run this one-shot sequence before BridgeOS has brought up its xART
master backing. Immediately before one explicit `modprobe`, the root-only
loader dynamically discovers the BiometricKit RemoteXPC port and requires a
BridgeXPC HELO reply. This is a userland-phase readiness discriminator, not a
biometric request or a claim that HELO is the vendor's direct xART event.

`t2-bridgeos-update-query.py` is a separate, read-only continuity tool. It
dynamically discovers `com.apple.bridgeOSUpdated`, sends only
`QueryUpdateState`, and prints a fixed non-identifying subset of the response.
It intentionally has no arbitrary-command, file-transfer, preflight, prepare,
or apply option. The recovered clean-wipe repair boundary is documented in
[`../linux_native/BRIDGEOS_UPDATE_XART_RECOVERY.md`](../linux_native/BRIDGEOS_UPDATE_XART_RECOVERY.md).

`t2-storage-inventory.py` issues only MobileStorage `CopyDevices` after it
verifies the running bridgeOS build. It emits a redacted device summary; raw
device nodes, mount paths, image paths, signatures, and the original response
are never printed.

`t2-bridgeos-recovery.py` is the distinct recovery-transition tool. Its default
mode is read-only: it checks the exact live bridgeOS build and advertised
restoreserviced endpoint. `--execute` sends only lowercase
`{"command":"recovery"}` and is refused unless the named independent USB
observer systemd unit is already active. A missing reply is exit status 3,
outcome-ambiguous, and must never be retried from that result. The static
`t2-recovery-usb-observer` records whether Apple recovery PID `1280` or `1281`
appears and whether its sysfs ancestry is the internal BCE VHCI. No automatic
host-reboot guard is supplied: the reference Mac disables its hardware
watchdog and the first direct-reboot experiment did not establish recovery.

Raw endpoint-0 command `0x22` is retired. D127 proves that the matching Intel
host AppleSEPManager never sends it: the similarly numbered operation is an
internal bridgeOS AppleSEPManager command reached through user-client selector
`0x11`. Matching Apple EFI later corrected D127's inferred `NSMN` route:
Linux writes the typed `EFMV` record, clears `EFMS`, commits
`EFBS = 0x11`, and polls `EFMS` before this PCI transport starts. `NSMN`
is a different generic platform notification. The carried applesmc research
patch implements the exact disabled-by-default EFI transaction. A later
successful capability reply, not a transport-owned status bit, proves that the
versioned SEP apps are available.

The installer requires an applesmc module that exposes the typed publisher,
enables it with the configured SEP epoch, and writes a modprobe soft dependency
so applesmc finishes the one-shot SMC boot-state handoff before
`t2_sep_transport` can bind. The matched bridgeOS epoch defaults to `1.0` in
the example configuration; it is explicit because other firmware may differ.

Direct endpoint-16 command 8 is retired. D123's complete MMIO reply and D124's
import-binding correction prove the x86 PCI endpoint reaches xART's AMDM
commands 2–4, while OS-UUID command 8 belongs to the separately registered
bridgeOS-internal `xars` service. The module therefore has no `xart_os_uuid`
parameter, xART OOL buffers, or publication ioctl. The installer rejects the
legacy UUID and deferred-publication settings rather than silently sending the
wrong command. See
[`../linux_native/XART_IDENTITY.md`](../linux_native/XART_IDENTITY.md).

The installed transport service blacklists PCI modalias autoload because that
path can run this one-shot sequence before BridgeOS has brought up its xART
master backing. Immediately before one explicit `modprobe`, the root-only
loader dynamically discovers the BiometricKit RemoteXPC port and requires a
BridgeXPC HELO reply. This is a userland-phase readiness discriminator, not a
biometric request or a claim that HELO is the vendor's direct xART event.

`t2-bridgeos-update-query.py` is a separate, read-only continuity tool. It
dynamically discovers `com.apple.bridgeOSUpdated`, sends only
`QueryUpdateState`, and prints a fixed non-identifying subset of the response.
It intentionally has no arbitrary-command, file-transfer, preflight, prepare,
or apply option. The recovered clean-wipe repair boundary is documented in
[`../linux_native/BRIDGEOS_UPDATE_XART_RECOVERY.md`](../linux_native/BRIDGEOS_UPDATE_XART_RECOVERY.md).

`t2-storage-inventory.py` issues only MobileStorage `CopyDevices` after it
verifies the running bridgeOS build. It emits a redacted device summary; raw
device nodes, mount paths, image paths, signatures, and the original response
are never printed.

`t2-bridgeos-oslog.py` is the constrained bridgeOS unified-log collector. It
requires an exact build, uses only the trusted sysdiagnose service, disables
log-copy, log-generation, time-sensitive, and UI task classes, and requests
only `system_logs.logarchive`. Output must be an unused absolute path beneath a
root-owned directory with no group/other access. The collector removes the
service's 24-byte stream wrapper, verifies exact size and gzip integrity, and
prints only build, byte count, and digest. Its explicit recovery mode sends
only the recovered `GetInProgressArchive` request and never starts a new
diagnostic.

`t2-bridgeos-recovery.py` is the distinct recovery-transition tool. Its default
mode is read-only: it checks the exact live bridgeOS build and advertised
restoreserviced endpoint. `--execute` sends only lowercase
`{"command":"recovery"}` and is refused unless the named independent USB
observer systemd unit is already active. A missing reply is exit status 3,
outcome-ambiguous, and must never be retried from that result. The static
`t2-recovery-usb-observer` records whether Apple recovery PID `1280` or `1281`
appears and whether its sysfs ancestry is the internal BCE VHCI. No automatic
host-reboot guard is supplied: the reference Mac disables its hardware
watchdog and the first direct-reboot experiment did not establish recovery.

After OOL registration the module also creates `/dev/t2-aks` as a mode-0600
root-only, exclusive-open exchange device. The kernel, rather than userspace, owns header
generation, transaction matching, SHA-256 verification, size bounds, and
request-buffer scrubbing. It accepts only the recovered AppleKeyStore opcodes
`0x03` (load keybag), `0x04` (change lock state), `0x06` (copy one live keybag
UUID), `0x19` (get device state), `0x21` (verify secret with either a 16-byte
ACM context or the bounded password-only diagnostic), and `0x4d`
(capabilities); every other opcode is rejected. Operation `0x21` is
additionally restricted to the recovered codec, session, password, context, and
option layouts. Capability negotiation uses the required v1 header, while
normal operations use the negotiated v2 header and calendar-time extension.

### The `/dev/t2-acm` endpoint-10 device

When endpoint 10 is enabled, `/dev/t2-acm` permits one root/CAP_SYS_ADMIN owner
at a time and leases at most one live context to that open file. Policy and
delete commands must carry that exact context. Closing the file with a live
context performs a kernel-side delete, covering ordinary exit and process
death. A timeout, excess unrelated replies, or an unknowable create result
increments the endpoint generation, marks it poisoned, rejects all later
commands, and requires a reboot; this prevents a late uncorrelated ACM reply
from being mistaken for a later operation. This is still a narrow research
transport, not an enrollment API or a general ACM command device.

## AppleKeyStore commands (`t2-aks-tool`)

The research-only `get-device-state-v1 SESSION HANDLE SELECTOR OUTPUT` command
implements the recovered 24-byte operation-`0x19` codec. Its output can contain
a private Apple account UUID, is created mode `0600`, and must never be
committed or published. Decode only a private copy, redact identifiers in
notes, and remove the raw output when the observation is complete.

`t2_aks_identity_create.py` contains hardware-free versioned codecs for the
operation-`0x01` create body and operation-`0x02` saved-keybag export body.
`t2_aks_provisioning.py` adds their non-retryable journal and atomic private
saved-keybag store. Neither module has a CLI. The kernel has exact request and
response validators and owns one create/export phase per boot: it binds export
to the returned session/handle, blocks all intervening AKS calls, permits one
same-owner UUID read after export, and poisons provisioning after any ambiguous
result or premature close.
`t2_aks_provisioning_operation.py` is the no-CLI broker core: it binds an exact
preflight digest and connection, owns create and export once, wipes all mutable
buffers, commits the saved object, verifies its live UUID, writes a disabled
Linux-owned mapping through `t2_user_mapping_store.py`, and requires a
different-boot load/UUID result before completion. The no-CLI
`t2_aks_provisioning_transport.py` is the concrete narrow ioctl adapter. It
holds one exclusive descriptor across bounded password binding, create,
export, and live UUID verification; it exposes no arbitrary operation method.
Its read-only info ioctl binds userspace to a kernel-generated connection UUID
and attests the actual registration flags, negotiated header version, phase,
poison state, and stable-absence count. The same descriptor must observe two
exact operation-`0x51` absent-primary results with the create session before
the kernel will dispatch create. It must then complete the exact bounded
operation-`0x21` password verification against the kernel's currently active
ACM context; create must carry that identical context.
No installed command enables this path, and the reference system's
`inventory_only=1` boot has not loaded or exercised it.

`t2_user_activation_broker.py` composes the normal-runtime half without a CLI.
It obtains evidence from one connected Unix peer, requires a
separate interactive activation grant when the mapped alias is absent or
locked, and passes the exact policy binding to the journaled operation while
one `AKSActivationTransport` owns the exclusive descriptor. Password storage
is caller-owned and wipeable and is cleared on every exit, including boot-ID
and journal-root failures. A production listener must load mapping and
Catacomb-reconciliation evidence from protected stores rather than accept them
from an IPC request. The old command-per-step scripts are deliberately inert
because closing the load process now unloads its positive handle.
`t2_user_authority.py` supplies that protected input boundary. After E4 it
copies the final immutable enrollment journal under the mapped UID, validates
the copy, and atomically publishes a small manifest bound to the journal head,
reconciliation snapshot, operation UUID, and exact mapping generation. Runtime
load accepts only that root-owned mode-0600 manifest and a post-reboot-verified
journal whose Linux UID, Apple UID, account UUID, bag UUID, and mapping all
match. No caller-selected path or authority field crosses IPC.
The retained, default-disabled `systemd/research/t2-user-activation.socket` accepts one bounded version-1
`SOCK_SEQPACKET` message containing only an optional password. Its per-request
service derives the target from peer credentials, returns only ready,
already-ready, or a generic unavailable result, and wipes both receive and
password buffers. It remains a research integration surface in the source tree;
the product installer does not install or start it, and fprintd does not call it.
The PAM password helper is the user-context activation client; root PAM callers
drop supplementary groups, GID, and UID before connecting. fprintd itself does
not proxy activation because its socket peer would be root. Instead it requires
the activation socket to be available, reloads the protected E4 authority for
each verification, and derives the BiometricKit numeric user from that mapping.
It no longer trusts `T2_TOUCHID_MACOS_USER_ID`. The generic BiometricKit warm-up
also performs no user-scoped inventory.

`t2_aks_identity_create.py` contains hardware-free versioned codecs for the
operation-`0x01` create body and operation-`0x02` saved-keybag export body.
`t2_aks_provisioning.py` adds their non-retryable journal and atomic private
saved-keybag store. The kernel has exact request and
response validators and owns one create/export phase per boot: it binds export
to the returned session/handle, blocks all intervening AKS calls, permits one
same-owner UUID read after export, and poisons provisioning after any ambiguous
result or premature close.

`t2_aks_identity_replacement.py` contains the hardware-free exact 36-byte
operation-`0x49` identity-delete and 32-byte operation-`0x03` UUID-open
recovery codecs. `t2_aks_protocol.h` validates their fixed shapes and explicit
session/UUID bindings. `t2_aks_replacement_transport.py` is the only userspace
adapter that can arm those operations: it owns one exclusive descriptor, has
no arbitrary dispatch method, permits one typed delete or exact UUID recovery,
and wipes its private arm record. The kernel admits this surface only when both
provisioning and the additional default-off `enable_identity_replacement=1`
module parameter are present. Its write-only arm binds one session, old/new
account UUID pair, phase, and—except for recovery—the exact 16-byte creation
material. Delete arming additionally proves those bytes equal the live,
externalized ACM identity-secret context. Create arming on a later boot instead
binds the saved bytes directly and requires two stable absent-primary reads;
this is what keeps a crash after deletion from destroying the only usable
creation input. Each mutation is attempted at most once per module lifetime,
even if the descriptor is closed. UUID recovery is restricted to the armed new
account and any exported keybag remains bound to the kernel-owned recovered
handle. `t2_aks_primary_identity.py` strictly decodes the three-field durable
primary DER dictionary but exposes only the caller-owned `uuid`; `guid` and
`kid` remain private SEP-owned values. The replacement adapter hashes each raw
inventory observation before wiping it. After create, export, and live UUID
verification, the same CREATE arm admits one operation-`0x05` only for the
exact provisioning-owned handle. A successful unload retires that handle
without returning the provisioning state to idle or admitting another create.

`t2_activation_bundle.py` implements the plan-of-record
pending-generation transaction: it durably stages and verifies the 16-byte
creation external form, then publishes that secret, the exported keybag, and
a digest-only manifest with one directory rename. Mapping schema 2 binds both
artifact digests and their exact generation paths; schema 1 remains readable
only as legacy authority.

`t2_aks_replacement_journal.py` is the D171 write-ahead state machine. It
accepts deletion only after the old primary exactly matches the protected D137
account and activation material is durably staged. Delete and create each have
one intent and no retry transition. Lost replies require fresh-boot,
fresh-connection inventory; only the exact new UUID may be reopened. Export is
the only repeatable operation, and only after such a reopen. The terminal
chain binds live UUID, exported digest, complete bundle, disabled mapping, and
owned-handle release without storing secret bytes.

`t2_aks_replacement_operation.py` composes those boundaries into the only
mutation coordinator. It completes stable old-primary inventory before the
caller creates the live ACM context (inventory deliberately clears prior ACM
authorization). While that context remains live, it stages and reopens the
exact activation material before writing delete intent. It records a
successful delete before mandatory stable-absence reconciliation, and arms
create only on that same reconciled owner;
and writes create/export intents before their single dispatches. A lost delete
or create reply is never retried. On a later boot the coordinator classifies
stable primary inventory and may open only the journaled new account UUID,
verify its live bag UUID, and repeat only the read-only export. Bundle writes
converge across safe partial files and a crash after the atomic rename; mapping
commit is idempotent; and either an exact unload reply or a fresh-boot stable
new-primary plus no-handle attestation closes the transaction. Closing a
descriptor with an exported but still-live created handle performs one bounded
exact unload; an already-attempted unload is never repeated before reboot.

`t2_aks_provisioning_operation.py` is the no-CLI broker core: it binds an exact
preflight digest and connection, owns create and export once, wipes all mutable
buffers, commits the saved object, verifies its live UUID, writes a disabled
Linux-owned mapping through `t2_user_mapping_store.py`, and requires a
different-boot load/UUID result before completion. The no-CLI
`t2_aks_provisioning_transport.py` is the concrete narrow ioctl adapter. It
holds one exclusive descriptor across stable-empty inventory, create, export,
and live UUID verification; it exposes no arbitrary operation method.
Its read-only info ioctl binds userspace to a kernel-generated connection UUID
and attests the actual registration flags, negotiated header version, phase,
poison state, and stable-absence count. The same descriptor must observe two
exact operation-`0x51` absent-primary results with the create session before
the kernel will dispatch create. It must then complete the exact bounded
request-10 credential transform: ACM command `0x28` type 5 must succeed on the
currently active context, and create must carry that identical external form.
Operation `0x21` remains the verifier for an already-existing keybag and is
not a greenfield create prerequisite.

`t2-native-provision` is the one-shot installed owner for the first
Linux-owned identity. It reads the credential from a supplied descriptor
without prompting, collects the two-read stable-empty gate, performs the exact
credential-to-ACM transform, records create intent before operation `0x01`,
exports and atomically persists the saved keybag, verifies its live UUID, and
writes only a disabled mapping. A different boot must load the saved object
and reproduce that UUID before the mapping can be enabled.
`t2-native-provision-verify` owns that one-shot reload/UUID comparison and
atomically enables only the exact disabled mapping recorded by the create
journal.
On the reference machine, D137 observed create/export/private persistence and
same-boot UUID equality. D138 loaded the saved object on another boot, proved
UUID equality again, unloaded the positive handle, and enabled only the exact
mapping.

`t2-native-enroll` is the fixed-purpose first-enrollment owner for that enabled
mapping. It rejects the compatibility configuration hash, runtime keybag-env,
and imported Catacomb backup as authorities. It accepts either the original
exact nine-record Linux-native provisioning journal and schema-1 mapping, or
the completed replacement journal, completed independent activation journal,
published activation bundle, original provisioning lineage, and enabled
schema-2 mapping as one fully reconciled authority chain. It then proves a
stable empty live BiometricKit/Catacomb namespace, journal-activates the saved
keybag and derived alias under one AKS descriptor, and retains the same Bridge
lease through ACM policy 1007, event-driven enrollment, and creation of the
initial Linux-owned user/master/biolockout Catacomb generation. For schema 2 it
also reloads and UUID-verifies the keybag, retains that positive handle, and
rebinds the alias. Because a legitimate rebind can return a previously ready
replacement to `device-locked`, the same scope authenticates the persisted
16-byte activation input into a distinct policy-1007 output, sends the original
input through operation `0x18`, requires ready read-back, and supplies the
still-live output context to Mesa. Configuration deliberately precedes ACM
context creation and option `0x21`, matching the exact ordering that produced
the D178 status-zero unlock. Load, bind, configuration, unlock, final
unload, and ready read-back are hash-chain journaled; the legacy schema-1
password binder is unchanged. The credential is accepted only through a
supplied descriptor and all copies are wiped.
`t2-native-enroll-tui-launch` supplies the reference machine's documented test
credential through an inherited descriptor and presents the broker's real
Bridge events in a persistent terminal. It starts one bounded operation
automatically; no Enter is used before or during capture. Contact, release,
accepted progress, and retry prompts are event-driven, and a terminal failure
cannot be restarted in the same screen or boot.
On the isolated reference machine it enters root through one direct
passwordless `sudo -n` exec. It must not issue a preliminary `sudo -v`:
validation forces PAM authentication even when the requested command is
NOPASSWD-authorized and makes launch success depend on a cached timestamp.
The fixed-purpose broker itself owns the volatile runtime boundary: before
opening `/run/t2-touchid/operation.lock`, it creates `/run/t2-touchid` at mode
`0700` when absent and rejects anything other than a private root-owned real
directory. It does not depend on fprintd or biometric-ready service startup to
create that directory.
It also treats the persisted BiometricKit port as a hint, not authority. Both
enrollment and different-boot verification perform one fresh identifier-safe
RemoteXPC discovery under the owned operation lock, require one canonical
dynamic service port, and connect only to that result. This avoids depending on
the disabled biometric-ready service or on a syntactically valid cache left by
an older bridgeOS boot.
The D146 stale-cache failure predates this correction. The later visible
immediate failure left no broker result or process, so the fresh-discovery
implementation has not yet been observed.
`t2-native-enroll-verify` is the separate different-boot owner. It reactivates
the Linux-created keybag for verification, proves the locally persisted and
live identity inventories still match the reconciled enrollment journal,
appends the post-reboot milestone, and atomically publishes runtime authority.
It sends no fingerprint mutation.

D200 exercised that complete path for the first native enrollment. Schema-2
activation reached ready from the persisted creation secret, E4 proved the
same host/SEP identity and E3 Catacomb snapshot on a different boot, the
journal reached `post-reboot-verified`, and runtime authority was published as
`linux-native-e4`.

The automatic native dispatcher also treats E4 proof and host authority
publication as distinct durable states. If an interruption occurs after E4 is
appended, it can publish only the exact unambiguous schema-2 E4 journal under
the operation lock, without repeating activation, inventory, or any hardware
verifier. It refuses a later mutation, a different or invalid existing
authority, and any non-identical temporary publication artifact. Service
failures retain the fprintd gate while reporting only a fixed redacted stage,
exception/cause classes, and a numeric errno or child exit status.

`t2-native-match` consumes only that E4 authority. It retains the schema-2
keybag and creation-secret authorization, passes the live 16-byte ACM context
to the Bridge child through an inherited pipe, restores native Catacomb and
rolling BioLockout state, requires the exact per-user/global identity, and
uses the authenticated 68-byte flags-9 request. Native version-1 results are
accepted only at exact body length `0xc84`; imported version-2 results retain
the `0xc88 + 4*LOTL-count` bound. Both require exact adjacent UID/UUID and a
clear ignored-result bit. Accepted results append updated BioLockout before
cancel and Bridge release. If SEP is ahead after an interrupted accepted
capture, the native path exports, appends, reloads, and validates SEP's secure
record without rolling a later host head back to the E4 seed.

D204 completed the first Linux-native saved-fingerprint match: one exact D200
identity result was accepted, generation 4 was persisted, cleanup completed,
and immutable evidence was sealed.

D206 completed additional Linux-native enrollment. The physical ceremony
proved the D200 finger, proved the candidate distinct, and reached 100 percent.
The version-1 terminal enrollment payload violated the still-conservative
20-byte parser assumption, so no guessed wire identity was accepted. A fresh
stable inventory instead proved exactly one SEP addition over the unchanged
one-finger host baseline. The recovery owner then persisted user, master, and
BioLockout state without recapture and reconciled a two-identity Catacomb. A
same-boot match constrained by that addition journal returned one valid,
host-accepted positive with `matches_required_identity=true`; cleanup, rolling
BioLockout generation 16, and Bridge release all completed.

The version-1 enrollment completion parser now follows the pinned T1Bridge
`7003b8d9f791` minimum-prefix rule without inheriting T1 authority semantics:
the first 20 bytes must validate, while any opaque tail is only a terminal
witness. A fresh, stable T2 global/per-user inventory remains the authority
for the new identity and all existing Catacomb, capacity, persistence, and E3
gates remain mandatory.

For an additional identity, the final constrained match appends
`ADDITION_MATCH_VERIFIED` to the same enrollment journal only after one exact
new-identity result, reconciled two-sided inventory, persisted BioLockout,
clean match cancellation, and Bridge transaction release. This same-boot
`addition-verified` state is terminal and does not incorrectly request the
first-enrollment E4 reboot proof.

`t2-native-match --expect-no-match` is the separate negative-control mode. It
uses the same authority and lifecycle, retries only image-quality no-matches,
stops on the first exact matcher verdict, and exits successfully only for one
valid signed-`-1`, flags-zero matcher no-match. Any positive result is a hard
control failure. D205 proved this with an unenrolled finger and persisted
BioLockout generation 5 before clean cancellation and Bridge release.

The D197 native owner also exposes an explicitly acknowledged
`--recover-observed-identity` mode for one same-boot terminal ambiguity. It
accepts only a fresh stable Bridge inventory containing exactly one built-in
SEP addition over an unchanged host baseline, binds that identity durably, and
finishes Catacomb persistence without starting enrollment again. For a
version-2 first-enrollment baseline only, the absent all-zero Catacomb UUID must
become one present nonzero UUID; established Catacombs retain exact UUID
continuity. D197 used this path to reach E3 after full capture reached 100
percent but the result envelope violated the provisional parser layout.

On the Omarchy reference host, use the focused desktop helper after normal
reconciliation and authorization:

```sh
python3 tools/tui-control.py launch
python3 tools/tui-control.py launch-match
python3 tools/tui-control.py launch-negative
python3 tools/tui-control.py launch-new-finger
```

One dedicated test worker owns the applicable launch. The authorized TUI starts
exactly one bounded child without keyboard input. Enrollment and match use
separate private Kitty sockets; the helper uses an explicit Hyprland instance
and bounded readiness checks.
The launch call returns only after the backend is stably ready for physical
interaction. Do not ask the operator for a separate readiness confirmation,
poll the screen after handoff, or inject keyboard input; the operator follows
the TUI and reports completion.
See [TUI control](../docs/TUI_CONTROL.md) for installation requirements,
read-only status, and failure handling.

`t2-native-provisioning-preflight` is the one-shot read-only reachability gate
for that path. It validates the immutable D124 routing correction, requires
Linux-native authority and a fresh fixed journal, opens the provisioning
transport, and performs only its two stable-empty operation-`0x51`
observations. It closes without ACM authorization, password binding, create,
export, enrollment, or any other mutation. Success or failure is terminal for
that boot. Its exchange path calls libc `ioctl` directly so a signed SEP status
mutated into the exchange structure remains visible when the syscall also
returns `EREMOTEIO`.

`t2_apple_control_discriminator.py` is the narrower imported-state gate. Before
opening the live path, it rehashes the disabled mapping, saved keybag, raw
captures, normalized backup, and committed Catacomb and requires their exact
immutable import provenance. Its one-shot CLI then retains the concrete
exclusive AKS descriptor across one saved-keybag load, the transport's two
operation-`0x06` reads, a private Catacomb UUID comparison, and one same-owner
unload. The fixed journal path prevents replay. Any lost reply becomes
outcome-unknown and forbids retry before reboot. This surface contains no
alias-bind, password, mapping enable, service, PAM, or biometric call.

After that discriminator completes as an exact match, the separate
`t2_apple_control_alias_discriminator.py` validates its full private journal
and requires a different Linux boot and AKS runtime generation. It observes
the derived negative Apple-UID alias first, then—only when absent—loads and
revalidates the saved keybag, binds the alias once, reads UUID/state back,
unloads the positive handle once, and proves the alias persists. Its fixed
journal makes the stage non-replayable. The acknowledgement-gated
`t2-bind-apple-control-alias.py` exposes only redacted booleans and has no
unlock, mapping-promotion, service, PAM, or biometric path.

The direct transport uses libc `ioctl` for AKS exchanges rather than Python's
staging-buffer wrapper. This preserves the kernel-mutated signed SEP status
when the syscall also returns `EREMOTEIO`; operation-`0x06` status `-3` can
therefore be classified as a stable absent alias. One separately journaled
later-boot recovery attempt is admitted only when the first journal validates
as exactly baseline plus outcome-unknown at pre-state, with no handle and no
mutation boundary crossed. The failed journal is retained and bound into the
new baseline; every other prior outcome remains non-replayable.

`t2_apple_control_alias_reconciliation.py` is the read-only closure for an
ambiguous bind whose positive handle was proven released. It independently
validates both prior journals, requires a later boot/runtime, and creates a
third fixed journal. The acknowledgement-gated
`t2-reconcile-apple-control-alias.py` double-reads only the derived alias UUID;
when it matches, it captures the bounded operation-`0x19` blob to a root-only
exclusive file, decodes it, and double-reads UUID again. The transport returns
that diagnostic blob only in mutable storage which the coordinator wipes.
Kernel rejection logs only envelope length, codec version, and declared blob
length. The reconciler has no load, bind, unload, unlock, mapping, service,
PAM, or biometric method.

`t2_apple_control_alias_unlock.py` is the separate later-boot compatibility
discriminator after that proof. It validates the complete immutable journal
and captured state before admitting one device-locked alias observation, one
password unlock intent/dispatch, and one independent alias UUID/state
read-back. Its fixed journal prevents replay, password storage is wiped, and
it cannot load, bind, enable a mapping, start services, change PAM, or request
biometrics. The acknowledgement-gated CLI reads the test password only from
standard input after rejecting same-boot use and an existing journal.

`t2_user_activation_broker.py` composes the normal-runtime half without a CLI.
It obtains evidence from one connected Unix peer, requires a
separate interactive activation grant when the mapped alias is absent or
locked, and passes the exact policy binding to the journaled operation while
one `AKSActivationTransport` owns the exclusive descriptor. Password storage
is caller-owned and wipeable and is cleared on every exit, including boot-ID
and journal-root failures. A production listener must load mapping and
Catacomb-reconciliation evidence from protected stores rather than accept them
from an IPC request. The old command-per-step scripts are deliberately inert
because closing the load process now unloads its positive handle.
`t2_user_authority.py` supplies that protected input boundary. After E4 it
copies the final immutable enrollment journal under the mapped UID, validates
the copy, and atomically publishes a small manifest bound to the journal head,
reconciliation snapshot, operation UUID, and exact mapping generation. Runtime
load accepts only that root-owned mode-0600 manifest and a post-reboot-verified
journal whose Linux UID, Apple UID, account UUID, bag UUID, and mapping all
match. No caller-selected path or authority field crosses IPC.
The retained, default-disabled `systemd/research/t2-user-activation.socket` accepts one bounded version-1
`SOCK_SEQPACKET` message containing only an optional password. Its per-request
service derives the target from peer credentials, returns only ready,
already-ready, or a generic unavailable result, and wipes both receive and
password buffers. It remains a research integration surface in the source tree;
the product installer does not install or start it, and fprintd does not call it.
The PAM password helper is the user-context activation client; root PAM callers
drop supplementary groups, GID, and UID before connecting. fprintd itself does
not proxy activation because its socket peer would be root. Instead it requires
the activation socket to be available, reloads the protected E4 authority for
each verification, and derives the BiometricKit numeric user from that mapping.
It no longer trusts `T2_TOUCHID_MACOS_USER_ID`. The generic BiometricKit warm-up
also performs no user-scoped inventory.

The read-only `copy-keybag-uuid SESSION HANDLE OUTPUT` command implements the
matching kext's exact raw endpoint operation `0x06`: a zero result placeholder,
session `1`, and one nonzero signed handle. The kernel rejects every other
body. Success writes exactly 16 UUID bytes to a newly created mode-0600 file
and never prints the UUID; an absent handle returns exit status 3 and creates
no file. Output paths are no-follow/exclusive and existing files are never
overwritten.

`get-primary-identity SESSION OUTPUT_DER` implements the matching kext's
read-only identity suboperation 0. Its 40-byte body has a nonzero generation
session, two `-1` selectors, and three empty blobs. The kernel rejects all
other command-`0x51` shapes because suboperations 1 and 2 transfer primary
state. Absence returns exit status 3 without creating a file; success writes
the private DER dictionary to a new mode-0600 file. In `inventory_only=1`
module mode, this exact request is the only admitted endpoint-7 ioctl, and the
module refuses xART publication, ACM registration, or capability probing.

`get-primary-identity SESSION OUTPUT_DER` implements the matching kext's
read-only identity suboperation 0. Its 36-byte body has a nonzero generation
session, two `-1` selectors, and two empty input blobs. The kernel rejects all
other command-`0x51` shapes because suboperations 1 and 2 transfer primary
state. Absence returns exit status 3 without creating a file; success writes
the private DER dictionary to a new mode-0600 file. In `inventory_only=1`
module mode, this exact request is the only admitted endpoint-7 ioctl, and the
module refuses xART publication, ACM registration, or capability probing.

Operation `0x21` codec v1 contains the password and optional ACM
external-context blobs followed by one 64-bit device-options value. Exact
selector `42` supplies plaintext-secret option `0x200`; the kernel accepts only
that canonical value. Memento and structured-credential variants are not
exposed by this research interface. Endpoint-7 mailbox failures are returned to
the root-only caller as a signed SEP status in the fixed-size ioctl record, so
diagnostics do not depend on scraping the kernel log.

`verify-password-only SESSION HANDLE` emits the same recovered codec with a
zero-length external-context blob. It is deliberately restricted to a nonzero
handle, session `1`, a nonempty bounded password, and option `0x200`. This
stage-isolation diagnostic has passed on the proven machine with SEP status
zero and the expected 12-byte response, proving password/keybag verification
before ACM attachment. It does not enroll, delete, or evaluate an ACM policy.

## ACM authorization research

`t2-acm-authorize-test` is the installed wrapper for these paths. Its
`--diagnostic-password-only` mode runs the `verify-password-only` stage
isolation above: it selects the known positive runtime keybag, creates and
attaches no ACM context, and requires a narrow acknowledgement:

```sh
sudo t2-acm-authorize-test --diagnostic-password-only \
  --acknowledge-password-verification
```

The wrapper refuses direct-root and cross-user invocation: `SUDO_UID` or
`PKEXEC_UID` must resolve to the single Linux account in the protected mapping,
and the Apple UID and special bag are always read from that root-owned mapping.
This is an explicit research authorization boundary; a dedicated production
PolicyKit action is still required before any enrollment API is exposed.

The internal `with_authorized_context` broker primitive holds the exclusive
device lease across context creation, policy preflight, explicit command-`0x13`
externalization, password binding, final policy-1007 evaluation, one trusted
consumer callback, and mandatory deletion. The callback is invoked only after
policy success and before deletion; callback failure still takes the same
cleanup path, and asynchronous consumers are rejected so work cannot escape the
context lifetime. No command-line option exposes the context bytes, and the
current diagnostic supplies a no-mutation consumer. This entire producer path
has passed on hardware: the initial type-1 requirement was satisfied, policy
1007 became true, and deletion/reconciliation succeeded without performing a
fingerprint mutation.

## Verification and the fprintd facade

These modules back the installed, exposed verification path.

### fprint projection and presentation

`t2_fprint_projection.py` defines the presentation boundary needed to replace
legacy labels with durable neutral handles. It accepts only the exact
reconciled public inventory and projects every T2 identity onto one unique
`finger-N` handle. Legacy labels, unknown labels, or duplicates produce no
partial list and require explicit migration. Handles remain presentation and
management metadata; mutation brokers must resolve them to private identity
authority again under a fresh operation lock.
The installed, no-argument `t2-touchid-fprint-status` command feeds it only the
existing root-only fresh reconciled identity collector and prints the redacted
projection. It is diagnostic-only and cannot rename, enroll, or delete.

`t2_fprint_runtime.py` defines the projection policy without performing I/O. It
strictly parses only the redacted projection schema. A complete projection
lists all neutral handles. `any` and an existing numbered request both become
an all-identities match; the numbered value only proves that the client's
presentation handle exists in the supplied projection. The facade may consume
the same caller’s list projection once for the next verification and coalesce
only currently running inventory reads. Native authority is independently
reconciled for every match. It resolves success to the actual neutral
`VerifyFingerMatched` handle. After returning `VerifyStart`, it emits
`VerifyFingerSelected("any")` on `match_armed`, so the placement prompt reflects
reader readiness and never claims a particular physical finger is required. Pre-match reconciliation and
post-match unchanged-state attestation remain mandatory.

### Identity-resolution authority

`t2_fprint_match_selection.py` is the private identity-resolution half of the
neutral listing. It accepts a strictly decoded user Catacomb and one exact
tuple of live 20-byte per-user identity records, requires complete unique
handles and exact UUID-set agreement, then returns exactly one opaque record
for diagnostics and identity-specific mutation checks. Public fprintd
authentication does not use this selector to narrow acceptance: any enrolled
identity can unlock. Record order is not authority and no UUID, Apple user, or
raw record appears in its public proof.

`t2_fprint_match_gate.py` wraps that selector in a read-only diagnostic match
boundary. The public facade instead uses
`--resolve-any-finger-name`: it retains all reconciled identities and reduces a
successful event to exactly one neutral presentation handle. Before and after
matching, the probe requires exact repeated per-user/global SEP inventories and
equality with the committed local Catacomb. Zero matched identities is a normal
negative result; more than one is ambiguous and fails closed. Public
attestations contain only booleans and the neutral handle—never Apple user IDs,
identity UUIDs, or Catacomb contents.

### Caller ownership

`t2_dbus_sender.py`, `t2_dbus_identity.py`, and `t2_fprint_claim.py` close the
caller-ownership gap in the fprint facade. The dispatch wrapper preserves the
immutable system-bus unique sender; `GetConnectionCredentials` supplies a
kernel pidfd, PID, and UID; and the claim joins that process to a protected
local-account generation and active physical logind session. Every claim-scoped
call revalidates all three layers. A root PAM client is accepted only when its
process has either stable all-root credentials or the exact setuid-PAM shape
`real=user; effective=saved=filesystem=root`. The latter shape pins the
originating real UID as part of the immutable process subject; any UID
transition invalidates the claim. It may use the unique active-local-session
fallback only for that pinned real UID because sudo's PAM helper is not itself
registered with logind. An all-root process still requires a direct
pidfd-to-session binding and cannot use that fallback. `NameOwnerChanged`
cancels active work, closes the pidfd, and releases the claim. The username
remains presentation input, never authority by itself.

A claim may derive a fresh `AuthorizationSession` using an independently owned
duplicate pidfd only when the D-Bus caller UID is the claimed UID and the
caller is not a setuid-root PAM process. Its account and session must equal the
original claim snapshot. Privileged PAM clients are thus verification-only;
they cannot become self-service mutation callers. This bridge is internal.
`t2_fprint_broker.py` passes the derived session into the existing joined
broker through an exclusive non-socket authorization source, allows only
enrollment or identity management, forces mutation policy on, and closes the
session on every exit. Its authority includes a fail-closed closure that
repeats caller, protected mapping, keybag digest, runtime generation, and
grant-expiry checks immediately before a mutation dispatch. No fprint D-Bus
mutation method consumes it yet.

### Adaptive template persistence

The normal daemon also supports default-off automatic adaptive-template
persistence through `T2_TOUCHID_AUTO_SYNC_ADAPTIVE=1`. Only an already-emitted
successful match schedules the static systemd oneshot; negative and unknown
verdicts do not. The oneshot invokes the same typed, blocking
`sync-user-catacomb` journal and exact Apple user-then-master save order, so
authentication never waits for or inherits a persistence result.

## Identity management

`t2-touchid-identities` is the privacy-safe identity-management inventory. It
joins the strict committed user Catacomb with a stable live per-user/global SEP
inventory under the operation lock and emits only numbered slots and local
labels. It fails closed on any local/live divergence and never exposes UUIDs.

The `t2-touchid-manage` rename path resolves one slot only after that
reconciliation gate, proves its strict archive rewrite changes only the
selected label, and binds an operation-fresh SEP secure envelope. Its typed
journal permits exactly one user Catacomb component and records prepare,
complete, host-stage, commit, confirm, read-back, and post-reboot phases. Every
post-dispatch fault becomes outcome-unknown. Its recovery broker records a
direction before touching the local transaction, discards only a validated
pre-boundary `prepare/`, rolls forward only a complete journal-bound `commit/`,
and never replays a SEP mutation. Fresh stable host/SEP read-back must classify
the result uniquely as unchanged or committed; a committed recovery still
requires post-reboot proof.

The independent rename read-back additionally requires the identity set,
account/keybag binding, master enrollment count, component ownership/modes, and
unrelated master/bio-lockout hashes to remain unchanged. The committed user
archive must equal the strict rename plan, the live per-user/global sets must
equal it, and both the selected-user and master SEP Catacomb states must be
clean before the journal can reach `reconciled`. The post-reboot verifier
additionally requires a different Linux boot and Bridge connection, the exact
journaled user-component hash and label, unchanged account/keybag/master and
unrelated component state, exact local/live identity equality, and clean
selected-user/master SEP state.

The `t2-touchid-manage delete` path is a separately acknowledged,
single-identity-only broker. It resolves an ephemeral slot against a stable
reconciled inventory and durably binds the exact 20-byte UID+UUID command-`0x0d`
request. The command's return status
is never sufficient evidence: a stable same-connection per-user/global
inventory must prove either exact target absence or, after a failed command, an
exact unchanged baseline. Proven absence is followed by a user-component only
Catacomb save, independent read-back, and stable local/per-user/global
reconciliation on the owned connection. That is the terminal deletion
boundary; an optional later cross-boot observation does not block another
mutation. The
companion `plan-delete --slot N` runs the same reconciled target planner but
does not create a journal, dispatch `0x0d`, or write a Catacomb component. It
reports only the selected label and before/after counts.

Deletion recovery never replays command `0x0d`. It records the local
transaction direction before resolving it and uses a fresh Bridge generation to
classify state as exact no-change, exact committed survivors, or an unconfirmed
SEP deletion requiring forward persistence. The forward path can rebind either
the exact baseline archive or an exact journaled survivor archive, resets
persistence onto the fresh lease, and cannot claim rollback. Ambiguous states
stay `outcome-unknown`. A verified final-identity operation admits only the
observed dirty-absent and clean-absent zero-identity Catacomb states. Batch
delete-all, whole-user deletion, and cross-user mutation are not implemented.

## Enrollment core

The layered enrollment implementation behind `t2-touchid-enroll`. Each layer is
separately testable and refuses to act without the layer beneath it.

### Protocol, journal, and operation

`t2_enrollment_protocol.py` is the transport-independent protocol layer. It
builds only the exact mode-0, 16-byte ACM enrollment request, keeps that
request in wipeable operation-local storage, parses the two-level service
envelope, and implements conservative progress, feedback, cancellation,
terminal-result, connection-generation, and duplicate-event rules. A terminal
SEP identity is only provisional; the state machine deliberately has no
`completed` state because durable Catacomb persistence and stable read-back are
still required. The module opens no device or socket and is not installed as a
command.

`t2_enrollment_journal.py` adds typed E0/E1/E2/E3 ordering above the generic
durable journal. It permits start, continue, cancellation, terminal identity,
terminal failure, stable identity read-back, reconciliation, and
outcome-unknown records only in their recovered order; every append uses an
atomic expected-head check. Before E1 it requires the same Linux boot,
protected mapping, caller/target pair, protocol, capacity, and exact Bridge
connection generation as E0. Consequently the standalone `t2-touchid-baseline`
command remains evidence collection only: it closes its inventory connection
and reports `same_connection_enrollment_ready: false`. An outcome-unknown
attempt may cross the distinct `E3_RECOVERY_NO_CHANGE_RECONCILED` transition
only on a fresh Bridge generation whose stable host/SEP read-back proves
identity, capacity, Catacomb, and binding state are all unchanged.

`t2_enrollment_operation.py` composes those two pure layers into a synchronous
E1/E2 operation core. It requires a same-connection E0 journal, accepts only an
injected transport interface, durably records start/continue/cancel intent
before dispatch, records observations afterward, wipes the authorization
request, and converts transport, protocol, or post-dispatch journal ambiguity
into `ENROLL_OUTCOME_UNKNOWN`. It must run inside the `with_authorized_context`
callback and stops at a provisional identity or reconciliation-required
failure. No BridgeXPC implementation or command-line entry point is supplied,
so this still cannot start enrollment on hardware.

### Bridge adapter and inventory

`t2_enrollment_bridge.py` supplies the first concrete boundary beneath that
operation core without opening a socket. It accepts only an already-open,
exclusive Bridge lease whose canonical connection-generation UUID matches E0;
emits exact start `0x03`, continue `0x0e`, and cancel `0x0c` commands;
validates and queues the recovered five-item service callbacks; and requires
empty command output. Zero-capacity commands accept the equivalent Bridge
encodings `[status]`, `[status, null]`, `[status, empty-data]`, and the one
exact fixed `bkremoted` nil-output placeholder; every other string and any
nonempty data are still rejected. A generation change, malformed reply/event,
disconnect, or nonzero authoritative start/cancel reply permanently poisons or
rejects the operation. Exact 24G830 discards the numeric `enrollContinue`
return, so a well-formed matching continue reply queues its interleaved service
events and journals that return as non-authoritative. It composes with the
journaled enrollment core in tests, but no live lease,
baseline-to-authorization coordinator, or enrollment CLI is exposed.

`t2_bridge_wire.py` holds the shared BridgeXPC framing used by both the
read-only probe and the enrollment path. `t2_bridge_connection.py` owns one
initialized socket, negotiates the matching API-v2 client contract, assigns one
canonical generation UUID, acknowledges synchronous and asynchronous service
callbacks, rejects reentrant use, and closes permanently on transport
ambiguity. The existing probe uses the same wire implementation.

`t2_bridge_inventory.py` double-collects the complete E0 inventory on that
owned connection and validates protocol, global/per-user identity agreement,
capacity, Catacomb metadata, SKS state, and exact snapshot equality. Any
dispatched but untrustworthy collection invalidates the generation.
`t2_enrollment_coordinator.py` then composes this E0, the typed journal, the
live-scoped ACM callback, the enrollment Bridge adapter, and a mandatory
injected finalizer without releasing the socket. A provisional identity cannot
be reported as complete unless the finalizer attests both persistence readiness
and same-generation reconciliation; finalizer ambiguity invalidates Bridge and
still triggers ACM deletion. These modules have no CLI and cannot initiate
enrollment by themselves.

### Catacomb persistence

`t2_mesa_enrollment_preparation.py` owns the final same-generation gate before
native enrollment start. It performs the T2 readiness-gated sensor reset,
sensor-info read, conditional bridgeOS FDR/EEPROM calibration load, and
calibration readback. Calibration command `0x20` alone admits the exact observed
version-1 status-80/status-94 empty notifications and status 64 with 36 detail
bytes; every other preparation command remains limited to exact SKS-lock
events. It invokes T2's no-Catacomb command only for a genuinely empty user;
established users retain their loaded identity set. It then adapts the working
T1 preparation order: bounded Catacomb refresh, exact expected identity count,
second stable refresh, and protected system/user policy reads. It performs no
user rebind or policy write; malformed, changing, nonsecure, count-mismatched,
or disabled state invalidates the lease before command `0x03`.

`t2_enrollment_persistence_journal.py` makes the recovered persistence ordering
mandatory after a provisional identity. An immutable plan contains exactly a
user-then-master primary batch followed by one separate bio-lockout batch. A
terminal failure instead permits exactly one bio-lockout-only refresh batch.
For every component it requires prepare intent/result, complete intent and
secure-blob digest, and host-stage digest. Non-final components must be
confirmed before advancing; the final component requires a separately journaled
host-batch commit before final confirm. Only a matching stable SEP/host
generation and independent archive read-back can reach `persistence-ready`. The
journal stores lengths and hashes, never secure bytes.

`t2_enrollment_persistence_operation.py` composes that journal with injected
prepare/complete/confirm, archive-encoder, host-store, and stable-read-back
interfaces. Intent is synced before every external dispatch, each component is
durably staged in protocol order, the host batch crosses its commit boundary
before the final SEP confirm, and secure/archive bytearrays are wiped on every
exit. A transport, codec, store, journal, or read-back ambiguity after SEP
dispatch becomes `CATACOMB_PERSISTENCE_OUTCOME_UNKNOWN`. Tests use only fake
transport and temporary Catacomb copies; no live adapter or command exists. The
Linux-local store makes its recovery direction durable with stricter fsync
ordering than the minimum host sequence: it syncs the root immediately after
`prepare/` becomes `commit/`, then syncs both the source `commit/` directory
and the destination root after every cross-directory component promotion. A
real forked child exits at the commit boundary in the test suite; a fresh store
instance proves that recovery rolls the transaction forward to the complete new
generation. An interrupted partial `prepare/` is rollback-only and may be
discarded only when every present component is schema-valid and belongs to the
journaled batch; a `commit/` can roll forward only when the journal contains a
validated digest for every planned component and a durable batch-commit intent.

`t2_catacomb_protocol.py` captures the exact non-sending command boundary
recovered from the matching daemon: prepare `0x3d` returns one 32-bit expected
secure-blob length, complete `0x3e` must return exactly that many bytes, and
confirm `0x3f` returns no payload. Every command carries the component
descriptor unchanged (4 bytes for protocol v1, 24 bytes for v2). The v2 value
is decoded exactly as `userID:u32 + groupType:u32 + groupUUID[16]`; typed
constructors distinguish canonical user, master, and group components. The same
module parses exact `0x3c` 8-byte user-state and `0x50` 28-byte group-state
records and derives a built-in enrollment save list only when the selected user
is the sole dirty non-master component, always placing master last. The pure
builders/parsers reject nonzero status, malformed descriptors, zero or
unbounded sizes, length drift, immutable complete buffers, and unexpected
confirm output. They do not open BridgeXPC or expose a command.

`t2_catacomb_bridge.py` is the bounded user/master composition layer. Its
caller must inject an already-open exclusive Bridge lease; this module creates
no socket and has no CLI. It pins one canonical connection-generation UUID,
requires an exact two-item `[status, data]` reply with no service events, and
drives only `idle -> prepared -> completed -> confirmed`. A disconnect,
generation change, malformed reply, capacity violation, nonzero command status,
or unexpected event permanently poisons the adapter, so an ambiguous component
cannot be retried. The complete blob is converted immediately to a wipeable
`bytearray`. Integration tests compose this adapter with the typed persistence
journal and crash-safe host store; malformed complete output becomes durable
`CATACOMB_PERSISTENCE_OUTCOME_UNKNOWN`.

`t2-catacomb-fixture-check` performs the separate offline archive-compatibility
gate. It accepts only a private regular archive, extracts no filesystem paths,
strictly decodes the captured user/master/bio-lockout component set, neutrally
re-emits each component, and requires a second independent semantic reader to
agree. Its JSON output contains counts and booleans only. It never changes the
archive or writes to a macOS Catacomb location.

### Reconciliation and finalization

`t2_enrollment_reconciliation.py` is the pure E3 classifier. It accepts only a
stable same-generation SEP inventory and a strict host Catacomb read-back,
requires the mapping, account, bag, existing identities, entity numbers,
component metadata, and Catacomb UUID to remain bound, and permits exactly one
new identity. A provisional identity reaches E3 only after the typed journal
has replayed every persistence milestone and its reconciliation-snapshot digest
matches the classifier's stable read-back. A terminal failure with no
persistence reconciles only to a byte-for-byte unchanged persistent state; the
concrete finalizer's bio-lockout-only path instead permits only that component
to refresh. If stable read-back reveals a new UUID despite failure, the journal
first promotes it to a provisional E2 identity. An outcome-unknown start can be
closed only as no-change recovery on a fresh generation; a new identity instead
refuses automatic recovery. These modules perform no I/O and no persistence
themselves.

`t2_enrollment_finalizer.py` is the concrete no-CLI producer. It derives the
post-E2 built-in save list on the owned connection, composes the strict
user/master encoders with the separate bio-lockout export, commits both batches
through `CatacombStore`, performs stable same-generation SEP and independent
local archive read-back, and appends E3 only when the snapshot digest agrees. A
real-codec end-to-end test reaches E3; malformed bio-lockout output or an
injected read-back disconnect after commit is durably outcome-unknown. Hardware
enrollment is exposed only through a privileged, explicitly acknowledged
broker.

### The `t2-touchid-enroll` frontend

`t2-touchid-enroll` is the stable subcommand frontend for that experimental
broker. It maps `status`, `preflight`, `start`, `verify-post-reboot`, and the
three typed recovery commands directly to the existing fail-closed engine;
`list` directly invokes the reconciled, UUID-redacting identity command. It
does not duplicate protocol or mutation logic. `t2-touchid-enroll-test.py`
remains the installed compatibility backend. Its `--preflight-only` cannot
enter ACM or enrollment; it verifies the sole protected backup, private local
store, sensor readiness, operation lock, same-connection E0, and capacity. The
original macOS archive remains an immutable recovery anchor, not a frozen copy
of current state: after a successful mutation, later preflight/enrollment
decodes the complete local Catacomb as the current host baseline, requires its
account and keybag bindings to remain equal to the protected backup, and then
requires that current identity set to equal stable SEP inventory. This permits
subsequent enrollments without accepting binding drift or overwriting advanced
state with the older archive. `--status-only` does not warm hardware or
provision the store; under the same operation lock it reports only redacted
unfinished-phase counts, whether live enrollment is blocked, whether exactly
one outcome-unknown journal is a candidate for no-change recovery, whether a
local Catacomb transaction is pending and recoverable, and whether one
successful E3 awaits E4. Recovery refuses any mixed set of unfinished journals.
The read-only `--verify-post-reboot` mode opens the existing mutated Catacomb
without selecting or restoring the original backup, collects stable host/SEP
state on the new boot, and appends E4 only when the exact E3 digest is
reproduced. A pending E4 blocks another enrollment so later mutations cannot
invalidate its snapshot. The non-live `--recover-local-transaction` mode
handles exactly one journal-bound interruption in the persistence phase. It
durably records an outcome-unknown direction before touching files, then either
discards a validated partial `prepare/` or rolls a complete `commit/` forward.
Re-running it after a process crash continues the already-recorded direction
rather than creating a second transition. The resulting ambiguous biometric
outcome must then pass the normal fresh-generation
`--reconcile-outcome-unknown` proof before another live run. The live branch
additionally requires explicit live-fingerprint and local-store mutation
acknowledgements, derives all security subjects from protected runtime state,
retains one Bridge lease through E3, and provides cancellation/audio feedback.
Immediately before live dispatch it acquires and verifies a block-mode systemd
sleep inhibitor; failure to acquire it aborts without entering ACM or
enrollment. The authorized consumer checks the actual logind inhibitor registry
again immediately before writing start intent or dispatching the first
enrollment command; a merely live helper process is insufficient. If the
inhibitor disappears or cancellation arrives while password authorization is in
progress, a typed `aborted-before-start` record with `mutation_possible=false`
is synced and neither enrollment transport nor finalization runs. The inhibitor
is held by a parent-owned pipe, so normal exit or broker death releases it,
while SIGINT, SIGTERM, and SIGHUP request the typed cancellation path.
User-facing summaries omit internal operation and identity UUIDs. Progress and
retry guidance is best-effort: a closed terminal or unavailable desktop
notification service cannot alter the biometric outcome, and handled live-path
errors still emit the terminal failure cue.

The typed journal also defines `E4_POST_REBOOT_VERIFIED` for a successful
identity. It is accepted only after E3, on both a different Linux boot UUID and
a different Bridge connection generation, with an exact match to the E3
snapshot digest (which includes account and bag bindings), protected mapping,
identity UUID, and protocol. Double collection, host/SEP equality, binding
checks, and keybag runtime revalidation must all be literal true. The broker
supplies the collector but never initiates the required reboot.

### Live run history

This is a chronological record of the approved live runs on the proven machine
and the adapter changes each one forced. It is history, not a description of
current behaviour; the sections above describe the code as it stands.

The preflight has passed on the target hardware. Five explicitly approved live
runs reached password-bound E1, then conservatively stopped outcome-unknown
while the adapter learned the real Bridge reply/event variants; fresh stable
read-back after each proved no identity or Catacomb delta. The second run
exposed a fixed 36-character placeholder. Exact `bkremoted` disassembly proves
that this constant is substituted for a nil Objective-C output, and a
non-mutating reset command on the target matched it without disclosing the
value. The adapter now accepts only that exact constant in addition to
omitted/null/empty-data encodings. The third run then recorded a successful
start before the event parser rejected a normal status message. A non-mutating
match/cancel control proved the common header's final qword is a monotonic
timestamp; the actual 32-bit status begins at byte 24, followed by padding and
a 64-bit detail length. The parser now uses that status and the timestamp as
its ordering key. `--reconcile-outcome-unknown` records no-change proof without
issuing enrollment or persistence. The fourth run crossed the corrected common
parser and stopped on another service envelope. The exact non-mutating control
already proves type `0xe3ff8004` statistics share this stream during normal
operations, so the reducer now ignores only version-1 statistics meeting the
daemon's 12-byte minimum without feedback or state advancement; all other
non-enrollment types remained fail-closed and are reported numerically. The
fifth run then exposed version-1 `0xe3ff800a`. Exact matching-daemon
disassembly requires at least a 32-bit user ID plus 16-bit SKS state. Depending
on the state bits, the daemon can synchronize the template list, save the
bio-lockout record, cancel a tokenless unlock match, notify observers, and emit
analytics. None of those callbacks is an enrollment transition. A later live
run proved its embedded user can differ from the active enrollment user,
matching the daemon's behavior of routing the ambient record by its own user
field. The reducer therefore validates the exact version and minimum shape but
never lets the event select an identity, send feedback, or send continue; the
finalizer owns persistence for the enrolled user. Live enrollment refuses to
start while an earlier mutation journal remains unfinished. The first complete
Linux enrollment reached E3, survived reboot/E4, appeared as a second
reconciled local/SEP identity, and matched independently through fprintd. Any
next live attempt remains explicitly operator-gated.

## Native fprint enrollment and deletion (staged)

The research gates described here remain separate from the installed service,
which enables both worker clients. Current installed completion, authorization,
and deletion recovery are specified in
[FPRINT_INTEGRATION.md](../docs/FPRINT_INTEGRATION.md).

The fprint enrollment consumer treats the canonical projection above as a
mutation boundary as well as presentation. Under the worker's owned operation
lock and Bridge generation, it requires the broker's fresh reconciled
projection to be complete and the requested canonical name to be absent before
recovery anchoring, ACM, journal creation, or enrollment dispatch. An earlier
facade check is never accepted as authority across the worker handoff.

`t2_fprint_activation_gate.py` and the installed
`t2-touchid-fprint-enrollment-gate` compose only redacted, read-only readiness
evidence for the uninstalled native-enrollment and combined identity-management
drop-ins. The gate requires exact core health, current module/DKMS, AKS alias
observation, an enabled protected mapping, a complete canonical projection, no
blocking enrollment or identity-management journal, an effective default-off
daemon, and explicit prior-live-control attestations. It reports readiness
only; it cannot stage a unit or invoke enrollment or deletion.

`t2_fprint_enrollment_runtime.py` is the pure status boundary for that
enrollment consumer. It translates accepted increasing progress and retry
guidance only to documented fprint statuses, suppresses duplicate progress, and
refuses to emit `enroll-completed` until the coordinator proves policy,
persistence, and reconciliation. The facade exposes fprint's complete
historical property set via both `Get` and `GetAll`; the unproven stage count
remains `-1`.

`t2_fprint_enrollment_controller.py` keeps one synchronous worker off the D-Bus
event loop and sends translated updates back to that loop in order. Its
stop/release path is cooperative: it sets the existing cancellation predicate
and waits for the journaled worker result. Even task cancellation cannot kill
the worker thread or trigger command replay. This controller is hardware-free
until the credential worker and D-Bus handoff are attached.

`t2_recovery_anchor.py` materializes a genuine immutable pre-mutation tar from
the already-validated Linux-local Catacomb. It publishes by exclusive hard
link, fsyncs the private directory, validates the archive through the baseline
parser, rereads the store, and never overwrites a different operation anchor.
`LiveUserReconciliationSession.prepare_enrollment_material` exposes that anchor
and the exact broker-held Bridge lease only after repeated stable
reconciliation and an unchanged protected account/keybag binding.

`t2_fprint_enrollment_consumer.py` composes those inputs with the existing ACM
coordinator, journal, built-in finalizer, canonical finger label, feedback, and
cooperative cancellation.

`t2_fprint_worker_protocol.py` is the bounded Unix-seqpacket boundary around
that consumer. One canonical start packet carries a canonical finger name and
the original protected account/session evidence alongside exactly one
SCM-transferred pidfd. The receiver independently validates the descriptor,
PID, UID, and start time. Subsequent packets are identifier-free progress or
one exact cancellation. `t2_fprint_worker_launcher.py` binds the private
socket, authenticates the accepted process against its exact transient systemd
unit, and supplies the encrypted credential only through
`LoadCredentialEncrypted`. Its argv contains only the operation socket path.

`t2_system_credential.py` validates the compatibility mode's service-scoped
credential and runtime keybag state, proves password fallback through
`verify-password-only-stdin`, and binds ACM through the new
`verify-password-acm-stdin` command. Mutable password buffers are wiped and tool
output is suppressed. `t2_fprint_worker` reconstructs the pinned authorization
session; its compatibility branch requires an enabled
host-encrypted-credential mapping, while its Linux-native branch uses E4
activation without a credential. A dedicated listener converts cancellation or
peer loss into cooperative reconciliation. `t2_fprint_worker_client.py`
supplies the installed async facade lifecycle and waits for a terminal update.

`t2_fprint_deletion_runtime.py` is the typed success boundary for single-name
deletion. The source fprint facade accepts an injected deletion client only
after the exact claim, operation exclusivity, fresh complete projection, named
enrollment, and survivor-count checks pass. `t2_fprint_delete_worker_*` provide
a separate credential-free transient worker, pidfd-bound request protocol,
exact `delete-one` broker consumer, and reconciliation-only response. The
worker repeats canonical-name resolution inside its lock-held private local/SEP
snapshot, freezes an immutable recovery anchor, and shares the CLI's
persistence/read-back tail. Peer loss cannot cancel or replay a handed-off
deletion. The installed daemon injects this client through the explicit
`--enable-native-deletion` process flag; both bulk-delete methods stay
fail-closed.

`t2_post_reboot_reconciler.py` supplies automatic enrollment E4 plus completed
rename and single-delete proof without loading the encrypted password
credential. The oneshot is ordered after keybag unlock and BiometricKit
readiness but before fprintd. It accepts exactly one eligible journal, holds
the protected mapping and operation locks, rechecks the Linux account and
keybag, binds both AKS handles to the mapped account/bag, reproduces stable
local and SEP state on a fresh boot/generation, and appends only the journal's
typed post-reboot record. There is no enrollment, rename, delete, or
Catacomb-persistence dispatch in this process. D-Bus `EnrollStart` is connected;
installed negative controls and a standard-client live proof remain release
gates.

The `FprintDevice` adapter is complete and connected: its enrollment client
receives the exact pinned caller and claim, while status,
finger-present/needed properties, cancellation, release, sender departure,
operation exclusion, and terminal grace expiry follow the standard fprint
lifecycle. The installed systemd unit supplies both
`--enable-native-enrollment` and `--enable-native-deletion`; each path still
fails closed unless its authority, worker, and journal controls pass. The old
research drop-ins are retained only as historical staging artifacts.

## Multi-user policy and broker (non-exposed)

The mapped-user broker is not exposed by the installed service. Its internal
components and authorization boundaries are described below; they do not enable
multi-user Touch ID.

### Mapping, account evidence, and administration

`t2_user_mapping.py` is the first non-exposed multi-user policy boundary. It
strictly parses a root-owned mode-0600 JSON file through a no-follow
descriptor, hashes the exact bytes as the mapping generation, and rejects
duplicate keys, unknown fields, ambiguous UID/account/bag/keybag ownership,
unsafe paths, and implicit capabilities. Each record targets an
already-provisioned Apple user; it cannot create an account, keybag, persona,
or biometric container. Its resolver checks only target mapping and capability.
Authenticated-caller and delegation policy remain separate from the file
parser.

`t2_linux_account.py` supplies the caller account generation. It supports a
strict local-files profile only: one numeric UID must have one root-owned local
passwd row, NSS must resolve the same complete record, the matching
root-private shadow row must remain usable, and the home path must open without
following its final component to a UID-owned directory. The generation commits
to the exact passwd database epoch and bytes, the target passwd/shadow records,
and the home filesystem-ID/inode/birth-time object. It excludes the boot-local
statx mount ID so an unchanged account survives reboot. The IPC join collects
it before and after PolicyKit. No username or digest comes from the request,
and no shadow data appears in returned or redacted evidence. A passwd
rewrite—even for another account—is deliberately fail-closed and requires
administrator re-attestation; LDAP and systemd-homed are not silently
approximated.

`t2_user_mapping_admin.py` is the only writer for the canonical
`/var/lib/t2-touchid/users.json`. It anchors all opens to a validated
root-owned directory, serializes writers with a private `flock`, hashes the
canonical root-private per-UID keybag twice, and repeats live account evidence
before publish. Initial publication uses Linux `renameat2(RENAME_NOREPLACE)`;
updates require the exact generation loaded under the lock and use a
same-directory atomic rename. File and directory fsync plus exact protected
read-back close the normal crash window. A pre-publish failure cleans its
temporary file; a post-rename sync/read-back failure remains an explicit
outcome to inspect with `status`, never a reason to repeat blindly.

The installed `t2-touchid-user-map` exposes `bind-current-disabled`,
`rebind-disabled`, unconditional `disable`, redacted `status`, and the separate
`enable-reconciled` transaction. The administrator mutations require long-form
acknowledgements, derive rather than accept the account/keybag digests, and
always publish the selected record disabled. Rebinding preserves every Apple,
keybag, mode, and capability field but still disables a previously enabled
record. Revocation requires no live hardware or account evidence, so loss of a
dependency can never prevent an administrator from disabling authority.

`t2-native-authority-rebind` handles a complete authority copied from another
Linux installation without rewriting `users.json` or its enrollment lineage.
It validates the imported E4 authority, derives the current strict local-files
account generation, and publishes a root-private per-UID migration record. The
account collector accepts the prior generation only while that record matches
the exact current account and the complete native authority still validates.

`t2_current_user_authority.py` removes Apple UID/account UUID/bag UUID values
from the public mapping command line. It reads one exact configured Apple user
and matching negative alias from the root-private configuration, holds the
machine-wide operation lock, and accepts only a present stable `0x06`/`0x19`
observation with canonical nonzero UUIDs and known lock-state bits. The values
remain in-process and feed only the disabled mapping writer; its public result
is identifier-free and the collector performs no T2 mutation.

`t2_user_reconciliation.py` is the only enable writer. It holds the mapping
writer lock across an injected read-only live session, two exact evidence
collections, intervening Linux-account/keybag rechecks, and the atomic publish.
`t2_user_reconciliation_live.py` is the fixed concrete session: it acquires the
machine-wide operation lock, owns one Bridge generation, requires stable local
Catacomb bytes and clean live SEP state, reconciles local/per-user/global
identity sets, and observes both live AKS UUID bindings. Its interface exposes
no activation, unlock, enrollment, or identity mutation. Every capability must
classify ready before the selected disabled record is enabled.

`t2_user_readiness.py` is the pure runtime readiness boundary. Given a
validated mapping plus independently collected Linux-account/keybag/Catacomb
and live alias evidence, it returns one redacted typed decision. Exact binding
and known safe SKS state are required for `ready`; an absent alias requests
activation, device-lock/first-unlock requests password bootstrap, lockout
requests recovery, and binding collisions, Catacomb corruption, or unknown
state bits quarantine the mapping. The classifier deliberately has no transport
and cannot perform the requested next step. This keeps future
observation/recovery logic separate from AKS mutation and prevents an error
return from becoming an implicit retry.

### Policy resolution and PolicyKit grants

`t2_user_policy.py` is the pure policy boundary above `t2_user_mapping.py`, for
the operations `verify`, `inventory`, `enroll`, `rename`, and `delete-one`. It
accepts only an authenticated active self-session, resolves the target
exclusively by numeric Linux UID through the protected mapping, and requires an
operation-specific grant bound to caller, target, live account generation,
exact mapping bytes, operation UUID, Linux boot, exact Bridge connection
generation, and a maximum five-minute monotonic validity interval. The
downstream consumer rechecks both that generation and the shorter expiry when
operation and activation grants are combined before its first AKS operation.
Cross-user delegation is disabled, root has no implicit authority,
mutation-disable policy is independent, and grants are not transitive between
action classes. A locked or absent target additionally requires a separately
bound `activate-user` grant; lockout and quarantine can never use that route.
The returned mapping and binding are internal while the report is
identifier-free.

`t2_polkit_grant.py` is the concrete but non-exposed grant producer. A future
IPC broker supplies a connected Unix socket to `t2_ipc_session.py`, which reads
`SO_PEERCRED` and obtains an exact `SO_PEERPIDFD`; neither layer reads
sudo/pkexec environment variables or accepts a username. The grant layer reads
`/proc/PID/stat` and all real/effective/saved/filesystem UIDs, uses polkit's
required `PID,start-time,UID` process subject, and repeats those reads after
`pkcheck` returns. PID reuse, setuid transitions, unknown actions, cross-user
targets, timeout, or an exit status outside the documented
authorized/denied/no-agent/dismissed set fail without a grant. Successful and
negative decisions receive a bounded in-process lifetime and exact operation,
boot, runtime-generation, target, and mapping bindings.
`polkit/org.t2linux.touchid.policy` defines the five compiled action IDs
without granting inactive or remote subjects.

The session layer holds the peer pidfd across the whole check and uses
libsystemd's race-free `sd_pidfd_get_session` path first. A user-manager app
with no direct session may fall back to active sessions for the same peer UID,
but authorization requires exactly one active, non-remote `user`-class
Wayland/X11/TTY session attached to a physical seat. Session ID and start time
remain internal and are compared before and after PolicyKit, so logout/login or
session replacement cannot reuse the decision. A live test on the proven
machine selects its local Wayland user session while safely ignoring an
unreadable stale logind row.

### Broker transaction and IPC

`t2_user_broker.py` joins those otherwise separate boundaries without exposing
a service. One reusable `AuthorizationSession` keeps the peer pidfd, exact
login session, and account evidence alive across distinct operation and
activation grants. Under the protected mapping lock, the broker then holds one
read-only live session and Bridge generation, performs three stable
mapping/keybag/live checks around PolicyKit, consumes the shorter grant expiry,
and invokes a synchronous internal consumer before releasing any lease. The
target Linux UID comes only from the kernel peer; request data cannot select an
Apple UID, alias, account UUID, bag UUID, or keybag path. A denied operation
never requests activation authority or invokes the consumer.

`t2_user_broker_protocol.py` defines the non-exposed local boundary as one
canonical, bounded Unix `SOCK_SEQPACKET` message. A request contains only
schema version 1, a command, and one named policy operation. `preflight`
accepts the compiled operation names; `identities` accepts only `inventory`.
Numeric commands, identifiers, extra fields, noncanonical JSON, truncation,
stream sockets, and ancillary file descriptors fail closed.
`t2_user_broker_preflight.py` joins preflight to the full broker transaction
but deliberately suppresses activation collection and all T2 mutation. An
authorized response is valid only when the broker invoked its typed synchronous
consumer while holding the same live runtime generation; every denied response
carries no authority or handoff claim.

`t2_user_broker_inventory.py` is the first typed operation consumer. The live
reconciliation session caches its identifier-free list only after a successful
complete collection and clears it before every recollection, on every failure,
and when the lease exits. The consumer accepts only the exact selected mapping,
same Bridge generation, authorized `inventory` decision, sequential slots, and
bounded Catacomb-valid labels. It requests neither modification nor activation
authority and returns no Apple UID, UUID, alias, entity number, or keybag data.
It remains an internal composition with no installed listener or client.

`t2_user_broker_dispatch.py` receives exactly one protocol packet and
dispatches only those two read-only forms. It passes modification policy only
to preflight; the identities runner is intrinsically non-modifying and cannot
collect activation authority. Runner/result type mismatches, malformed packets,
and encoding failures produce no fallback operation. The dispatcher returns one
canonical packet, then its caller owns connection closure. No listener or
public service installs these modules yet.

`t2_user_broker_client.py` completes the other half of the one-packet boundary
without choosing or opening a socket path. `send_request` and
`receive_response` require Unix seqpacket descriptors, exact whole-message
sends, bounded receives, no truncation, no ancillary descriptors, canonical
JSON, and typed responses. The client additionally binds preflight replies to
the exact requested operation and permits only the inventory response for an
`identities/inventory` request. It offers no retry or command fallback and is
not exposed as a command.

`t2_user_broker_negative.py` and the non-installed research negative client
define the first live exposure test without weakening that protocol. A clean
seqpacket peer close is typed separately from malformed/truncated traffic. The
classifier accepts only that no-response close or the two exact unmapped/
inactive denial states with no consumer, inventory, activation authority, or
mutation. The fixed client has no arguments or caller-selected socket path and
is excluded from installation until the combined exposure gate passes.

### Socket-activation candidates

`t2_user_broker_socket_activation.py` is a non-installed one-connection process
adapter for a future systemd `Accept=yes` unit. It calls
`sd_listen_fds_with_names(1)`, inheriting systemd's PID/PIDFD activation
checks, `FD_CLOEXEC` handling, and activation-environment clearing. It then
requires root, exactly one fd starting at 3 with the default `connection` name,
an `AF_UNIX`/`SOCK_SEQPACKET` type, `SO_ACCEPTCONN=0`, and a live peer. It owns
and closes that descriptor after exactly one dispatcher call. No socket or
service unit invokes this adapter yet.

`t2-touchid-user-broker.py` is the corresponding fixed-policy candidate entry
point. It has no arguments, socket path, or fallback: one systemd activation
connection runs with modification disabled and PolicyKit interaction enabled;
failures produce one generic journal message. The candidate `Accept=yes` socket
and templated sandboxed service live in `systemd/research/`, have no
`[Install]` section, and are excluded from the installer until the documented
live gates pass.

`t2_user_broker_exposure_gate.py` and the installed
`t2-touchid-user-broker-gate` diagnostic join only redacted evidence: the live
module/build match, stable AKS operations `0x06`/`0x19`, a reconciled minimum
of two T2 identities, the operator's same-boot two-distinct-finger
verification, and a present enabled protected mapping. The report explicitly
records that no T2 mutation occurred and that the broker socket is not
installed. Even a fully passing report authorizes only the staged negative
service test, not service installation or enablement.

### Keybag activation

`t2_user_activation_journal.py`, `t2_user_activation_operation.py`, and
`t2_user_activation_recovery.py` encode the serialized activation transaction
without supplying a live transport. The hash-chained journal binds
mapping/boot/runtime generations, target capability, Apple/account/bag/keybag
authority, derived alias, and whether that alias predated the operation. The
injected core writes intent before load, bind, and unlock; verifies a loaded
handle's bag UUID before bind; re-observes alias and lock state after every
ambiguous command return; accepts ready state over a lost reply; and never
retries. Password input must be a bounded `bytearray` and is wiped on every
exit. A post-mutation transport, observation, or journal fault becomes a
terminal reconciliation-required record. Recovery requires a fresh runtime
generation and an unchanged exact mapping, performs one read-only alias
observation, and never retries a password, bind, unlock, or unknown handle. It
can close only as observed ready, observed not-ready, blocked, or quarantined.
The activation operation refuses to observe or mutate unless supplied the exact
policy binding. It accepts an ordinary operation grant only while the target
remains ready, accepts activation only with the separate activation grant, and
uses the policy-bound operation UUID as its journal UUID so a grant cannot be
detached from recovery evidence. `t2_aks_state.py` strictly decodes the exact
ten-field DER keybag-state schema observed on the proven build, including
Apple's exact UTF-8 key ordering, integer encoding, queried handle, lock state,
and private user UUID. `t2_aks_observer.py` brackets that state with two
operation-`0x06` bag-UUID reads, stores raw output only inside a private
transient directory, verifies the private account UUID, and deletes it
immediately. `t2_aks_transport.py` composes that observer with the existing
load, bind, and unlock commands; password bytes traverse a pipe and command
output must match the exact typed reply. These modules provide the concrete
dependency boundary, but no public IPC request protocol, recovery CLI, or
public activation command is present. `t2-aks-observe-test` is only a redacted
read-only hardware gate; operation `0x06` has passed live validation with the
rebuilt pinned module.

## Research notes

The v2 platform field formerly labelled `uid` is the caller's macOS audit
session ID (`ai_asid`). `aks_platform_asid` names it accordingly. The adjacent
64-bit field is the macOS process-unique ID, not a PID. Both are research-only,
boot-scoped data; they must not be inferred from the configured account UID.
