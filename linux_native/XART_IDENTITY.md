# xART OS identity and gigalocker backing

This note records the minimum matching-firmware behavior needed to reproduce
the Intel T2 xART boot boundary. It separates two UUIDs that must not be
conflated.

## Active OS identity

BridgeOS 10.6 build `23P6068`'s `multiboot` plugin implements
`sepStartVersionedApps(epoch, partition_uuid, volume_group_uuid)`. After
AppleSEPManager selector `0x11`, it calls selector `0x28` with exactly 16 bytes:

1. the APFS volume-group UUID when supplied; otherwise
2. the boot partition UUID when supplied; otherwise
3. no xART OS-identity call.

Selector `0x28` routes those bytes to xART endpoint 16, opcode 8. The message
uses separate 32 KiB send and receive OOL buffers. Its header is endpoint, tag,
opcode, and a little-endian 16-byte OOL length. The synchronous response
replaces the opcode byte with status.

A non-APFS Linux boot therefore uses the GPT PARTUUID of the partition from
which its EFI loader was started. A root filesystem UUID, DMI product UUID, and
random installation UUID are different identity domains.

## Gigalocker backing identity

The same bridgeOS build's `/usr/libexec/init_data_protection` is a link to
`seputil`. Its gigalocker initializer independently:

- detects xART in the IODeviceTree;
- selects `/private/xarts` (or `/mnt7` during the restore path);
- obtains `gethostuuid()`, renders it as an uppercase UUID, and forms
  `/private/xarts/<HOST-UUID>.gl`;
- creates a 6 MiB file if needed; and
- uses AppleSEPManager's gigalocker migration and initialization selectors to
  load records and mark the backing store available.

The host UUID names the bridgeOS gigalocker file. It is not the UUID sent by
multiboot to select the active host OS namespace.

### Creator and normal-boot attachment are different paths

Matching `seputil` makes the clean-install boundary explicit. Its shared
gigalocker routine is at `0x10000487c`, but the caller controls whether an
absent store may be created:

- the `--gigalocker-init` CLI path passes true at `0x100002a78` and calls the
  routine at `0x100002a7c`;
- the ordinary `init_data_protection` path first checks
  `protected-data-access`, passes false at `0x10000301c`, and calls the same
  routine at `0x100003020`.

With creation disabled, a missing host-UUID `.gl` file is an error. With
creation enabled, the routine creates the xART directory, creates an exactly
`0x600000`-byte backing file, queries migration state with selector `0x4f`,
imports source records with selector `0x4e`, completes migration with selector
`0x50`, and attaches the selected backing path with selector `0x2c`.

Matching `launchd` embeds a required `data-protection` boot task whose program
is `/usr/libexec/init_data_protection` and whose signing-identity override is
`com.apple.seputil`. That normal task therefore attaches existing state; it
does not provision missing clean-install state. The matching restore/Ramrod
image contains the only recovered producer call site: it invokes
`--gigalocker-init` from `ramrod_init_gigalocker_if_xart`. This explains why a
wiped machine can reach normal bridgeOS userland while xART still has no
backing store to attach.

No advertised RemoteXPC service directly exposes this creator. In particular,
`com.apple.xpc.remote.multiboot` only accepts a `version` string and mutates the
bridge-version whitelist. Its handler never calls `sepStartVersionedApps` or a
gigalocker routine. `com.apple.RestoreRemoteServices.restoreserviced` exposes
only recovery/reboot, nonce and preflight queries, AP parameters, delayed
recovery-image handling, and restore-language selection. None is a targeted
gigalocker-init operation, and the recovery actions are not safe substitutes.

Matching AppleSEPManager code also contains the SEP-driven storage handler.
It dispatches xART request opcodes against an in-kernel gigalocker state and
the registered OOL buffers. This matters if a future Linux transport must host
the master storage role; it is not evidence that the current Intel slave path
must do so before the correct boot-identity probe.

## Master and slave roles

Matching AppleSEPManager's `AppleSEPXART::_initForDeviceService` derives the
role from the provider's four-character name:

| Provider | Role flag | Host behavior |
| --- | --- | --- |
| `xarm` | true | Check in as master and serve SEP-driven gigalocker requests |
| `xars` | false | Use the slave request path; do not own the backing store |

The matching Intel host implementation names endpoint 16
`xartSEPSlaveEP`. Linux must therefore preserve the slave role and must not
invent a second gigalocker master merely because the backing-store protocol is
present in the shared manager binary.

Master readiness is a two-prerequisite rendezvous. `checkInMaster` records the
master object and initializes it only if the backing path is already known.
`_setGigalockerAvailable` records the backing path and initializes only if the
master has already checked in. `gl_initialize` is the master-only point that
loads the backing and marks gigalocker available. The arrival order is
deliberately asynchronous.

The SEP-driven dispatcher handles opcodes `0`, `1`, `5`, `6`, `7`, `14`,
`29`, `30`, and `31`; at least opcodes `5` and `7` reject requests until the
gigalocker-available flag is set. That master-backed path is used by durable
record operations such as the internal `0x271b` loader below. D119 corrects an
earlier conflation: host-facing xars command 8 only installs the 16-byte OS
UUID in local xART application state. It does not send an opcode-5 master
request, so the observed Linux status `0x2d` cannot be attributed to a
gigalocker backing read.

`xartstoraged` in this bridgeOS image is a signed eight-byte executable that
returns success; the substantive file and SEP protocol implementation is in
`seputil` and AppleSEPManager, not that executable.

## AppleKeyStore durable-read dependency

The matching `sks` SEP application now closes the receiver attribution for the
primary-identity timeout. During application startup, `0x001048ee..0x001048fc`
calls the shared service resolver with fourcc `xART` (`0x78415254`) and stores
the returned handle in application global `0x04117668`. The non-lazy pointer at
application address `0x0011346c` points to that exact global.

The durable loader at `0x001003f0..0x001003fa` loads that non-lazy pointer and
passes it as argument 2 to shared-runtime command `0x271b`. In the shared
routine, `0x00040b96` preserves the argument and `0x00040d60` dereferences it
immediately before the synchronous internal IPC call at `0x00040d6a`.
Therefore command `0x271b` is sent through the `xART` service handle; it is not
an anonymous filesystem or generic SEP service transaction.

The receiver side closes one more layer. The xART application's internal
dispatcher subtracts `0x2711`; table index 10 routes `0x271b` to handler
`0x000bb9e8`. That handler's `0x271b` case reaches
`0x000bbdd4..0x000bbe02`, constructs host-facing opcode `5`, and submits it
through the same xART master-request routine at `0x000bad38` used by the
application's other backing operations. It propagates the response status and
length before replying to `sks`.

This proves that the isolated operation-`0x51` timeout is blocked at xART
master-backed durable storage before class-10 record decoding. It does not
prove that a record is absent, nor does it authorize creating a host-side
substitute for the bridgeOS-owned master. The safe next boundary remains
provisioning or attaching the embedded gigalocker through the recovered vendor
lifecycle.

## Reference-machine discriminator

The wiped reference installation has no APFS volume group. Its current EFI
loader and `/boot` filesystem reside on the same GPT partition, so that
partition's PARTUUID is the evidence-backed opcode-8 input. One boot using the
btrfs filesystem UUID and a second boot using the correct GPT PARTUUID both
received status `0x2d`. The first result rejects the filesystem-UUID
substitution; the second proves that correct active-OS identity is not by
itself sufficient to make xART available. The numeric meaning of `0x2d`
remains unlabelled.

The second boot also exposed a startup-order discriminator. PCI modalias
autoload ran the one-shot slave sequence before the T2 CDC-NCM function had
even enumerated. Later in that same boot, dynamic RemoteXPC discovery followed
by a BridgeXPC HELO-only exchange succeeded. The next experiment therefore
suppresses modalias autoload and performs one explicit module load only after
that capability signal. This does not claim that BridgeXPC HELO is the direct
gigalocker-ready event; it tests whether waiting for the surrounding BridgeOS
userland phase is sufficient for the already recovered asynchronous master
rendezvous to complete.

That experiment completed with the same `0x2d` status. HELO is therefore not
a gigalocker-availability boundary. The next discriminator must address the
missing restore-time creator or establish an equally exact, non-destructive
replacement; another delay or whitelist message cannot answer it.

## macOS-control volume-group oracle

After installing the temporary macOS control, Linux read the APFS container's
volume superblocks directly without mounting or decrypting any volume. The
container has the expected six roles. System and Data share exactly one
nonzero volume-group UUID; Preboot, Recovery, Update, and VM have zero group
IDs. The shared value is stored only in a root-private oracle file and is not
printed or committed.

This is the exact identity class selected by matching Apple boot policy when
an APFS volume group exists. A future, separate xART-only boot may use it to
discriminate “wrong Linux boot identity” from “missing embedded creator or
attachment.” It remains macOS-derived interoperability evidence and cannot be
an installation prerequisite. A clean Linux-only installation still needs to
originate and provision its own equivalent xART identity/backing lifecycle.

The source installer can consume such a discriminator through the mutually
exclusive `T2_TOUCHID_XART_OS_UUID_FILE` setting. The named file is opened
once, then that exact descriptor must prove regular-file type, root ownership,
mode `0600`, 37-byte size, and canonical UUID syntax. When xART is enabled, the
derived modprobe options are also mode `0600`. This prepares private input
handling only; it does not install or authorize the future oracle generation.

Post-macOS bridgeOS logs provide the live attach ordering: launchd begins the
`data-protection` boot task, embedded `disk1s3` mounts as xART four seconds
later, APFS enables bypass mode on the backing inode, and SEP/USER xART are
then fetched. No creator call occurs in this boot window. Normal boot therefore
consumes already provisioned embedded state exactly as the recovered static
path predicts.

The separate Linux boot using that protected APFS volume-group candidate still
received opcode-8 status `0x2d`. Versioned app selection completed, but
endpoint-7 setup did not follow. This rejects UUID class as a sufficient
explanation: filesystem, Linux boot-partition, and macOS volume-group inputs
all reach the same application status. It does not reject the candidate's
provenance or the embedded-volume transition. The next recovery target is the
internal opcode-5 master-record/rendezvous path, not another UUID guess.

Focused disassembly closes that internal status boundary. Opcode 5 first
asserts the global gigalocker-available byte; a false value is a fatal
invariant edge, not the observed reply. It then calls `gl_rec_find`. A missing
record returns success with `found=false`, while the function propagates any
backing-page read error unchanged. The handler copies that return value's low
byte directly into the xART reply. Status `0x2d` is therefore Darwin
`ENOTSUP` from the initialized gigalocker backing read, before the requested
record UUID is compared. This rules out master absence, record absence, UUID
byte order, and versioned-start timing as explanations for this result.

The remaining ordering hypothesis is keybag protection. Linux currently sends
opcode 8 before endpoint 7 exists, while the proven Apple alias can only be
password-unlocked afterward. The explicit `defer_xart_publish` discriminator
registers xART OOL at probe, completes endpoint-7 setup, and exposes a
kernel-enforced one-shot root-only ioctl. It does not publish automatically.
After the reconciled alias is observed and unlocked, the same exclusive AKS
owner may issue that ioctl once. Attempted, published, and poisoned states are
typed in the metadata ABI; either success or failure forbids another attempt
before reboot.

The discriminator returned a definite negative. Endpoint 7 and capability
negotiation completed first, and the protected Apple alias was already ready,
so no password mutation occurred. The one deferred opcode-8 request still
returned `0x2d` and poisoned the generation. Alias/keybag lock state is not the
cause of the backing vnode's `ENOTSUP` result.

Linux reboots did not restart bridgeOS across the earlier experiments. The
next lifecycle discriminator uses the matching normal restoreserviced reboot
command. Static recovery proves lowercase `reboot` schedules `reboot3(0)`
after three seconds and is distinct from the forbidden `recovery` branch that
changes one-shot boot policy. A paired host reboot discards Linux's pinned DMA
generation before any post-transition access.

The cold-lifecycle discriminator also returned `0x2d`. It ran after a
force-completed full-machine restart and on a later clean Linux boot with
capability probing omitted, so endpoint 7 could not contaminate the result.
The publication-only owner accepted deferred header-v1 metadata, journaled one
xART ioctl, and the kernel poisoned it on the same definite backing error.

The preceding Linux shutdown had reached persistent-storage flush but remained
on a black screen until the operator force rebooted. It is therefore a cold
lifecycle result, not proof of an ordinary successful reboot.

Thus that restart does not repair the backing. Identity class, byte order,
record absence, alias lock state, BridgeXPC/SKS readiness, and bridgeOS boot
lifetime are insufficient explanations.

The exact backing path is now recovered. Gigalocker retains the original `.gl`
vnode only for APFS control, while its read/write wrapper uses the synthetic
`/dev/apfs-raw-device.%d.%d` vnode created as a mode-`0600` block device. The
initial attach reads every complete `0x9000` record page through that same
wrapper before availability can become true. Later record lookup reads the
`0x22`-byte header at each same page boundary.

APFS unmount invalidation cannot explain status `0x2d`: it clears the enabled
bit and makes raw-device strategy return `0x23` before dispatch. Matching
`spec_read` supports the later partial read and propagates `buf_bread` errors.
On the valid-device path, APFS maps the cached file extent into its normal
container read callback, which propagates the lower `buf_biowait` completion
error. The remaining `ENOTSUP` producer is therefore below the raw vnode and
extent mapping, in the embedded storage strategy/completion path.

That lower errno is now resolved more precisely. The BSD media completion
converts I/O Kit `kIOReturnUnsupported` (`0xe00002c7`) into errno `0x2d`.
Matching embedded-NVMe hardware completion and reset paths do not generate
that status. The composite short-read deblocker has a nearby inherited
unsupported DMA-operation branch, but the actual NVMe preparation requests a
different, supported operation class. The unresolved boundary is therefore an
immediate start/preparation failure in the concrete provider/filter chain, not
a normal NVMe completion and not short-read alignment by itself.

The successful initial gigalocker scan is also a weaker storage control than
it first appeared. APFS's lower callback obtains one container block with
`buf_getblk` and checks `buf_valid`. A valid cached block completes without
calling `VNOP_STRATEGY`; only an invalid block reaches `IOMedia` and the
embedded NVMe device. Attach-time full-page reads can therefore succeed from
cache before the later record-header lookup encounters a physical miss.

The physical-miss descriptor is an ordinary `IOGeneralMemoryDescriptor`.
Exact class-5 DMA handling, class-0 mapping through `IODARTMapper`, and the
embedded NVMe encrypted-I/O field builders all exclude
`kIOReturnUnsupported` from their recovered explicit failures. Nearby literal
unsupported returns belong to controller management and media-format methods,
not the read slot. The remaining boundary is a status-bearing request-
preparation edge reached only after an invalid APFS buffer is dispatched.

The rest of the ordinary miss path has since been recovered as well. Exact
`IOBlockStorageDriver::executeRequest` forwards to the concrete embedded-NVMe
read slot, and the descriptor attach, prepare, segment mapping,
synchronize/reprepare, queue, submit, reset, and completion paths contain no
`0xe00002c7` producer. In particular, descriptor attach uses supported
operation `0x02000000`; a later operation-3 return is ignored. The captured
BSD `0x2d` must therefore be traced from the APFS callback buffer's actual
device-vnode/strategy and transform owner before it can be assigned to the
ordinary physical-NVMe path.

Exhaustive constructor recovery removes the transform-owner alternative. All
three APFS container-constructor callers leave the operations pointer null, so
the default vnode-backed read table is always installed. Its invalid-buffer
path reaches `VNOP_STRATEGY`. A completed error cannot masquerade as a later
cache hit: `buf_getblk` waits while the buffer is busy and `buf_brelse` marks a
released error buffer invalid. Both asynchronous `IOMedia` read overloads also
converge on the same `IOBlockStorageDriver` request builder, whose validation,
aligned, and split paths exclude unsupported before the already audited
execute routine.

The embedded container loader opens the physical store vnode, and retained
platform evidence identifies that store as `/dev/disk0s1`, below synthesized
`disk1` and its `disk1s3` xART volume. The unresolved fact is now the concrete
provider instance/vtable bound below that physical device. Generic class-table
recovery is not enough to prove that the live binding is the ordinary embedded-
NVMe instance whose full read path has been excluded.

That live binding is now proved. `AppleEmbeddedNVMeController::AllocateNodes`
creates NSID 1/type 1 before scanning special namespaces, and its type-1
factory allocates, attaches, starts, and registers
`IOEmbeddedNVMeBlockDevice`. The class inherits through
`IONVMeBlockStorageDevice` from `IOBlockStorageDevice`; standard superclass
initialization supplies `device-type=Generic`, which is the exact prelinked
`IOBlockStorageDriver` match. The installed instance vtable reaches the
already-audited `0xfffffff006b9931c` read implementation.

Neither the effaceable personality nor APFS error sampling supplies an
alternative. The former cannot attach above the ordinary namespace as a read
interposer, and the synchronous APFS path branches on a fresh `buf_biowait`
return before using data. The remaining static target is therefore completion
object/status lifetime between the BSD media client and APFS buffer, not a
different provider class, namespace, transform, or normal NVMe/DMA exit.

That completion lifetime is now closed. `IOBlockStorageDriver` copies the BSD
client's stack completion into its request, forwards status as a callback
argument, calls the saved completion before releasing the request, and never
loads status from reused request storage. `IOMediaBSDClient` maps that direct
status and calls `buf_seterror` even on success, clearing any prior errno
before `buf_biodone`. APFS immediately consumes the fresh `buf_biowait`
result, with no transform to errno 45.

The upper edge has also been re-established independently. Exact
`gl_rec_read` propagates both `gl_rec_find` and its final `VNOP_READ` return
unchanged; both xART read cases store that low byte directly into the reply.
The helper's imports resolve to `uio_create`, `uio_addiov`, and `VNOP_READ`.
Because the synthetic vnode is `VBLK`, `spec_read` does not reject the actual
`0x1800` flags and otherwise propagates the block-read result. The audited
kernelcache UUID exactly matches the runtime kernel UUID in retained logs.

Thus the normal chain from reply byte through the exact NSID-1 provider is
internally contradictory: it preserves `0x2d`, while every reachable lower
producer has been excluded. The next boundary is endpoint-16 reply ownership
and observation provenance, not another storage implementation or patch.

Endpoint-16 ownership does not resolve the contradiction. Matching
AppleSEPXART separates traffic by role before tag lookup: `xarm` receives
SEP-driven requests, while the Intel host-facing `xars` receives transaction
replies. Its slave receiver requires the exact endpoint and an active matching
tag, copies the whole reply over the request, and wakes the sender;
`_xmsgSendLocked` then returns byte 2. Linux serializes the same single
endpoint-16 transaction and applies that same endpoint/tag/byte-2 rule.

The D058 installed source is unchanged in this parser, and its only other
nearby transactions were endpoint-0 OOL registrations with distinct tags.
Consequently the retained `0x2d` is not an internal master request, response
body field, tag collision, or decoder drift. Static work returns to indirect
or asynchronous storage completion owners outside the already excluded normal
request path.

Those asynchronous owners are now exhausted. The hardware completion handler
writes success or calls its bounded error mapper before placing a request on a
post-lock callback list; retry either resubmits that request or completes it
with the mapped status already present. Bulk teardown supplies only
`kIOReturnDeviceError` or `kIOReturnNoDevice`, the alternate completion
supplies success or `kIOReturnDeviceError`, and timeout supplies
`kIOReturnTimeout`.

The standalone `AppleNVMeRequest::setStatus` accessor is non-virtual and has
no caller or stored function pointer in this image. Active code uses inline
status stores, all of which are already enumerated; request initialization
clears the field. The earlier label on raw `0xe00002e9` is corrected here:
Apple's `IOReturn.h` names it `kIOReturnDeviceError`, while
`kIOReturnAborted` is `0xe00002eb`. The final unowned embedded-NVMe callback
edge therefore does not supply `kIOReturnUnsupported`; the next audit must
return to the retained observation's exact lower-buffer identity and
timestamp provenance.

That final buffer boundary is also closed. Exact `buf_bread` dispatches an
absent block through the vnode strategy, waits, and returns only success,
`EINTR`, generic `EIO`, or the buffer's completed error. `spec_strategy`
indexes `bdevsw` directly by major number. The APFS raw-device registration's
strategy slot is exact `0xfffffff006892534`; its local failures exclude
`ENOTSUP`, and its imported `buf_map_range` helper returns only success or
`ENOMEM`. The valid path converges on the previously recovered synchronous
APFS container callback.

The full `IOService::errnoFromReturn` jump table confirms that only
`0xe00002c7` becomes errno 45. A contemporaneous D058 bridgeOS log archive
could not be obtained: the single OS-log-only request failed closed, left no
local artifact, and retrieval-only reported no available archive. The current
boot must not repeat either request. Further live work requires a separately
specified discriminator and a new explicitly ordered boot; the module remains
pinned and all authentication surfaces remain off.

## Post-repair no-publication durable inventory

The successful authenticated Apple-control match does not imply that a fresh
durable AppleKeyStore inventory can bypass xART publication. On the recovered
post-reinstall machine, Linux issued one exact read-only endpoint-7 operation
`0x51` primary-identity request while the transport still reported only OOL
registration, versioned application selection, and untouched deferred xART
readiness. The request timed out after zero unrelated messages and produced no
DER output. It was not retried.

Read-back after the timeout reported header version 1, provisioning phase 0,
stable-absence count 0, and flags `1033`: OOL registered, versioned apps
selected, and deferred xART ready. Neither the attempted nor published nor
poisoned xART bits were set. Thus this observation did not publish an OS UUID
or convert unavailable inventory into an empty result.

The distinction is now concrete. D110 matching used a host-saved Apple keybag
that Linux explicitly loaded and unlocked, so the live biometric path could
consume already-instantiated identity state. Operation `0x51` instead invokes
the lazy class-10 durable loader and still blocks on its synchronous xART
backing transaction. Existing-state matching is therefore not a substitute
for the durable empty/present oracle required before Linux-native creation.

## Host ANS2 effaceable side path

D117 closes the apparent host-NVMe ownership gap without a live request.
RecoveryOS `AppleANS2Controller::start` waits for the BCE-NOR-backed
`AppleEffaceableStorage`, publishes its registry-entry ID, and then calls the
ordinary inherited NVMe start. RecoveryOS APFS consumes that ID together with
`AppleKeyStoreRegistryID` in `_kb_effacer_create`, resolving the effaceable
service used by host-container wrapping/media keybags. The property is not
consumed by `IONVMeFamily` and does not expose or activate bridgeOS embedded
NVMe.

The exact Linux v7.1.8 driver already applies the known `106b:2005` ANS2 queue,
tag, command-ID, and identify quirks, while the matching T2 kernel patchset has
no host-NVMe patch. Apple's remaining derived-controller initialization adds
wall-time, QoS, logger, and housekeeping work, not xART or gigalocker traffic.
Therefore neither emulating `AppleEffaceableRegistryID` nor binding BCE NOR is
a justified fix for opcode-8 `0x2d`. Any remaining host-transition hypothesis
must be tied to a recovered reset/power effect on the T2 master, not this APFS
registry association.

## BridgeOS xART shutdown lifecycle

D118 closes that reset/power hypothesis. The matching bridgeOS
AppleSEPManager implements xART disable as a coordinated local protocol, not
as a host-controller side effect. It registers up to sixteen four-character
clients, clears their acknowledgements at disable begin, records each client
acknowledgement, and formats the complete acknowledgement state on failure.

Its paging-off notification callback resolves the embedded xART SEP slave and
runs the gated shutdown sequence. A failed sequence logs
`xART shutdown failed` together with the formatted acknowledgements. A separate
`systemWillShutdown` method sends a control notification before delegating to
its superclass; ordinary macOS/Linux host switching while bridgeOS remains
running is not that bridgeOS system-shutdown event.

The signed update-ramdisk caller confirms the intended quiescing boundary.
`seputil --gigalocker-shutdown` issues AppleSEPManager userclient selector
`0x2e`, and Ramrod invokes it only after checking for SEP/xART and waiting for
the APFS container reaper when a container node exists. This is restore/update
lifecycle plumbing, not normal host reboot handling and not a safe live probe.

The retained post-macOS bridgeOS archive spans four hours and two bridgeOS boot
UUIDs. It contains six normal xART-disable client registrations (`sksm`, then
`scrd`, `sbio`, `sse `, `sks `, and `sksm`) but no disable-begin,
acknowledgement, paging-off, shutdown-failure, or bridgeOS system-shutdown
event. The second boot mounts `disk1s3` as unencrypted xART and enables its raw
device bypass without a later unmount in the archive.

Consequently a blind ANS2 reset or power toggle cannot be treated as
`gl_shutdown` and would bypass the proved APFS/client-acknowledgement contract.
Do not issue selector `0x2e`, synthesize paging-off, or alter host ANS2 power.
Do not continue treating bridgeOS attachment or backing-page `ENOTSUP` as the
producer of the host-facing opcode-8 result. D119 below supersedes that
attribution while preserving the separate durable-loader dependency.

## Host-facing opcode-8 dispatch correction

D119 recovers the matching J152f xART SEP application's xars receive loop at
`0x000b9d44`. Initialization registers fourcc `xars` first and stores its
handle at application global `+0x10`; the loop reads eight-byte messages from
that handle. It loads request byte 2, subtracts 8, accepts commands 8 through
20, and preloads literal status `0x2d` at `0x000b9dfc` as the unsupported-
command result.

The command-8 table entry is exact. It requires OOL length `0x10`, copies the
16-byte input, rejects an all-zero UUID with status 1, and otherwise installs
or replaces the UUID before returning status zero. First use only resolves the
two per-OS state objects; it does not call the xarm request routine. Length
mismatch returns `0x16`. Therefore a correctly dispatched command 8 with the
nonzero Linux identity has no reachable `0x2d` return in this matching app.

The retained bridgeOS oracle independently agrees. Its 335,784 records cover
the Linux result at `2026-09-02T00:32:23.086757Z` with 9,862 records in the
surrounding three minutes. There is no master-reply record in that interval.
Across the complete archive all 48 logged AppleSEPXART master replies carry
status byte zero; byte 2, not the adjacent tag or opcode field, is the status.
Those replies are a positive control that post-macOS master/gigalocker traffic
was functioning, but xars command 8 is not such traffic.

Consequently D059 through D068 and D112 remain valid only as storage-path
research and as proof that Linux received a synchronous endpoint-16/tag-1
reply. Their claim that this particular `0x2d` came from a backing VNOP read is
superseded. The next boundary is the contradiction between Linux's source
word (`endpoint 16`, tag 1, byte-2 command 8, byte-3 length 16) and the SEP
dispatcher result: on-wire dispatch/routing/correlation must be reconciled
statically before another xART request. Exact evidence is immutable in
`D119-xart-opcode8-dispatch-20260903T203917Z`.

## Alternate producer and firmware boundary

D120 proves the other xART literal `0x2d`, at `0x000bc56c`, is not another
host reply path. It belongs to a loop rooted at the separately discovered
`AMDM` resource handle, registered through libShared destination `0x412c` and
using methods `0x412d`/`0x412e`. That loop accepts command bytes 2–4 and uses
different receive/reply imports. The named `xars` loop continues to use the
handle stored at application-global `+0x10`.

SEPOS contributes no executable status producer: its raw immediate is ASCII
formatting state and the apparent `0xc7f0` hit is data word `0x0000272d`.
The raw kernel halfword `0x4143` is also unrelated; its paired high half forms
fourcc `0x54524143` (`CART`). Current DMI remains identical to the retained
post-reinstall D112 line and corroborates the direct bridgeOS `23P6068`
observation. A fresh splitter run reproduced the matching xART image exactly.

This leaves the `xars` unsupported-dispatch default as the only matching
host-facing source of `0x2d`. The next useful Linux observation is therefore
the complete public request/reply header at the MMIO boundary, not another
UUID, storage, service, or power experiment. D120 evidence is immutable in
`D120-xart-routing-boundary-20260903T210232Z`.

## D123/D124 MMIO result and routing correction

D123 retained the exact one-shot request and reply:

```text
request 0x10080110/0x00000000/0x00000000/0x00000000
reply   0x002d0110/0x00000000/0x00000000/0x0010ab00
```

Matching Intel `AppleSEPIntelIOP::_getMailboxGated` reads all four words and
uses only word-3 bits 18 and 19 as FIFO/error sideband; neither is set.
`AppleSEPXART::_xmsgReceived` copies only the first 12 bytes. On transmit,
`AppleSEPManager::_sendMessageGated` preserves bytes 1–11, replaces only byte
0 with the endpoint argument, and zeros word 3. The fixed
`xartSEPSlaveEP()` endpoint is 16. The PCI frame is therefore exact and is not
transformed by Apple's Intel transport.

D120's decisive error was treating import aliases as different transports.
The named xars receive/send stubs resolve through libShared branches at
`0x3e930`/`0x3e934` to generic receive `0x3e4dc` and send `0x3e7b0`. The AMDM
stubs resolve to those same generic functions. The service handles, not the
import implementations, distinguish the queues.

The AMDM loop receives `(AMDM_handle, 16, buffer, 8)`, loads request byte 2,
accepts commands 2–4, and assigns literal `0x2d` otherwise. Its zeroed reply
copies tag byte 1, writes status byte 2, and sends `(AMDM_handle, 16, reply,
8)`. That construction exactly accounts for all 12 payload bytes in D123.
Thus a raw x86 PCI endpoint-16 message reaches the AMDM control loop, not the
bridgeOS-internal named xars queue.

The matching Intel xART driver independently has no OS-UUID command caller:
its three `_xmsgSend` callers erase one session, erase all sessions, and fetch
known sessions. The command-8 caller is bridgeOS `multiboot`, using
AppleSEPManager userclient selector `0x28` inside bridgeOS. Its advertised
RemoteXPC listener exposes only bridge-version whitelisting, not that selector.

Direct PCI command 8 is therefore retired. Current kernel code has no xART
UUID parameter, endpoint-16 OOL allocation, or publication ioctl; the
installer rejects legacy settings. The D111–D123 scripts and immutable
journals remain historical evidence and must not be replayed. Native identity
provisioning no longer gates on a synthetic host-publication flag; its
stable-empty inventory, capability, ACM, and non-retryable transaction gates
remain. Exact evidence is immutable in
`D124-xart-routing-correction-20260903T212912Z`.
