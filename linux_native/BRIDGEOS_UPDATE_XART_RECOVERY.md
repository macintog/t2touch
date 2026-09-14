# Recovering missing xART through the bridgeOS update path

This note defines the current clean-install repair boundary. It is deliberately
separate from Linux authentication: nothing here enables biometrics, provisions
a user keybag, or changes PAM.

## Correct storage namespace

Matching bridgeOS `23P6068` Ramrod does not scan the x86 host's Linux block
devices. `ramrod_wait_for_internal_media()` waits for an I/O Registry object
whose `EmbeddedDeviceType` is `Root`; `ramrod_probe_media()` walks the `IOMedia`
tree below that object and records its APFS volumes by name.

The retained boot log identifies that root unambiguously:

```text
Using device path /dev/disk0 for EmbeddedDeviceTypeRoot
device partitioning scheme is GPT
APFS Container 'Container' /dev/disk0s1
Found synthesized APFS container. Using disk1 instead of /dev/disk0s1
```

It then reports the system volume and another encrypted volume on `disk1`, but
no xART volume. Linux `/dev/nvme0n1p3` is not in this namespace. The D016 APFS
image is therefore useful formatter work and negative evidence, but cannot be
the bridgeOS xART volume regardless of another bridgeOS restart.

## Matching vendor creator

The source artifact is Apple's public *full restore* image:

- IPSW: `iBridge2,..._10.6_23P6068_Restore.ipsw`
- SHA-256: `da1ce0198ee23d38a6d065e296fed3f302ff79b196c14107ab59ea191028206a`
- `BuildManifest.plist` identity 20: update identity for `j152f`
- update ramdisk: `094-92985-079.dmg`
- recovered executable: `/usr/local/bin/restored_update`
- executable SHA-256:
  `18479a1199a63384075101ebe1c9a0ac15bdeea4f24ae3b624231228e10fcc94`

`restored_update` contains the missing creator inside
`create_apfs_filesystems`. For partition-table entry 1 it:

1. calls `ramrod_should_have_xart_partition()`;
2. skips creation when the DeviceTree says xART is unsupported;
3. skips creation when Ramrod already recorded an xART device node;
4. otherwise selects role character `x` and size `0xa00000`; and
5. invokes the shared filesystem helper for the embedded APFS container.

The helper constructs this effective command vector:

```text
/System/Library/Filesystems/apfs.fs/newfs_apfs
    -s 10485760 -A -D -o role=x -v xART <embedded-container-device>
```

The matching `newfs_apfs` usage identifies `-s` as volume size. Its role table
maps the xART entry to APFS role `0x100`, source path `/private/xarts`, and
Ramrod mount point `/mnt7`. This corrects two D016 assumptions: Apple creates a
10 MiB volume inside the T2-owned APFS container, not a 128 MiB standalone
container in the host GPT.

After discovery/mount, `ramrod_init_gigalocker_if_xart()` runs
`/usr/libexec/seputil --gigalocker-init`. That is the vendor transition which
creates the 6 MiB host-UUID `.gl` backing and attaches gigalocker. Normal boot
remains attach-only.

That normal-boot distinction is now recovered directly from matching
`23P6068`. The launchd `data-protection` boot task executes
`/usr/libexec/init_data_protection`, a symlink to the signed `seputil` binary,
under a `com.apple.seputil` code-signing identity override. `seputil` selects
this mode from its basename and, when the `protected-data-access` feature is
enabled, calls its common gigalocker routine with `create=false`. A missing
6 MiB host-UUID `.gl` file therefore returns without the file-creation call.
The separate `--gigalocker-init` option calls the same routine with
`create=true`. There is no boot argument or property fallback that changes
the normal task into the creator.

## Normal software update is not the creator

The live T2 advertises `com.apple.bridgeOSUpdated` over RemoteXPC. A read-only
`{"Command":"QueryUpdateState"}` request returned:

```text
CurrentOSBuildVersion: 23P6068
UpdateState: 0
UpdateOperation: 0
PreviousUpdateState: 1
UpdateOperationResult: 0
PreviousUpdateDate: 2026-07-27 16:37:58
```

The service is idle. Its matching server accepts the ordered update operations
`TransferUpdateBrain`, `TransferUpdateBundle`, `PreflightUpdate`,
`PrepareUpdate`, and `ApplyUpdate`; the two transfers are streaming zip
archives represented by XPC file-transfer objects. The service stages them as
`UpdateBrain` and `UpdateBundle` before calling MobileSoftwareUpdate.

Apple's official software-update catalog resolves the exact matching payloads:

- product `140-93588`, product version `26.6.2`, bridge ordering
  `23.16.16068.0.0`;
- `BridgeOSBrain.pkg` SHA-256
  `2e270aba5839005d9d0483dea46140e5877ebda31b1148331c0ac70c77726f33`;
- contained `UpdateBrain.zip` SHA-256
  `2c9bb7fcab41e9ca56481ece12503c0085307bd84bca254de05e83b1dbe79784`;
- `BridgeOSUpdateCustomer.pkg` SHA-256
  `34c32a7aa8a7cb8b49f5a4dd043b76e8e65d817c510ee494fb2c74c7c48d2fa7`;
  and
- contained `UpdateBundle.zip` SHA-256
  `d25a2e7f27031e75ea00dcb3bcf809e5f0d0827b07f4e296868c31cb09c780ab`.

Those exact artifacts falsify the proposed repair route. The matching
`UpdateBrainLibrary.dylib` has one `CreateFilesystemPartitions` option site and
sets it to `false` before the limited firmware update. The software-update
ramdisk (`arm64SURamDisk.dmg`) contains gigalocker initialization but not the
`Will create an xART partition` creator. Sending the matching archives through
`bridgeOSUpdated` can therefore update bridgeOS, but it cannot reconstruct a
missing xART volume. Do not transfer them for this project goal.

The gate is confirmed end to end. `_install_personalized` places the false
Boolean in the restore dictionary carried by the firmware-update context. The
normal-boot and software-update-ramdisk copies of
`ramrod_update_copy_deviceinfo_with_options` independently create a nested
`RestoreOptions` dictionary with `kCFBooleanFalse` for the same key. Finally,
the exact update ramdisk's `libSEUpdater.dylib` requires that key to be a
Boolean and maps it to the erase-install/MFD decision. Supplying `true` in a
host request cannot survive these signed, hardcoded constructors.

Normal-mode `restoreserviced` does not provide an alternate dispatch. Its host
command set is recovery, reboot, nonce and preflight/AP-parameter reads,
recovery-image delay, and restore language. Its linked Ramrod contains the same
forced-false logic. This closes the signed normal update/restore-service branch
without sending an update archive or mutating request.

The standard x86 NVMe view is also not an alias for the embedded container. A
read-only Identify Controller reports one namespace on Apple ANS2, and that
namespace is the complete 500 GB Linux-visible disk. Namespace 2 is invalid;
the controller does not advertise namespace management. Its vendor identify
area is populated, so a proprietary Apple protocol may exist, but no vendor
command is authorized by this evidence. Do not infer bridgeOS `/dev/disk0`
from `/dev/nvme0n1` or create another host GPT partition.

## Remaining Linux-side control boundary

The creator is confined to the full IPSW restore/revive machinery. The IPSW
contains both `Erase` and `Update` build identities for `j152f`; only the
non-erasing `Update`/revive route is a candidate for this installed Linux
system.

### Identity selection is now proven

The matching manifest and pinned restore client agree on the selector:

| Manifest identity | Variant | Restore behavior | Ramdisk |
| --- | --- | --- | --- |
| 4 | `Customer Erase Install (IPSW)` | `Erase` | `094-92961-079.dmg` |
| 20 | `Customer Upgrade Install (IPSW)` | `Update` | `094-92985-079.dmg` |

Both identities require board ID `0x3A` and target `j152fap`. Pinned
`idevicerestore` commit `45145e9fdc8458022c61a4b87bd029b866d5bcdc`
selects `Upgrade Install (IPSW)` when `FLAG_ERASE` is absent and selects
`Erase Install (IPSW)` only when it is present. RestoreKit's `Mode::Revive`
passes flags `0`; its erase and obliterate modes pass `FLAG_ERASE`. Thus the
exact creator-bearing update ramdisk is selected by revive without relying on
a filename guess or a project-local board allowlist.

### Recovery transition and same-host transport

Matching `restoreserviced` SHA-256
`c5bb4d668bac753cfb25b2817c0b507d5f1a54152956343bbed6139c45374a01`
advertises `com.apple.RestoreRemoteServices.restoreserviced`. Its lowercase
`{"command":"recovery"}` handler writes CFData `false` to the
`auto-boot-once` property in `IODeviceTree:/options`, returns success, and
schedules `reboot3(0)` three seconds later. The one-shot meaning is an
inference from the property name and control flow; it is not yet a live result.

On the reference Mac, the booted T2 USB device `05ac:8233` and its CDC-NCM
interface are presented through the internal `t2bce_vhci` below PCI function
`04:00.1`. The Linux root disk is Apple ANS2 NVMe function `04:00.0`. These are
sibling functions, not an external USB cable. Whether iBoot recovery PID
`05ac:1280` or `05ac:1281` is presented through that same VHCI is the next
single hardware discriminator.

The first live recovery request used a five-second reply timeout. It passed the
exact build and advertised-service gates, then timed out after sending the
command. An independent 150-second observer completed with booted T2
`05ac:8233` and ANS2 NVMe continuously present and no recovery PID. The user
later hard-reset the host. This is a negative recovery-transition result, not
evidence that iBoot recovery is invisible to BCE: the T2 never left booted
mode. The command must never be retried merely because its reply was lost.

A subsequent single read-only `getnonces` request returned the expected
`result=nonces` shape with 32-byte AP and 20-byte SEP nonce fields; the bytes
were neither printed nor persisted. Thus RemoteXPC framing and the service
dispatcher work on `23P6068`. Current upstream pymobiledevice3 commit
`ec4ac06a850a6a884ca778350621f354faf347c6` independently uses the identical
lowercase command envelope and `result=success` contract. The remaining fault
is specific to recovery handling or its reply latency.

The corrected second attempt used a 30-second transition timeout and received
the authoritative `{"result":"success"}` reply. Twenty-five seconds later the
observer still saw booted T2 `05ac:8233`, all BCE functions, CDC-NCM, and ANS2;
no recovery PID had appeared. The entire Mac then powered off. The previous
Linux journal ends at `12:50:48`, and the next boot began only after the user
powered the machine on at `12:55:24`. That boot again presents normal T2
`05ac:8233`.

This falsifies the same-running-host premise on the reference hardware. The
recovery command is functional, but its T2 power transition terminates the x86
Linux host before that host can observe or service T2 iBoot recovery. It is not
a missing Linux USB PID driver. A full-IPSW revive therefore requires an
independent USB host; the one physical Mac cannot be both target and restore
host across this boundary.

RestoreKit commit `7745cadad6b660dfb070504c8505bbe07f817e70`
already embeds pinned `idevicerestore`, but its CLI rejected iBoot recovery
before reaching the library. The carried patch
[`patches/restorekit/0001-allow-revive-from-iboot-recovery.patch`](patches/restorekit/0001-allow-revive-from-iboot-recovery.patch)
accepts an identified recovery device only for `Revive`; all erasing modes
remain DFU-only. The patched `restorekit 0.5.10` release binary builds on this
machine and links only the expected system runtime libraries plus libusb and
libudev.

Before the live Apple revive result, the remaining gates were:

- an independent restore host, which is unavailable in the current one-machine
  scope; or a newly recovered normal-mode primitive that reaches the exact
  creator without entering T2 recovery;
- a RAM-resident observation and an explicitly communicated manual hard-power
  fallback, because this Mac's firmware disables `iTCO_wdt` and the first
  direct-reboot guard is not proven to have fired successfully;
- staging the 742,609,165-byte IPSW, 14,072,304-byte patched client, cache,
  socket, and logs in tmpfs before the transition; and
- a post-revive observation proving xART/gigalocker exists before the Linux SEP
transport is allowed its one attempt.

The direct `reboot(2)` guard used in the first attempt has been removed from
the project. It left no persistent fire record and cannot be distinguished
from a platform restart hang. Do not claim an automatic last-resort reboot on
this hardware until a truly independent hardware mechanism is demonstrated.

### Live Apple Finder DFU Revive result

An independent M4 Mac completed Apple's non-erasing Finder DFU Revive against
this `iBridge2,14` target on 2026-09-01. The running bridgeOS subsequently
reported `PreviousRestoreDate = 2026-09-01 20:58:08 +0000`, build `23P6068`,
idle state, and a successful result. Its first cleanup pass independently
classified the event as a completed tethered restore.

A fresh constrained unified-log capture then observed the T2-owned
`EmbeddedDeviceTypeRoot` at `/dev/disk0`, its APFS container at `/dev/disk0s1`,
and synthesized container `disk1`. The post-Revive inventory found System,
Preboot, the existing encrypted user volume, and Hardware. It found no volume
named xART, no expected xART slice, and no post-Revive xART mount,
`seputil --gigalocker-init`, or `gigalocker: ONLINE` event. Only System,
Preboot, and the encrypted user-volume slices occur in the retained log.

Therefore Finder DFU Revive did **not** reconstruct the missing xART/gigalocker
state on this clean Linux-only reference Mac. Selecting the non-erasing Update
identity proved which ramdisk contains the creator, but did not prove that the
Revive operation invokes its filesystem-creation branch. Do not repeat Revive
for this blocker. Apple's destructive DFU Restore is now the remaining known
vendor operation that may select filesystem creation, but it is not authorized
by this result and must remain separate from Linux Touch ID execution.

The completed revive preserved the Linux installation and operated on T2
firmware, but preservation does not imply xART creation. The static separation
between T2 embedded media and the x86-visible ANS2 namespace remains correct.

Do not issue `restoreserviced` recovery again from this machine. With the
one-machine constraint, research returns to the normal-mode boundary: locate a
signed/vendor path that can run `create_apfs_filesystems` plus
`seputil --gigalocker-init`, or expose the T2 embedded APFS container through a
bounded service, without terminating the x86 host. The RestoreKit recovery
admission patch remains useful upstream work for conventional two-host setups,
but it is not the solution to self-hosting this Mac.

The matching normal-mode MobileStorage stack contains a read-only physical
`IOMedia` inventory, but it is not advertised to the Linux peer. Both bridge
RemoteXPC entries require Apple's private
`com.apple.private.mobile_storage.remote.allowedSPI` entitlement. A redacted
`CopyDevices` probe failed closed at service discovery and sent no command.
This closes MobileStorage as a current one-machine path; entitlement forgery is
outside the project boundary.

A plain bridgeOS restart is no longer a useful discriminator: it would rescan
the same T2-owned container, find the same missing volume, and leave D016's
host-side image invisible. Do not reboot solely for storage discovery.

## Portability rule

The implementation must discover the live service, embedded media, build
identity, and DeviceTree capability. `j152f` is the only tested reference, not
an allowlist baked into the protocol. On hardware without the xART capability,
the matching vendor path itself skips the volume. T1 extrapolation remains an
architectural question until its corresponding service and firmware contract
are recovered; it must not be claimed from this T2 result.
