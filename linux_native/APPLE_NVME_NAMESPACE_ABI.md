# Apple embedded-NVMe namespace ABI

This note records the bounded storage ABI recovered while looking for a
one-machine route to the missing bridgeOS xART volume. It does **not** authorize
an NVMe command on the running Linux system. The principal result is that the
bridgeOS namespace ABI and Linux's host ANS2 device terminate at different PCI
interfaces.

## Provenance

The bridgeOS evidence is from the public `iBridge2,..._10.6_23P6068_Restore.ipsw`
selected for `iBridge2,14`/`J152fAP` by its manifest:

- production bridgeOS kernelcache
  `kernelcache.release.iBridge2,3_4_7_8_10_12_14_15_16_21_22`, SHA-256
  `578530d4a6c57861de55320ff5ec5e11b14bf3f4b8e4eaa31cbcb76660bda2e9`;
- update-ramdisk `AppleNVMe.framework/AppleNVMe`, SHA-256
  `a459de422ae1909536e9e90f05d540580deb93425e3ddcd2169d76321e73467b`;
- normal bridgeOS `/usr/libexec/DumpPanic`, SHA-256
  `dc96979cbe2565201dbab448b666b41cd0140794d32ee36043d8c579a5e3902f`;
  and
- normal bridgeOS `System/Library/xpc/launchd.plist`, SHA-256
  `151f59b3d49e0b9138460280c0f41572006c999434a3423e1019ff52f7e2d09a`.

The x86 host comparison is from the installed RecoveryOS BaseSystem:

- `BootKernelExtensions.kc`, SHA-256
  `c80161fa3065883753fc285339281361a8469cbb6fb27653c88e2a22eb4807a4`;
- `BaseSystemKernelExtensions.kc`, SHA-256
  `60d3f43f1a23847aa8b60b7c57153fd93d20d0653c116d14da4875f09e5d2f04`;
  and
- extracted `com.apple.iokit.IONVMeFamily`, SHA-256
  `e560849664894bd670e646e83a70a4bd8cbb8db7c0048418ac2e86d595a00049`.

Extracted Apple artifacts remain below the ignored `linux_native/artifacts/`
tree and must not be committed or redistributed.

## Recovered bridgeOS namespace model

The matching IONVMeFamily personality binds its internal
`AppleEmbeddedNVMeController` to PCI ID `106b:2002`. During controller setup it
enumerates namespace IDs, submits standard NVMe Identify Namespace, and reads
one Apple namespace-type byte at offset `0x180` in the 4096-byte identify
response. Values below 15 are recorded in an NSID-to-type table. NSID and type
are distinct values; neither may be inferred from the other.

The recovered type enumeration is:

| Type | Name | Type | Name |
| ---: | --- | ---: | --- |
| 1 | Root | 8 | PanicLog |
| 2 | Firmware | 9 | AHCI |
| 3 | SysConfig | 10 | BIS |
| 4 | ControlBits | 11 | ME |
| 5 | NVRAM | 12 | Lifeboat |
| 6 | Effaceable | 13 | EAN |
| 7 | Calibration | 14 | PcieBootFirmware |

For each published namespace, `AppleNVMeNamespaceDevice` retains NSID at
object offset `0x88` and namespace type at `0x8c`. It obtains block count and
the active LBA format from Identify Namespace, records block size at `0x90`
and block count at `0x98`, and services I/O as ordinary NVMe commands addressed
to the retained NSID. Its read path requires 4096-byte alignment.

Important matching-kernel locations are:

| Function | Virtual address | Recovered behavior |
| --- | ---: | --- |
| controller enumeration | `0xfffffff006b8e220` | Identify each NSID; load type from byte `0x180` |
| namespace-device factory | `0xfffffff006b8dca4` | publish device for the discovered NSID/type pair |
| device initialization | `0xfffffff006ba345c` | retain NSID and type |
| property discovery | `0xfffffff006ba3700` | Identify Namespace; derive geometry |
| read wrapper/internal read | `0xfffffff006ba38dc` / `0xfffffff006ba397c` | aligned, range-checked NVMe read |
| write | `0xfffffff006ba3bb0` | mutating; quarantined |
| block size/count | `0xfffffff006ba3ed8` / `0xfffffff006ba3f14` | return cached geometry |
| unmap wrapper/internal DSM | `0xfffffff006ba3f4c` / `0xfffffff006ba3fd0` | mutating; quarantined |

## User-client contract

`AppleNVMeNamespaceUC` refuses to open unless the caller has Boolean entitlement
`com.apple.AppleNVMeNamespaceDevice.allow`. Its external-method dispatcher at
`0xfffffff006ba545c` rejects selectors greater than 4 and maps exactly:

| Selector | Operation | Project classification |
| ---: | --- | --- |
| 0 | read | read-only after alignment/range validation |
| 1 | write | mutating; forbidden |
| 2 | get block size | read-only |
| 3 | get block count | read-only |
| 4 | unmap | mutating; forbidden |

The framework read call takes `(buffer, offset, length)` and sends the scalar
triple `[buffer_address, length, offset]`. Kernel-side validation requires
aligned offset, length, and buffer address and rejects a range past the cached
block count.

`DumpPanic` is the only recovered normal userspace executable containing the
AppleNVMe entitlement key. It imports
`AppleNVMeDeviceSupportsPanicLogAccess`, `AppleNVMePanicLogGetSize`, and
`AppleNVMeReadPanicLogData`. Its launch entry is a local `RunAtLoad` job with
`KeepAlive/Crashed=true`; it has no `MachServices`, `RemoteServices`, socket,
or XPC listener. It is therefore a consumer, not an existing signed delegate
available to Linux.

## Hard transport boundary

The bridgeOS namespace code above runs on the T2-side `106b:2002`
`AppleEmbeddedNVMeController`. The running Linux host instead sees PCI
`106b:2005` and binds it as the x86-visible Apple ANS2 controller. Read-only
standard Identify on that interface reported one namespace: the complete
Linux disk. This is not the bridgeOS embedded controller and its user-client
selectors cannot be replayed against `/dev/nvme0`.

The x86 RecoveryOS driver independently corroborates the separation:

- its `AppleANS2Controller` personality matches `ANS2`, the logical interface
  Linux is already driving;
- its startup searches for `AppleEffaceableStorage` below
  `AppleBCENORFlashDevice`, records that service's registry-entry ID as
  `AppleEffaceableRegistryID`, and then enters the ordinary inherited NVMe
  start path; and
- it contains command builders for Apple opcodes `0xc6`
  (`BuildCommandCreateNamespaces`), `0xc8`
  (`BuildCommandIdentifyStorageDevice`), and `0xd8` (`BuildCommandTunnel`).

The names and opcode bytes alone do not establish a safe command contract.
Opcode `0xc6` is explicitly destructive.  Static recovery now closes `0xc8`
as a candidate for this task: `BuildCommandIdentifyStorageDevice(unsigned)`
sets vendor opcode `0xc8`, clears the command ID, and places its sole 32-bit
argument in command dword 13.  The matching x86 kext contains no caller.
Independent public ANS2 boot output shows the command used after ordinary
namespace discovery to enumerate physical NAND devices by index (vendor,
device, NAND description, firmware, controller ID, and ASIC revision).  It is
not an alternate namespace inventory and cannot expose the T2-side APFS
container.  The public observation is
[`JCRW.txt`](https://gist.github.com/networkextension/266dfe649d6c1dad26f1d371d3768daf#file-jcrw-txt).

The production tunnel remains too broad for this project.  No `0xc6`, `0xc8`,
or tunnel command was sent; all remain quarantined.

### The ANS2 effaceable property is host-APFS plumbing

The `AppleEffaceableRegistryID` publication is now traced to its consumer and
does not supply a missing controller command. RecoveryOS APFS function
`_kb_effacer_create` walks from the physical-store device, reads both
`AppleKeyStoreRegistryID` and `AppleEffaceableRegistryID`, resolves the latter
back to the exact `AppleEffaceableStorage` service, and retains that object for
the host container's wrapping-keybag and media-keybag paths. The property has
no second reference in `IONVMeFamily`; `AppleANS2Controller::start` sends no
vendor command before its inherited start call.

The installed `7.1.8-arch1-Watanare-T2-3-t2` package was also reconciled to
its exact public packaging and patch inputs. Its T2 patchset does not patch
`drivers/nvme/host`. Linux v7.1.8's generic PCI NVMe driver binds `106b:2005`
with the five established ANS2 quirks: single interrupt vector, 128-byte I/O
SQEs, shared tags, bounded command IDs, and NVMe-1.0-style namespace identify.
The corresponding upstream changes describe controller I/O correctness, not
bridgeOS embedded-media ownership or xART activation.

Apple's derived NVMe initialization adds wall-time initialization, optional
QoS bandwidth setup, logger setup, and a housekeeping timer around the common
controller initialization. None is an xART, gigalocker, BCE-NOR, or embedded
NVMe operation. Reproducing the I/O Registry property in Linux would therefore
create no route to bridgeOS `106b:2002` and is not an implementation target.

## Consequence and next boundary

There is no justified Linux `/dev/nvme0` discovery primitive to implement from
this ABI. The follow-up x86 service-graph trace closed the proposed BCE route:
`AppleEmbeddedOSSupportHost` provides bridge identity, reset, sleep, and power
plumbing but no embedded-media operation, while `AppleBCENORFlashDevice`
exports fixed-region read/write/erase operations solely for
`AppleEffaceableBCE`. That NOR protocol is not the T2-side NVMe/APFS namespace.

The exact D117 sources, kernel collection, four extracted kexts, focused
disassemblies, and hashes are retained in root-owned artifact
`ans2-effaceable-static-20260903T194848Z`. Read-only snapshots
`D117-ans2-effaceable-static-20260903T194848Z` and
`D117-ans2-effaceable-static-complete-20260903T194848Z` preserve the initial
and complete checkpoints. No NVMe command, SEP request, service change, test,
or reboot was performed.

A correct one-machine path must therefore cause a signed T2-side component to
operate on `106b:2002` through a recovered, narrowly typed contract. No such
normal-mode contract is currently advertised; a raw NVMe vendor command,
generic tunnel, entitlement forgery, or arbitrary-execution route remains out
of scope.

The already verified non-erasing full-IPSW revive remains the reference vendor
creator, but it requires a second physical host because the recovery transition
powers off this Mac's x86 host.
