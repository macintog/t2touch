# Boot and persistent storage

The SEP can answer mailbox setup while its versioned applications are not ready.
AKS identities also depend on durable xART backing managed inside bridgeOS.
Host startup, internal service routing, and storage creation are distinct parts
of this path.

## Publishing boot state

The successful Linux startup reproduced the typed EFI/SMC publication sequence.
It preserved EFI-owned `EFMU` and `EFRO`, derived the bridgeOS version from DMI,
wrote format-1 `EFMV`, cleared the one-byte `EFMS`, and committed `EFBS = 0x11`.
It then polled `EFMS` within the recovered AppleEFI 40-second bound. A successful
AKS capability response established that the application was ready afterward.

A received byte is not itself readiness. The
[VirtualSMC EFMS reference](https://github.com/acidanthera/VirtualSMC/blob/master/Docs/SMCKeys.txt)
identifies 1 as `BootPolicyOk` and 3 as `BootPolicyReboot`. The installer accepts
only 1 for proceeding to independent service readiness, reports 3 as requiring
T2 boot-policy recovery, and blocks other outcomes. On a fresh Omarchy installation, the
patched publisher was observed returning 3 after its first kernel restart;
the response alone does not establish SEP app readiness. Private bridgeOS logs
subsequently showed successful `StartVersionedApps` calls followed by a
previous/current boot-volume UUID mismatch. The same bridgeOS boot session
survived multiple Linux reboots. Neither a normal Linux reboot nor an ordinary
poweroff cleared result 3 on that installation. A new Linux boot ID therefore
does not prove that the T2 restarted or accepted the new OS identity. The
operator then performed the documented physical SMC reset; the next Linux boot
reported result 1. Installation testing exposed a separate replacement-attempt
guard bug, so this policy result alone is not end-to-end qualification.

An earlier raw endpoint-0 `0x22` attempt confused an internal bridgeOS selector
path with an Intel mailbox command. The recovered `sepStartVersionedApps` caller
uses AppleSEPManager selector `0x11` inside bridgeOS. It does not establish a
corresponding raw Intel command.

## xART and gigalocker

The bridgeOS xART master, `xarm`, handles SEP-driven backing requests. It needs
both a checked-in master and a known backing path; either can arrive first.
The gigalocker file is `/private/xarts/<HOST-UUID>.gl`, with a 6 MiB backing size
on the analyzed build. Its host UUID is separate from the active OS UUID.

The internal `xars` command-8 path installs a 16-byte OS UUID. bridgeOS multiboot
chooses a volume-group UUID when present, otherwise the boot partition UUID,
and publishes it through AppleSEPManager selector `0x28`. This sets per-OS state;
it does not itself read the gigalocker or create its backing file.

Within the SEP, `sks` resolves the four-character `xART` service and uses its
handle for durable record loading. The recovered load path sends internal
command `0x271b`. The xART dispatcher subtracts `0x2711`, selects table entry 10,
and builds a master opcode-5 request. That is a concrete path from an AKS record
operation through internal IPC to bridgeOS backing storage.

In the matched payload, the `sks` call site is `0x001003f0`; the shared-runtime
handle dereference and IPC call are `0x00040d60` and `0x00040d6a`. The xART handler
is `0x000bb9e8`, with opcode-5 construction at `0x000bbdd4..0x000bbe02` and the
master-request routine at `0x000bad38`. These addresses belong to the
[identified firmware payload](artifacts-and-method.md), not to an Intel host binary.

## Why host endpoint-16 command 8 failed

Linux sent this four-word MMIO request and received this reply:

```text
request: 10080110 00000000 00000000 00000000
reply:   002d0110 00000000 00000000 0010ab00
```

The initial interpretation assigned status `0x2d` to a backing read failure.
Later dispatcher recovery contradicted it: the named `xars` command-8 handler
accepts a nonzero 16-byte UUID and returns zero, rejects an all-zero UUID with 1,
and rejects a wrong length with `0x16`. It has no `0x2d` result for the valid input.

Both `xars` and `AMDM` import aliases resolve to the same generic receive/send
functions in `libShared`. Their service handles select different queues.
The raw Intel endpoint-16 request reaches `AMDM`, which accepts commands 2–4 and
returns `0x2d` for command 8. Its tag/status reply construction accounts for the
captured payload. The Intel xART driver's callers cover session operations;
the OS-UUID caller resides inside bridgeOS.

This resolved the mismatch without a storage repair or another UUID choice.
Direct host command 8 was removed from native startup. Filesystem UUID changes,
extra startup delays, and keybag unlock ordering could not make a request reach
a different service queue.

## Creating embedded backing

The analyzed `seputil --gigalocker-init` path enables creation, while normal
`init_data_protection` startup uses an existing backing file. The restore path
creates an embedded APFS volume with role `x` (`0x100`), allocates 10 MiB to it,
and then creates the 6 MiB gigalocker. The matching `xartstoraged` executable is
an eight-byte success stub; the substantive implementation is in `seputil` and
AppleSEPManager.

The examined RemoteXPC services did not expose the targeted creator. The
advertised multiboot service accepts version-whitelist work, rather than arbitrary
execution of its internal SEP startup functions. A Finder DFU revive did not
create missing xART backing in the observed experiment. Later macOS provisioning
did establish backing, although the exact creation instant was not captured.

## Embedded NVMe is separate from host storage

The embedded controller is PCI `106b:2002`; the Linux-visible ANS2 host controller
is `106b:2005`. Creating an APFS role-`0x100` volume on the host disk does not
create a volume in the embedded T2 container.

In the analyzed embedded ABI, the 4096-byte Identify Namespace response has a
vendor namespace-type byte at offset `0x180`. Namespace ID and namespace type
are separate values. The namespace object stores ID at `0x88`, type at `0x8c`,
block size at `0x90`, and block count at `0x98`.

| Type | Name | Type | Name |
| --- | --- | --- | --- |
| 1 | Root | 8 | PanicLog |
| 2 | Firmware | 9 | AHCI |
| 3 | SysConfig | 10 | BIS |
| 4 | ControlBits | 11 | ME |
| 5 | NVRAM | 12 | Lifeboat |
| 6 | Effaceable | 13 | EAN |
| 7 | Calibration | 14 | PcieBootFirmware |

The embedded namespace user client requires
`com.apple.AppleNVMeNamespaceDevice.allow`. Its selectors are 0 read, 1 write,
2 block size, 3 block count, and 4 unmap; the recovered read path uses 4096-byte
alignment. Vendor command `0xc8` concerns physical NAND enumeration rather than
namespace discovery. The host's `AppleEffaceableRegistryID` association describes
APFS wrapping/media-keybag bookkeeping and supplies no embedded xART access.
