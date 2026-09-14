# Normal-mode signed service boundary for xART creation

This note records the bounded normal-mode service check on the reference
MacBookPro16,1.  It is not a catalog of bridgeOS services.  The question was
whether a service that the running Linux RemoteXPC peer can actually discover
owns a typed, non-destructive path to the embedded APFS container needed to
create xART.

## Matching and live evidence

The inspected root is the extracted public bridgeOS `10.6 (23P6068)` system
for `iBridge2,14`/`J152fAP`.  On 2026-09-01 the running T2 advertised 27
services through its nonempty RSD control endpoint.  The inventory was read
again after the storage-boundary work; it was unchanged and included the
restore, software-update, sysdiagnose, mobile-obliteration, multiboot,
BiometricKit, LASecureIO, and developer-instrumentation services.  It did not
include either entitlement-protected MobileStorage proxy service.

Each advertised service was mapped back to its matching launchd owner.  Those
executables were then checked for APFS, `IOMedia`, `newfs_apfs`, `seputil`,
gigalocker, xART, DiskArbitration, MobileStorage, and StorageKit dependencies
or strings.  Only three relevant owners remained:

| Advertised owner | SHA-256 | Relevant behavior | Decision |
| --- | --- | --- | --- |
| `/usr/libexec/restoreserviced` | `c5bb4d668bac753cfb25b2817c0b507d5f1a54152956343bbed6139c45374a01` | Links APFS and has restore-media helpers, but its normal-mode command dispatcher has no filesystem-creation command. The only creator-bearing full-IPSW path requires a recovery transition that powers off this x86 host. | Closed; never send `recovery` again on the reference Mac. |
| `/usr/libexec/sysdiagnosed` | `3ca509c24c213897e913c1a0f3707bbb51054e8b5280e04553cedbf0b600e5a7` | Its fixed diagnostic container invokes `/usr/libexec/seputil --rawlog` and writes `sep_util.log`. The matching `seputil` help defines this as an undecoded mailbox-log dump. | Observation only; no creator contract. |
| `/usr/libexec/mobile_obliterator` | `50f83ad3ef1999a91480191e6e56411c9e01cd1a74fecd7b6aa73cc9d08e0a77` | Deletes or reformats data, wipes APFS keys, cleans xART, and tells SEP to obliterate gigalockers. | Destructive inverse of provisioning; quarantined. |

The mobile-obliteration binary was checked one level deeper because it carries
the only remaining xART strings.  `epdm_fixup_xart` is a logging/exception
label around post-obliteration xART cleanup, not a callable creator.  Its only
`newfs_apfs` helper is named `reformat_volume`, hard-codes the label `Data`,
and is called from data-volume obliteration paths.  The `NoDelete` option skips
deletion but still creates and formats that Data volume.  None of these paths
creates the missing xART volume or performs gigalocker initialization, and
none is safe to probe.

`com.apple.instruments.dtservicehub` belongs to a developer-mode launch job
and requires the private Instruments client entitlement.  Its matching binary
has no storage dependency from the bounded check.  Generic debugging or code
execution is not a typed storage contract and is outside this project's
normal-mode provisioning boundary.

The x86 RecoveryOS service graph does not provide an alternate crossing.
`AppleEmbeddedOSSupportHost` owns bridge availability, identity, reset, sleep,
and power-state plumbing; it publishes no embedded-media or APFS operation.
`AppleBCENORFlashDevice` implements the fixed-region
`ExchangeProtocolVersion`, `GetRegionCount`, `GetRegionSize`, `ReadRegion`,
`WriteRegion`, and `EraseRegion` protocol used by `AppleEffaceableBCE`. That is
effaceable NOR storage, not the T2-side NVMe/APFS namespace. Neither object is
a narrowly typed delegate for xART-volume creation.

## Result

No service advertised to this Linux peer, and no matching host BCE support
object, exposes a typed, non-destructive
xART creation operation.  This independently closes the signed RemoteXPC
route without broadening the search into arbitrary execution or unsafe vendor
commands.  The unadvertised MobileStorage proxy remains entitlement-gated and
read-only.  Host ANS2 opcode `0xc8` is a physical-NAND descriptor rather than
a namespace path, while the production tunnel remains untyped and
quarantined.

Under the one-machine constraint, missing embedded xART/gigalocker state is a
physical provisioning blocker for a first SEP identity transaction on this
clean-wiped machine.  The portable supported repair remains a non-erasing
full-IPSW Revive hosted by a second computer.  Static recovery of later
keybag/Catacomb protocol layers can continue, but it must not be represented
as hardware validation past this prerequisite.

No mutating RemoteXPC request, NVMe vendor command, biometric request, or SEP
identity request was sent for this check.

D124 revisits this boundary after proving command 8 is bridgeOS-internal. The
result is unchanged but more specific: `multiboot` is the exact selector-0x28
caller, while its advertised `com.apple.xpc.remote.multiboot` listener accepts
only a `version` string for the bridge-version whitelist. Biometric BridgeXPC
terminates at the separately advertised `bkremoted` service. Neither is a
typed delegate for AppleSEPManager selector `0x28`; direct x86 PCI endpoint 16
instead reaches the AMDM commands-2–4 loop. No remote request was sent for this
static correction.

## Shutdown is not a normal-mode provisioning shortcut

The matching update ramdisk also exposes
`seputil --gigalocker-shutdown`. It reaches AppleSEPManager userclient selector
`0x2e`; Ramrod calls it only in the restore/update lifecycle, after waiting for
the APFS container reaper when applicable. In-kernel AppleSEPManager then
coordinates an xART-disable acknowledgement set before the embedded xART SEP
slave shutdown can complete.

This is a destructive-state-transition boundary, not a creator, attachment
repair, or ordinary host-reboot hook. It must not be invoked through arbitrary
execution or used as a substitute for Linux-native master attachment. D118's
exact binaries and disassemblies are retained read-only in
`D118-bridgeos-xart-lifecycle-static-20260903T203500Z`.
