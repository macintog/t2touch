# Reconstructing the clean-install xART volume

## Recovered storage contract

Matching bridgeOS `23P6068` restore code establishes the disk prerequisite for
gigalocker creation:

- the internal GPT contains an Apple APFS container partition whose content
  type is `69646961-6700-11AA-AA11-00306543ECAC`;
- that container has an APFS volume named `xART` with role `0x100`;
- Ramrod mounts the partition at `/mnt7` and executes
  `/usr/libexec/seputil --gigalocker-init`;
- seputil creates the host-UUID `.gl` file at exactly 6 MiB, migrates any old
  records, and attaches the backing store; and
- normal boot later mounts the xART-role volume at `/private/xarts` and invokes
  only the attach form of the same seputil routine.

The GUID and role are storage capabilities, not J152f board constants. The
matching DeviceTree decides whether the device should have xART; the same APFS
role is defined by public `apfsprogs` and used by m1n1's existing gigalocker
reader.

## Reference-machine state

Read-only GPT inventory on 2026-09-01 found only a 2 GiB EFI System Partition
and the Linux LUKS root partition. No Apple APFS container or xART-role volume
survived the clean wipe. This directly satisfies Ramrod's logged condition
"build supports xART but no xART volume present" at the disk-layout level;
the live bridgeOS log itself has not yet been collected.

The internal SSD uses 4096-byte logical sectors. The Linux root contains far
more unallocated Btrfs space than the small xART container requires, but any
partition-table change remains a separately journaled destructive operation.
Exact private disk and partition UUIDs stay in ignored artifacts, never in the
repository.

## Upstreamable APFS tool change

Public `apfsprogs` commit `3721463ba7f539e532907bc1d10ed5b9a97d0449`
already defines `APFS_VOL_ROLE_XART` and validates that role in `apfsck`.
`mkapfs` creates a valid empty single-volume container but previously left
`apfs_role` at zero with no CLI override.

[`patches/apfsprogs-mkapfs-volume-role.patch`](patches/apfsprogs-mkapfs-volume-role.patch)
adds a generic numeric `-r` option and writes the selected 16-bit role to the
volume superblock. The option is not xART-specific and can represent other
special-purpose APFS volumes.

The handoff patch was reapplied from scratch to public upstream commit
`3721463ba7f539e532907bc1d10ed5b9a97d0449` on 2026-09-01. Both `mkapfs` and
`apfsck` built in that clean detached tree; `mkapfs -r 0x100` created one
16 MiB image; upstream `apfsck` accepted it; and `git diff --check` passed.
This was one pivotal smoke check, not a generated test suite. Reproduction and
submission notes are in [`patches/README.md`](patches/README.md).

Static recovery of seputil's creator added a second exact requirement. It opens
the host-UUID path exclusively with mode `0600`, requests physical allocation
with `F_PREALLOCATE`, and truncates it to `0x600000` bytes. A sparse placeholder
is not an equivalent prerequisite.

The combined
[`patches/apfsprogs-mkapfs-xart-prerequisites.patch`](patches/apfsprogs-mkapfs-xart-prerequisites.patch)
adds the role option plus a generic `-f name:size` option for one root-owned,
preallocated file. It creates the catalog, dstream, physical extent reference,
spaceman bitmap, and volume accounting in the initial transaction. No xART,
J152f, or machine UUID is hard-coded.

The final 128 MiB image used role `0x100` and one 6 MiB preallocated `.gl`
file. Its private name is the uppercase Apple platform UUID exposed through
SMBIOS/DMI. The image passed `apfsck`. One earlier pivotal validation rejected
the first uppercase-name hash and led to the required APFS ASCII case-folding
correction. No test suite was run.

## Hardware experiment gate

The reference machine completed this journaled operation:

1. preserve a read-only GPT dump in ignored artifacts;
2. shrink the Btrfs device below the proposed new encrypted-partition end;
3. reduce the active dm-crypt mapping to that exact safe boundary;
4. shorten only the tail of the Linux GPT partition by 128 MiB;
5. create a 128 MiB entry using the recovered Apple APFS content GUID;
6. write the `apfsck`-clean role-`0x100` container with its preallocated file
   only to that exact region; and
7. compare SHA-256 of the complete raw region with the source image.

The hashes matched. GPT verification, active dm-crypt length, Btrfs device
length, and intentional safety slack were rechecked immediately before the
write. Private disk, partition, filesystem, and platform UUIDs remain only in
ignored artifacts or live machine state.

The success discriminator is the existing one-shot path: xART opcode 8 must
return zero, after which endpoint 7 may register. A repeated `0x2d` fails
closed and ends the generation without retry. This experiment does not create
a Linux account identity, touch BiometricKit, enable authentication, or modify
PAM.

## Reference result

Boot `16b6bad4-194e-4e6a-bda4-1595347a4bf7` preserved the new GPT entry and an
`apfsck`-clean APFS volume, but xART opcode 8 still returned `0x2d`. Endpoint 7
did not register. The complete partition hash remained identical to the source
image, so bridgeOS made no persistent APFS change. The layout, role, and
preallocated filename are therefore necessary-looking restore artifacts, not a
proven substitute for seputil's live creator and attachment sequence.

### BridgeOS correlation correction

A subsequently recovered bridgeOS unified-log archive first showed that the
Linux reboot did not restart bridgeOS. Static recovery plus an earlier matching
boot log now resolves the remaining ambiguity: Ramrod locates
`EmbeddedDeviceTypeRoot` at bridgeOS `/dev/disk0`, follows its APFS container
from `/dev/disk0s1` to synthesized `disk1`, and searches only that I/O Registry
subtree. Linux `/dev/nvme0n1p3` is outside the discovery namespace.

The matching update ramdisk also shows that Apple creates xART as a 10 MiB
volume *inside that existing embedded container* using
`newfs_apfs -s 10485760 -A -D -o role=x -v xART ...`, then runs
`seputil --gigalocker-init`. D016's 128 MiB host-side standalone container is
therefore not a cold-boot candidate. Do not spend a reboot on it. Matching
normal software-update payloads explicitly disable filesystem-partition
creation, so the next repair candidate is the non-erasing full-IPSW
restore/revive path documented in
[`BRIDGEOS_UPDATE_XART_RECOVERY.md`](BRIDGEOS_UPDATE_XART_RECOVERY.md).
