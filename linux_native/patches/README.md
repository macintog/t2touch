# Patch handoff

## `applesmc-t2-sep-boot-state.patch`

Research target: Linux `v7.1.8`, Arch `v7.1.8-arch1`, plus the t2linux patch
series at commit `01a53a9d6a99ff86486b5bf42be816272165349a`. The prepared
baseline `applesmc.c` hashes to
`452f4d64aad251ecdcd300a4441e1f0a182815908cf072ad2c385e8faa1d055e`.

The patch adds a typed, disabled-by-default T2 boot-state transaction to the
existing serialized MMIO SMC driver. When explicitly enabled, it runs only on
the T2 MMIO transport, requires the exact 32-byte non-macOS sentinel
`fe 00 ... 00`, derives the six-component bridgeOS version from DMI, leaves
EFI-owned `EFMU` and `EFRO` untouched, writes a format-1 `EFMV` record, clears
the one-byte `EFMS` result, commits one-byte `EFBS = 0x11`, and polls `EFMS`
until bridgeOS returns a nonzero policy result or the matching Apple EFI
40-second limit expires. Its read-only result distinguishes pre-commit
failure from an uncertain post-write outcome and reports a received policy
byte. A later successful SEP capability reply is still required to prove that
bridgeOS launched the versioned apps.

Matching J152F Apple EFI recovered from bridgeOS 10.6 (`23P6068`) establishes
that exact ordering and timeout. It also corrects the earlier D127 inference:
`AppleSMC::smcSendNotify` uses `NSMN` as a generic platform-notification
transport whose first byte is fixed by the selected notification object;
`NSMN = 0b 11 00 00` is not the multiboot boot-state transaction.

The patch hashes to
`a3ed860e032b2f9bb2aa9d7f4c70f879b35b30c23f78c7db9adbea87750c4c24`.
Applied to the recorded baseline, the patched source hashes to
`ad5815ae45ee4ce631de97e17c87bac21575ac513b900ee788b61a14c2812c26`.
It compiled as a complete matching module with vermagic
`7.1.8-arch1-Watanare-T2-3-t2 SMP preempt mod_unload`; `applesmc.o` hashes to
`5d35942aa369a5c583e426d4e1f9995f7dbcd5ad2d9669f8f3f1df9dcae3c10e`
and the unsigned `applesmc.ko` to
`e570beb74d715c87547a352b3b6953fbd2119870ff31fd076b44a250c002709c`.
No automated test was added or run.

This is a research handoff. Before upstream submission, regenerate it with the
contributor's real authorship and `Signed-off-by` trailer and follow the
kernel/t2linux submission requirements.

## `apfsprogs-mkapfs-volume-role.patch`

Upstream target: [`linux-apfs/apfsprogs`](https://github.com/linux-apfs/apfsprogs)
at commit `3721463ba7f539e532907bc1d10ed5b9a97d0449` (`v0.2.1`).

The patch adds a generic `mkapfs -r <role>` option, accepts a 16-bit numeric
role in decimal, octal, or hexadecimal notation, and stores it in
`apfs_superblock.apfs_role`. It does not contain T2 board identifiers, create
an xART backing file, initialize a gigalocker, or alter an existing device.

Clean-base verification performed on 2026-09-01:

```sh
git clone https://github.com/linux-apfs/apfsprogs.git
git -C apfsprogs checkout 3721463ba7f539e532907bc1d10ed5b9a97d0449
git -C apfsprogs apply /path/to/apfsprogs-mkapfs-volume-role.patch
make -C apfsprogs/mkapfs
make -C apfsprogs/apfsck
truncate -s 16M role-0x100.img
apfsprogs/mkapfs/mkapfs -L interoperability -r 0x100 role-0x100.img
apfsprogs/apfsck/apfsck role-0x100.img
git -C apfsprogs diff --check
```

All commands succeeded. The generated image's SHA-256 in that run was
`9d9c68cbd15b67c06f892bdddcd354b05e88e3f4e6b8f3a6297bcf06389c6625`;
UUID generation means this is a run record, not a reproducible expected hash.
No test suite was generated or run.

Before mailing the patch, add the contributor's real `Signed-off-by` trailer
and use the upstream project's preferred submission channel. The carried
patch intentionally does not invent an identity on the contributor's behalf.

## `apfsprogs-mkapfs-xart-prerequisites.patch`

This is a research patch that also creates one preallocated root-directory
file in the initial APFS transaction. It records recovered xART prerequisites
but is not the first upstream submission: the generic volume-role change above
is smaller, independently useful, and cleanly separable.

## `restorekit/0001-allow-revive-from-iboot-recovery.patch`

This remains a research handoff for a two-host non-erasing T2 Revive. It must
not be used from the reference Mac: the successful recovery transition powers
off that Mac, so it cannot serve as its own restore host.

## `apfs-fuse-metadata-volume-group.patch`

Research target: `sgan81/apfs-fuse` commit
`66b86bd525e8cb90f9012543be89b1f092b75cf3`.

The patch adds an explicit metadata-only `ApfsContainer::Init` mode used only
by `apfsutil`, prints the already parsed APFS volume-group UUID, and adds the
missing standard integer header needed by current compilers. Normal callers
retain fail-closed key-manager initialization. It does not mount, decrypt, or
write an APFS container.

On the reference Mac it built with CMake and parsed the six macOS volume
superblocks directly from the partition. Two independent runs produced the
same private System/Data group identity; UUID output remains root-only and is
not part of this patch or repository.
