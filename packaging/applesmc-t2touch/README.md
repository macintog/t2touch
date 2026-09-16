# `applesmc-t2touch` DKMS prerequisite

This package-managed replacement supplies the typed T2 SEP boot-state
publisher required before t2touch can start bridgeOS biometric services. It is
not the t2touch transport and never owns the T2 PCI/DMA device.

The carried `applesmc.c` is Linux GPL-2.0-only source from Linux `v7.2.4`, plus
the Arch `v7.2.4-arch1` patch and the t2linux applesmc series at
`09d5f53e873cfeea0386077ce8b75f767d5a475e`. The resulting pre-t2touch source
hash is `a6c13be26763d65589722de270b9e241bb4d4d0bde3fc419764a4859ce026c60`.
Applying `linux_native/patches/applesmc-t2-sep-boot-state.patch` produces the
source with SHA-256
`9390325931138518aa768f9a3b0e6ffb85aad5ef3f8ad3e74f6848efeb60c84c`.
The patch applies unchanged to the current `linux-t2 7.2.4.arch1-2` source.

The carried source additionally replaces two `kzalloc_objs` calls with equivalent
`kcalloc` calls for older kernel headers. Its SHA-256 is
`4edb24f48a39b1f56522be4dd5d6f8c2650e8b1c63d279cf9a3c2ccff6d561a6`.
This source builds against `6.19.11-arch1-Watanare-T2-2-t2` with GCC
`16.2.1 20260810` on MacBookPro15,2. This is build validation only;
installation and live boot-state publication still require hardware validation.

The installer registers this source with DKMS only when the running applesmc
driver lacks `/sys/module/applesmc/parameters/t2_sep_boot_state`. It rebuilds
the initramfs, then stops before configuring t2touch: the replacement cannot
safely take over from an already loaded in-tree driver. After the next ordinary
kernel start, rerunning the installer requires the live sysfs parameter and may
continue in the current session.

This **adapts** T1Bridge's package-managed DKMS delivery. It **rejects** the T1
unload/rebind model: t2touch does not unload either a live applesmc instance or
the separately pinned T2 transport to complete installation.
