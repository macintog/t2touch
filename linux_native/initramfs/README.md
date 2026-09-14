# Pre-NVMe xART discriminator

> **Permanently quarantined:** D113 booted into an unusable initramfs and did
> not preserve whether its one xART request ran. Never rebuild, install, or boot
> this generation. The install hook now fails unconditionally; the remaining
> files are forensic source only.

This directory holds one isolated initramfs generation for D112's remaining
storage-ownership discriminator. It is not a production boot path.

The systemd unit is ordered before both module loading and udev coldplug. Its
owner resolves the Apple ANS2 and SEP PCI functions by vendor/device identity
and refuses to contact SEP if ANS2 already has a driver. Otherwise it loads the
existing `t2_sep_transport` with one immediate opcode-8 publication, proves
the SEP driver bound while ANS2 remained unbound, then loads `nvme` in its exit
trap so the normal encrypted root boot can continue after success, protocol
failure, or a guard rejection.

The build-time hook overwrites only the initramfs copy of the installed
transport options. The canonical xART UUID is supplied through a root-owned
mode-`0600` `/etc/t2-xart-pre-nvme.conf` generated on the reference machine;
no stable machine identifier belongs in Git.

The boot result consists of the kernel's exact xART status plus the small
identifier-free `/run/t2-xart-pre-nvme.result` ordering record. A request is
material only when that record says `xart-completed-before-nvme`. Any skip or
ordering violation closes the generation without retry.

Building or booting this artifact does not authorize a new EFI/NVRAM entry,
`BootNext`, startup-disk change, service activation, or second request.

## D114 diagnosis

The direct build passed an alternate `-c` file below `/var`, so mkinitcpio used
that file's base settings but did not source `/etc/mkinitcpio.conf.d`. The
result omitted `dm-crypt`, `cryptsetup`, and the `encrypt` hook required by the
reference machine's encrypted root. It entered emergency mode before mounting
the real root.

The known-good Omarchy initramfs also uses BusyBox, where `run_earlyhook`
executes before module loading and the ordinary udev hook. D113 instead added a
systemd unit, so its orchestration was not compatible with the actual image
construction path. Both defects are proven from the retained UKIs. A future
design would need a BusyBox early hook built through the normal mkinitcpio
drop-in pipeline, but D113's ambiguous xART outcome forbids replaying that
experiment.
