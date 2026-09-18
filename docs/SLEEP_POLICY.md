# Sleep policy and migration

T2Touch does not select a machine-wide sleep mode. Suspend/resume is not
qualified on the MacBookPro16,1 reference system: s2idle has failed to wake the
host, while deep sleep has left the T2 transport unusable in inherited
MacBookPro16,2 testing. A successful desktop resume does not prove working
Touch ID, and a configured mode does not prove either.

## Older installations

Older versions installed
`/etc/systemd/sleep.conf.d/90-t2-touchid-s2idle.conf`, overriding the kernel's
sleep default. This was inherited from the fork base; T2Touch owns its cleanup.

Install and uninstall now retire that file only if it is a regular, singly
linked, root-owned file with the exact content T2Touch shipped. The original
is retained alongside it with a `.t2touch-retired` suffix, which systemd does
not load. Modified files, symlinks, unexpected ownership, and conflicting
backups are preserved with a warning. Repeated migration is safe, including
after an older installer recreates the original policy.
If interrupted after creating the archive link, migration can finish on retry
only when the two expected names are the sole links to the unchanged original.
Additional links or intervening edits remain preserved.

Removing the override makes subsequent sleep requests follow remaining
systemd and kernel policy. On the reference Omarchy installation, this exposes
the `deep` boot default. **This migration is not a suspend repair or a claim
that deep is safe.** It does not change the current kernel mode, initiate
sleep, install a replacement mode, or disable suspend. Automatic-suspend
containment and hardware experiments belong to the machine operator.

Review the effective configuration with:

```sh
systemd-analyze cat-config systemd/sleep.conf
cat /sys/power/mem_sleep
```

The second command shows the current kernel selection, which systemd may
override at the next request. The doctor reports both configuration layers and
warns about the unqualified resume path.

## Systems that deliberately retain s2idle

An operator with independent qualification for their own machine can maintain
a standalone systemd drop-in under an operator-owned name, for example
`/etc/systemd/sleep.conf.d/80-local-sleep-mode.conf` with:

```ini
[Sleep]
MemorySleepMode=s2idle
```

This is a description of how to preserve an existing deliberate choice, not a
recommendation to test or enable it on the failing reference machine. Local
files must not reuse T2Touch's retired filename. T2Touch will neither install
nor remove this operator-owned configuration. Rollback of the standalone
choice is removal of that local file followed by inspection of effective
policy. Keep the retired original as evidence; restoring it restores the
known policy risk as well.

## Diagnosis and ownership

Platform GPU, PCI, firmware, and T2 BCE driver fixes belong with the applicable
kernel/distribution component. T2Touch remains responsible for its sleep
quiescence, transport usage, authentication recovery, and installed artifacts.
Do not unload the pinned SEP transport, or substitute USB/PCI rebinding, to
recover a broken transport. Reboot is the known recovery boundary.

Before public reporting, redact kernel/device identifiers and private data.
Record the actual entered mode, kernel/T2 driver revisions, and which device
first failed. Do not infer a kernel regression from an update alone, or call a
single successful wake reliable support.

### Reference-machine results

On MacBookPro16,1 with Linux `7.2.6-arch2-Watanare-T2-2-t2`, a fresh-boot test
with T2Touch services and its SEP module inactive still failed AMD's noirq
suspend callback with `-110`. The same systemd request then fell back to
s2idle and required forced recovery. This was not an isolated deep-sleep test.

The result shows that active T2Touch services and drivers are not required
for that failure sequence. It does not rule out additional T2Touch problems.
Neither sleep mode is established as reliable on this machine. Retiring the
old drop-in returns sleep-mode selection to the remaining system configuration.
