# Disposition: T2 network transport dies after deep-sleep resume

Status: **external, reported upstream, fix pending review.** T2Touch ships no
part of this repair. This record follows the
[required disposition of unrelated findings](../PROJECT_SCOPE.md#required-disposition-of-unrelated-findings).

## Symptom

After a deep (ACPI S3) sleep with a stateful BCE restore, the `cdc_ncm`
interface to the T2 controller on virtual USB port 1 stays `UP` but never
completes a transmit again:

```text
PM: suspend exit
cdc_ncm 5-1:1.0 <iface>: NETDEV WATCHDOG: CPU: 0: transmit queue 0 timed out
t2bce_vhci: [01] pause timeout waiting for 1 outputs
NETDEV WATCHDOG ...   (every ~5 s until reboot)
```

That link carries BridgeXPC, so `t2-biometric-ready.service` fails on its
next start and the doctor reports `bridge-network: cached BridgeXPC endpoint
unreachable` and `suspend-health: T2 network watchdog timeout seen this
boot`. Keyboard, trackpad, Touch Bar, ambient light sensor and audio are
unaffected. A six-second sleep reproduces it; the sleep length is irrelevant.

## Affected component

`t2bce_vhci`, the virtual USB host controller of the T2 BCE driver stack
(`deqrocks/t2bce`), built into the linux-t2 kernel from
`t2linux/linux-t2-patches` (`1001-Add-t2bce-driver-stack.patch`, generated
from `AdityaGarg8/t2bce`). Not T2Touch, not its DKMS SEP transport, not
`fprintd`, not systemd sleep policy.

## Reproduction

Reference machine: MacBookPro16,2, Linux `7.1.8-arch1-Watanare-T2-3-t2`
(t2bce in-tree source identical to `linux-t2-patches@b71434b`, i.e.
`deqrocks/t2bce@967465d`), `mem_sleep_default=deep`, no systemd sleep
override. `systemctl suspend`, wake after ~15 s, wait 10 s. The bridgeOS build
was not queried for this record.

## Evidence and cause

Confirmed with `dynamic_debug` on `t2bce_vhci` across four instrumented
sleeps and one interface-driver rebind:

- Healthy protocol: the T2 keeps one bulk-OUT read credit (`TRANSFER_REQUEST`
  event `0x1000`) outstanding on endpoint 01 and re-posts one after every
  completion; a freshly created endpoint receives four.
- After the stateful restore the T2 posts **no** credit for the preserved
  endpoint. The credit parked in the driver's deferred-event list before sleep
  is consumed by the first TX URB; its DMA never completes (the single
  `pause timeout` line); every later OUT URB waits for a credit that never
  comes. The DMA ring and command path are intact: the watchdog-triggered
  flush receives its abort completion, and preserved IN endpoints (ALS on
  port 3) keep working.
- Host-controller actions that do **not** re-arm the T2 (each accepted with
  status 0, zero credits afterwards): `ENDPOINT_SET_STATE` active,
  `ENDPOINT_RESET`, endpoint destroy/create on the existing DMA queues, and a
  full transfer-queue rebuild plus endpoint destroy/create.
- Unbinding and rebinding the `cdc_ncm` interface driver restores the link
  within 25 ms. What that adds is `usb_set_interface()`, i.e. `SET_INTERFACE`
  to the device: the credits are the T2's gadget-side NCM function posting its
  reads, and only device-side re-activation restores them.

Confirmed cause: device function state for bulk-OUT endpoints is not preserved
across stateful sleep. Hypothesis only: whether bridgeOS considers this a
firmware bug or the expected host behaviour (it already disconnects and
recreates the keyboard on every resume).

Earlier hypotheses ruled out by the traces: silent endpoint-pause failure,
DMA ring desynchronisation, and the upstream cancel-order change (`a973d53`).

Instrumented traces (kernel log with MAC and IPv6 addresses redacted) are held
by the reporter and are not part of this repository.

## Upstream report

Fix: during a stateful resume the virtual hub reports ports whose device has a
non-EP0 OUT endpoint as connected but not enabled until usbcore resets them,
so usbcore reset-resumes the device (`usb_reset_and_verify_device()` restores
configuration and interfaces, then the interface driver's `reset_resume`). The
network device survives; ~20 ms added to resume, completed before
`PM: suspend exit`. Devices with only IN endpoints resume in place as before.

| Repository | Pull request | Status (2026-09-19) |
| --- | --- | --- |
| `deqrocks/t2bce` (origin) | [#8](https://github.com/deqrocks/t2bce/pull/8) | open, awaiting review |
| `AdityaGarg8/t2bce` (source of the linux-t2 in-tree patch) | [#1](https://github.com/AdityaGarg8/t2bce/pull/1) | open, awaiting review |
| `t2linux/linux-t2-patches` | none needed; regenerated from the above by its `bce.yml` workflow | pending the merge |

Both variants were validated on the reference machine: no watchdog, TX with
zero errors, BridgeXPC reachable, Touch ID authenticating after resume, across
separate boots with and without tracing. The `AdityaGarg8` tree (t2bce_core
0.07) was tested as a whole out-of-tree stack on the 7.1.8 kernel with audio,
keyboard, trackpad and Touch Bar confirmed working.

## Local workaround (operator-owned, not T2Touch)

Until the fix ships in a linux-t2 kernel, the reference machine runs the
patched modules from the operator's build:

| Item | Value |
| --- | --- |
| Files | `/lib/modules/<running kernel>/updates/t2bce_{core,dma,vhci,audio}.ko` |
| Source | operator clone of `AdityaGarg8/t2bce` at PR #1, built with `make` against the running kernel headers |
| Precedence | `updates/` is first in `depmod` search order and overrides the in-tree `drivers/staging/t2bce` copy; the UKI is rebuilt with `limine-mkinitcpio` so early boot loads the same modules |
| Ownership | the machine operator. T2Touch `install.sh`, `uninstall.sh`, upgrades and the doctor neither install, verify, nor remove these files |
| Verification | `modinfo -F filename t2bce_vhci` points into `updates/`; after a sleep the doctor reports `bridge-network` reachable and `suspend-health` clean; the only default-loglevel trace is `usb 5-1: reset high-speed USB device number N` |
| Lifetime | survives reinstalling the same kernel package; a kernel version upgrade gets a fresh `/lib/modules/<ver>/` without `updates/` and reverts to the in-tree driver (fixed or not) |
| Rollback | `rm /lib/modules/$(uname -r)/updates/t2bce_*.ko && depmod -a && limine-mkinitcpio`, then reboot; the previous UKI also remains selectable in Limine's history menu |

Operator-level recovery without reboot, used as a diagnostic during this
investigation: unbind and rebind the `cdc_ncm` interface driver for `5-1:1.0`
under `/sys/bus/usb/drivers/cdc_ncm/`. T2Touch does not perform this and the
[sleep policy](../SLEEP_POLICY.md#diagnosis-and-ownership) is unchanged: the
product's recovery boundary remains a reboot.

## Remaining T2Touch limitation

- Suspend/resume stays unqualified for the product. The doctor's
  `suspend-mode` warning and the `s2idle` wake failure on MacBookPro16,1
  ([sleep policy](../SLEEP_POLICY.md#reference-machine-results)) are
  unaffected by this disposition; only the "deep leaves the T2 transport
  unusable" half now has a confirmed external cause and a pending fix.
- `t2-biometric-ready.service` still fails after resume on stock linux-t2
  kernels until the fix lands. No T2Touch change is planned for that: a
  transport that the driver cannot restore is not something the service
  should paper over.
- Release claims about suspend remain "not qualified" until a stock linux-t2
  kernel containing the fix has been tested; the operator workaround does not
  count as product qualification.
