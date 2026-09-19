# Touch ID transport unavailable after deep sleep

A reported driver failure can leave Touch ID unavailable after deep sleep on
MacBookPro16,2. The T2 network interface remains present, but stops transmitting;
BridgeXPC becomes unreachable and biometric readiness fails. Reboot is the known
recovery boundary. Suspend/resume remains unqualified for T2Touch.

Thanks to [@tonibergholm](https://github.com/tonibergholm) for raising and
investigating this issue in [PR #3](https://github.com/macintog/t2touch/pull/3).
This entry summarizes the contributor's report; T2Touch has not independently
reproduced those results.

## Reported configuration and diagnosis

The report concerns MacBookPro16,2 with Linux
`7.1.8-arch1-Watanare-T2-3-t2`, deep sleep selected, and no systemd sleep
override. The contributor identifies the in-tree driver source as
`linux-t2-patches@b71434b`, corresponding to `deqrocks/t2bce@967465d`.
The bridgeOS version was not recorded.

The contributor's instrumented traces indicate that, after a stateful resume,
the T2 stops supplying read credits for the network function's bulk-OUT
endpoint. Pending transmissions then stall and produce network watchdog
timeouts. Host-side endpoint resets did not restore traffic in those tests;
a diagnostic interface rebind did. The traces are held by the contributor,
not included in this repository. Whether the lost device state is a firmware
bug or expected host behavior remains unresolved.

This diagnosis is specific to the reported configuration. It does not explain
every suspend failure or establish the cause of the separate MacBookPro16,1
s2idle wake failure described in the [sleep policy](../SLEEP_POLICY.md).

## External repair and current limits

The proposed repair belongs to `t2bce_vhci`, outside T2Touch. It asks USB core
to reset-resume devices with non-control OUT endpoints so their configuration
and interfaces are restored. As checked on September 19, 2026, the proposals
remain open:

- [deqrocks/t2bce #8](https://github.com/deqrocks/t2bce/pull/8), reviewed at
  `21221926651b8c9238066b7bc163438d8b9364dc`.
- [AdityaGarg8/t2bce #1](https://github.com/AdityaGarg8/t2bce/pull/1), reviewed at
  `6c374bb240242ea06b43a9a656123fff601f4f39`.

The contributor reports successful post-resume BridgeXPC traffic and Touch ID
with both variants on their machine. Delivery through a stock linux-t2 kernel
still requires downstream patch regeneration and a kernel release. Neither an
open fix proposal nor a successful custom-module test qualifies stock-kernel
suspend support.

T2Touch does not distribute, install, verify, or remove these driver fixes.
The contributor's custom-module workaround remains their responsibility; its
files and rollback are recorded in the [original report](https://github.com/macintog/t2touch/blob/ad2e8aa141e80c3d62d0f745a07a1cdb40140f63/docs/dispositions/t2bce-stateful-resume-bulk-out.md).
It is not a T2Touch recovery procedure. Do not substitute USB or PCI rebinding
for reboot when the transport is unusable. See
[diagnosis and ownership](../SLEEP_POLICY.md#diagnosis-and-ownership).

This release documents the known issue without changing the installer, doctor,
sleep policy, or authentication behavior. Suspend/resume remains unqualified
until the relevant stock-kernel behavior is tested.
