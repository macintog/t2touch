# Fingerprint recovery findings

Recovery could not restore the existing fingerprints on the MacBookPro16,1
reference machine after a cold reset. Their saved files remained intact, but
we do not yet know whether those fingerprints can be recovered.

A reset and fresh enrollment succeeded. After a normal T2 reboot followed by
a host reboot, the newly enrolled finger matched and an unenrolled finger was
rejected. The old fingerprints have not been restored. These observations
cover bridgeOS 23P6068, protocol 2, and Linux
`7.2.6-arch2-Watanare-T2-2-t2` on one machine.

## What to preserve

Keep the saved fingerprint archives, account configuration, and recovery
journals intact. Do not delete a journal to bypass an incomplete operation or
replay an archive load that firmware has rejected. Keep password access and a
recovery terminal available.

The recovery implementation involved is also present in `v0.0.8`. Normal
startup stops before invoking explicit retained-master recovery, but startup
can still fail when the saved and hardware state disagree. Installation and
upgrade do not automatically consent to fingerprint loss.

Explicit retained-master recovery can recreate or remove T2 components.
Those operations now require separate acknowledgement of fingerprint loss,
including when resuming an interrupted operation. Retaining archive files
does not guarantee that the hardware will accept them afterward. See
[Troubleshooting](TROUBLESHOOTING.md) for command-specific guidance.

## Firmware-log follow-up

Firmware rejected the saved master archive with status `0x8002`, which the
examined Apple implementation identifies as a corrupt-Catacomb error. It then
rejected the user archive with `0x101`. An empty master reported in state 3
was previously mistaken for a successful master load. Recovery now stops at
the rejection, including when reading an older journal that recorded that
continuation.

Malformed replies are recorded as unknown outcomes separately from explicit
firmware rejections. An old user-load failure without a recorded firmware
status cannot authorize resetting the fingerprint inventory to empty.

Two cloned installations held the same account credentials and different
saved archives. Normal startup now refuses to save hardware state when the
live fingerprint list differs from the installation's saved list. This
prevents that automatic save from silently advancing shared hardware state.
The exact transition that made the old archives unusable remains unknown.

## What the reboot result establishes

The new enrollment loaded successfully after one T2 and host reboot. The
saved archive files remained unchanged, and enrolled- and unenrolled-finger
checks both passed. Repeated physical power cycles, interrupted writes, and
use across cloned installations have not been established by that result.

One startup reconciliation attempt failed transiently before later attempts
succeeded. No persistent failed service remained, and verification worked
without manual service repair. The cause of that transient failure is unknown.

To establish recovery of existing fingerprints, a test must restore the same
enrollment and verify both a matching finger and an unenrolled finger after
the relevant failure and reboot. A successful reset and new enrollment cannot
answer whether the old fingerprints are recoverable.

Sleep and graphics problems are documented separately in
[Sleep policy](SLEEP_POLICY.md). Those settings were unchanged during these
recovery checks.
