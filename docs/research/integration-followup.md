# Lessons from the installed integration

The subsequent engineering work moved the native account and fingerprint
lifecycle into the installed fprintd service. It exposed integration assumptions
that the earlier protocol experiments did not exercise. The three mini modules
still implement the same creation/export bodies, replacement bodies, and
activation storage; no protocol or storage-code update was needed in mini.

This review covers the retained engineering checkpoint reviewed on 2026-09-14
UTC. The [evidence index](integration-evidence.json) identifies that exact
committed source revision and the file hashes reviewed; it is provenance, not
the identity of the later publication commit. Hardware statements below come
from retained engineering records; this review itself ran no hardware actions.

## What the later observations establish

| Boundary | Recorded result |
| --- | --- |
| Blank native bring-up | Installed first-run created a new Linux account identity and activation bundle without using imported macOS or archived research identities as runtime input. |
| First fingerprint | Standard enrollment completed, survived reboot, published the first enrollment's verified account authority, and appeared in stock inventory. |
| Verification | Positive and negative native matches were exercised through fprintd. |
| Additional fingerprints | Subsequent standard enrollments persisted and verified new identities. A post-deletion addition was ultimately assigned the durable handle `finger-4`. |
| Selected deletion | Stock fprintd deletion of Finger 3 reached SEP. Forward recovery completed persistence without repeating the delete; automatic reconciliation confirmed absence on a later boot. |
| Rename and slot history | The historical post-deletion addition was safely renamed to `finger-4` and survived reboot reconciliation; the product now uses five stable slots and fills the lowest vacancy. |
| Survivor use | Final inventory retained `finger-1`, `finger-2`, and `finger-4`. All-enrolled matching succeeded without treating a requested handle as anatomy or as a restriction on which enrolled fingerprint may authenticate. |
| Service startup | `t2-biometric-ready.service` and `fprintd.service` started unattended and reached the reconciled native authority. |
| PAM and fallback | A real `sudo -v` accepted an enrolled fingerprint. In a separate transaction with fprintd runtime-masked, biometric verification timed out and the known Linux password succeeded; fprintd was then restored active. |

The companion TUI changed during integration from a stock-command wrapper to
a direct D-Bus client. Standard fprintd commands separately established first
and additional enrollment, listing, verification, and named deletion. A direct
client result still proves only the service call it made, so retain which client
and source generation supplied each result. The PAM claims above come from the
separate recorded `sudo` controls, not from the TUI.

## Current product behavior

The installed t2touch lifecycle now completes first enrollment and fresh-owner
authority publication in the current session. Named deletion includes the final
fingerprint and reconciles an enrollable empty inventory. The next enrollment
uses Finger 1. Batch delete-all remains unexposed.

The Omarchy installer supplies a missing applesmc boot-state prerequisite and
then requires one restart; a capable running kernel supports same-session
installation. A different resident transport is rejected before installed-state
changes. These kernel boundaries are distinct from enrollment completion.

The current source comparison is pinned to t2touch
`01ef002bcae2aa257f968071e7bcde5b626d3858` and t2touch-mini
`f28146248e4e9c78b07e60e18302adc2aa3fce40`. All three mini modules match the
t2touch implementations after excluding license comments and module docstrings.
The [evidence index](integration-evidence.json) retains the original checkpoint
hashes and limitations; it is not a current capability checklist.

The checkpoint results below describe earlier experiments. Their boot counts,
slot history, and absent controls are not instructions for the current product.

## Account proof and the current identity set

The first enrollment's later-boot proof, called E4 in the engineering project,
establishes the native account's authority. It is not a permanent list of that
account's fingerprints. Two assumptions failed during integration: an addition
gate expected exactly one existing identity, and later-addition authorization
required the first fingerprint to remain present.

An adapter needs both the original account evidence and a reconciled current
catalog. Bind the current Catacomb components and completed mutation journals
to the same account UUID, keybag UUID, and mapping generation. Then require:

- An addition extends the complete baseline by exactly one new identity.
- Its verification matches that new identity, not merely any retained finger.
- A selected deletion removes only its target and preserves the exact survivors.
- Unfinished or inconsistent mutations block a new mutation.

The third-fingerprint correction and a later addition after deleting `finger-3`
were exercised live. The separate correction allowing additions after the
original first fingerprint is absent has offline regression coverage and a live
preflight with the retained survivor set, but the records do not include an
actual delete-`finger-1`-then-enroll sequence. Do not present that narrower case
as hardware-proven.

## Names survive deletion

Names such as `Finger 1` are neutral handles for enrollment records. The private
UUID identifies the enrolled template. Neither a list position nor an anatomical
label inferred by software identifies the person's physical finger reliably.

Expose five independent neutral slots, `Finger 1` through `Finger 5`. Deleting
Finger 1 never moves Finger 2 or any other retained identity. The next
successful enrollment takes the lowest vacant slot, so a fully empty inventory
always starts at Finger 1. Failed or cancelled captures do not occupy a slot.

An earlier reference run assigned `finger-4` after deleting `finger-3`; that is
retained as historical evidence for rename and persistence, not as the final
product's allocation policy. The corrected allocator chooses the lowest vacancy
inside the authorized, lock-held worker and never renumbers survivors.

## Completion and interrupted deletion

Capture reaching 100 percent precedes terminal identity validation and durable
persistence. A wrapper can report an error after the fingerprint already exists.
Reconcile that outcome from the operation journal, retained private events, and
fresh inventory before deciding whether another capture is appropriate.

Deletion has the same distinction. In the installed run, SEP removed the target,
but the persistence adapter omitted the committed master Catacomb needed by
the recovery path. The repair supplied the master component and resumed the
existing operation from observed absence. It did not repeat biometric command
`0x0d`. Recovery still had to persist the paired state, confirm the exact survivors,
and verify the deletion after reboot.

Keep first enrollment and additions distinct as well. The original research
established first-enrollment authority through later-boot proof; the installed product also completes it through a fresh owner in the
current session. An addition to an already verified account uses its own same-boot, identity-specific completion gate. Do not restart that
proof sequence merely because both operations are called enrollment.

## Service ownership and startup

A direct D-Bus client must handle loss of its service owner or bus connection,
accept only status for its own operation, and preserve a completed terminal
result against late signals. Cleanup calls need bounded waits. A timeout lets
the client stop waiting; it does not certify that hardware cleanup completed.
Do not let a replacement daemon inherit a previous client's cleanup authority.

The discovery path also stopped repeating a full endpoint scan on every pass.
A private cached endpoint is only a routing hint: every connection still needs
a fresh RemoteXPC handshake and a fresh advertised biometric service record.
It supplies neither account authority nor a previous authentication verdict.
This optimization has offline checks; no measured latency improvement is
claimed by this review.

The completed startup and PAM controls add a distinct product boundary: the
readiness and fprint services must converge unattended after reboot, while PAM
must retain an independently usable password path when the biometric service is
unavailable. Success of one transaction is not evidence that fallback works;
the recorded controls exercised those cases separately and retained rollback
copies of the managed PAM files.

## Scope retained by mini

These are integration requirements and original explanations of observed
failures. Mini does not add the full daemon, transport, journal framework,
installer, or PAM assets. Its existing MIT code and credits remain intact.
The [T1 reference already credited](artifacts-and-method.md#research-credits) informed lifecycle design;
T2 credential representations, request layouts, and hardware evidence remain
specific to this implementation.

The review did not originally establish multi-user operation, delete-all or
last-fingerprint deletion, deep-sleep recovery, persistence across a macOS boot,
a dedicated live adaptive-update control, or release-level support across
additional hardware. Subsequent full integration hardware-proved final-identity
forward recovery to a clean empty inventory; the other limits remain.
Those limits do not weaken the completed greenfield lifecycle on the reference
machine.
