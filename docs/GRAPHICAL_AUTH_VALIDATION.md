# Graphical authentication validation

## September 2026 correction

The initial graphical lock test authenticated, then crashed Hyprland while
unlocking. The crash report showed the fallback framebuffer's `Unknown-1`
connector being re-enabled, followed by EGL context and framebuffer allocation
errors. On the same machine, selecting native DRM devices removed that phantom
output and the subsequent actual fingerprint unlock returned to a stable desktop.

The installer now supplies a UWSM drop-in which discovers native DRM devices at
login. It does not embed GPU addresses, card numbers, a username, or a model
allowlist. Explicit selections and systems without both fallback and native DRM
devices retain their prior behavior. Multi-GPU fixtures retain other native GPUs
and put a connected internal panel first. Physical testing is on one
MacBookPro16,1; fixture coverage is not a claim of qualification on every T2 Mac.

## Authentication latency

On that laptop, a desktop-session D-Bus client measured the ordinary
ListEnrolledFingers → Claim → VerifyStart → finger-needed → VerifyStop → Release
sequence, without a touch. Times below are elapsed seconds from starting the list.

| Source | Listed | VerifyStart returned | Reader armed | Released |
| --- | ---: | ---: | ---: | ---: |
| Baseline run 1 | 1.750 | 3.518 | 7.322 | 8.027 |
| Baseline run 2 | 1.784 | 3.557 | 7.311 | 8.020 |
| Candidate run 1, before concurrent-read coalescing | 1.772 | 1.785 | 3.780 | 4.486 |
| Candidate run 2 | 1.765 | 1.778 | 3.778 | 4.450 |

The alternating baseline/candidate sequence used fresh client processes and the
same enrolled inventory. The measured startup improvement is approximately
3.54 seconds (48%). This is time to readiness, not a fabricated end-to-end login
benchmark: physical touch timing varies. The operator separately confirmed an
actual lock unlock on the first ready touch, with helpful GUI feedback and no
compositor crash.

A profile of one baseline inventory collection took 1.879 seconds, including
1.169 seconds in 23 AKS ioctl exchanges and 0.316 seconds in journal fsync calls.
The change removes redundant collections rather than bypassing those authority
and durability operations. There are no changes to kernel timeout constants,
calibration gates, identity reconciliation, credential retention or match verdicts.

- A caller's successful list supplies single-use presentation metadata to its
  next VerifyStart; another caller cannot reuse it. It is discarded on use,
  release, enrollment and deletion. Native matching still reconciles current
  private identity authority and attests the result.
- VerifyStart passes its validated presentation to the backend instead of
  collecting it again. Clients that start without a list still collect it.
- Concurrent inventory reads share only a running read; the next completed-read
  boundary triggers a fresh collection. Cancelling one waiter cannot cancel the
  other caller's inventory.
- The PAM placement signal and optional sound follow `match_armed`. Sound work
  runs independently of authentication; a slow sound service cannot hold up
  readiness or a terminal verdict.

## GUI integration

Compatible Omarchy QML receives a small, reversible integration: show the actual
PAM placement message, distinguish preparation, and wake the lock display once
for the first placement prompt. The permission dialog now displays its existing
Polkit supplementary message instead of discarding it. The enrollment detection
check recognizes numbered fingerprint entries rather than matching the word
“finger” in the no-enrollment error message.

All source anchors are checked before any file is changed. Unfamiliar UI versions
are left untouched with an installer notice. Originals and installed hashes are
retained in `/var/lib/t2-touchid/omarchy-ui-backups/`; permissions and ownership
are preserved. Package updates may require reapplying this integration. The
backend protocol and DRM selector do not depend on the QML patch being applicable.

The hardware-free validation covers facade lifecycle, fresh native authority,
match selection, claims, cancellation, concurrent reads, slow notifications,
DRM layouts, and UI patch compatibility/idempotence. Hands-on validation remains
necessary for additional hardware and future Omarchy/Hyprland versions.

After installation, a reboot on the tested MacBookPro16,1 returned to a normal
Hyprland session with the dynamically selected native DRM device, only the
internal panel active, and no safe-mode fallback. The fingerprint service was
healthy, the lock UI still detected fingerprint support, and fingerprint unlock
continued to work. The installed facade and DRM selector matched the validated
source. This verifies the tested laptop across reboot; it does not broaden the
hardware qualification claim above.
