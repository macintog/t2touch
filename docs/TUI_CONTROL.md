# Terminal clients

For normal use, run `t2touch enroll`, `t2touch verify`, `t2touch status`,
`t2touch list`, `t2touch count`, `t2touch delete finger-N`, or `t2touch purge`
from the active local desktop account. Enrollment
uses a direct D-Bus client, takes touch and lift cues from fprintd, and returns
success only after durable persistence and fresh-owner verification.

The contributor helper `tools/tui-control.py` opens bounded controls in a
separate Kitty terminal on Hyprland. It is not an extra installation step.

## Standard service controls

Run these from the repository as the desktop user:

```sh
python3 tools/tui-control.py launch-fprintd-enroll
python3 tools/tui-control.py launch-fprintd-verify
python3 tools/tui-control.py launch-fprintd-negative
python3 tools/tui-control.py launch-fprintd-delete --finger finger-3
python3 tools/tui-control.py launch-sudo-pam
```

Enrollment invokes the fprintd enrollment TUI. Verify and negative controls use
the same direct D-Bus TUI; the negative control succeeds only for an unenrolled finger's
`verify-no-match`. Named deletion uses `fprintd-delete` and preserves the
caller's active-session authorization. Deleting the final named fingerprint is
supported. Product batch deletion is available through `t2touch purge`; this
contributor control exercises only the standard named-delete client path.

The sudo control invalidates sudo's cached timestamp and runs one `sudo -v`
transaction. Any enrolled fingerprint may satisfy it. A successful biometric
transaction does not independently prove password fallback.

## Research controls

The helper also retains direct native-backend profiles:

| Action | Purpose |
| --- | --- |
| `launch` | Direct native enrollment. |
| `launch-match` | Match the saved native inventory. |
| `launch-negative` | Require an unenrolled-finger no-match. |
| `launch-new-finger` | Verify the specific addition selected by its reconciled journal. |
| `launch-second-finger` | Verify an existing fingerprint, check for a duplicate, enroll, and verify the addition. |

These profiles exercise real hardware operations. They are contributor tools,
not a continuation queue or substitutes for the installed product interface.
A direct backend result establishes only that backend's behavior; use the
standard service controls to test fprintd or PAM.

## Terminal ownership and diagnostics

The helper selects a Hyprland instance and creates one held Kitty terminal
with a private per-boot Unix socket. A lock serializes helper calls, and an
existing named terminal prevents a duplicate launch. Remote control is scoped
to that terminal rather than enabled globally. The helper has no keyboard-input
action.

Launch waits for the profile's sensor-ready cue or an earlier terminal result.
Its read-only status actions inspect the existing terminal. An error after
dispatch does not prove that enrollment or deletion failed: reconcile the
existing operation and its journal before starting another one.

Discovery caches only a per-boot endpoint hint. Every new connection still
performs a fresh RemoteXPC handshake and validates the advertised biometric
service; the cache carries no authentication authority.

## Enrollment artwork sizing

The enrollment and verification view keeps the same compact fingerprint artwork
at every terminal height. Enlarging the window adds surrounding space instead of
switching to a taller, differently proportioned mask. Progress still colors the
art from the live reported percentage. Layout regression checks include the old
40-row transition and tall windows; the normal 76×28 view remains unchanged.
