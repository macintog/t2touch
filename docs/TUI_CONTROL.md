# Fast desktop terminal transport

New discovery processes reuse a revalidated per-boot endpoint hint and stop
fallback scans early. The cache is routing-only: each connection still performs
a fresh RemoteXPC handshake and service validation, as summarized in the
[integration follow-up](research/integration-followup.md#service-ownership-and-startup).

Run as the desktop user from the repository:

```sh
python3 tools/tui-control.py launch
```

For the installed upstream-interface proof, use the standard fprintd client
profile instead of the direct native research owner:

```sh
python3 tools/tui-control.py launch-fprintd-enroll
```

For an additional fingerprint, pass its neutral numbered handle:

```sh
python3 tools/tui-control.py launch-fprintd-enroll --finger finger-2
```

Its visible companion runs `/usr/bin/fprintd-enroll`. The wrapper subscribes
to the daemon's standard `finger-needed` and `finger-present` properties so it
does not display `TOUCH SENSOR BRIEFLY` until fprintd requests contact, changes
immediately to `LIFT FINGER NOW` on presence, and provides an audible cue on
each actionable transition. Launch it only after the operator explicitly
confirms immediate sensor readiness. `fprintd-enroll-status` is read-only and
is not part of the normal handoff.

For positive and negative match controls through the same standard fprintd
boundary, use the Apple-style companion profiles:

```sh
python3 tools/tui-control.py launch-fprintd-verify
python3 tools/tui-control.py launch-fprintd-negative
```

Both run `/usr/bin/fprintd-verify`; the second succeeds only when an unenrolled
finger produces `verify-no-match`. Their corresponding `*-status` actions are
read-only diagnostics, not normal post-handoff polling.

After the PAM templates are installed, prove the real sudo PAM path in the
same dedicated terminal style:

```sh
python3 tools/tui-control.py launch-sudo-pam
```

The launcher invalidates only sudo's cached authentication timestamp and runs
one `sudo -v` transaction. It never enrolls, deletes, or selects a fingerprint;
any enrolled identity may satisfy PAM.

Selected deletion must run inside the active local desktop session so the
daemon can pin the stock client's login-session authority. Launch the real
stock client in its dedicated retained terminal with an exact numbered handle:

```sh
python3 tools/tui-control.py launch-fprintd-delete --finger finger-3
```

The operation begins once, without an acknowledgement prompt, calls
`fprintd-delete "$USER" -f finger-3`, and retains either `FINGERPRINT DELETED`
or `DELETION STOPPED` for reconciliation. It does not weaken the daemon's
caller/session checks or provide bulk or final-fingerprint deletion.

For the saved-fingerprint match milestone, use the separate profile:

```sh
python3 tools/tui-control.py launch-match
```

For the controlled unenrolled-finger case, use its fail-closed profile:

```sh
python3 tools/tui-control.py launch-negative
```

To prove only one newly reconciled additional identity, use:

```sh
python3 tools/tui-control.py launch-new-finger
```

This root-selects exactly one reconciled baseline-v1 addition journal and
passes it to the native match owner. A match against another enrolled identity
fails the proof.

For the uninterrupted second-finger ceremony, use:

```sh
python3 tools/tui-control.py launch-second-finger
```

That one TUI verifies the existing finger, offers `A` to add a distinct
finger, performs a duplicate-finger negative check, enrolls it, and
immediately restricts the final match to the newly returned identity.  No
reboot, automation handback, or Enter acknowledgement occurs between phases.
D218 completed this exact flow in one process and retained the terminal result,
all child evidence, and the `addition-verified` journal. A future launch is a
new biometric mutation, not a UI demonstration; reconcile state and intend a
new enrollment before using it again.

This machine also has `~/.local/bin/tui-control` pointing to the helper.

The already-authorized application starts exactly one bounded operation itself
and never uses Enter during capture. Automation launches it exactly once after
the operator confirms immediate sensor readiness. The single `launch` call
waits locally until the TUI reaches `PLACE FINGER NOW` and fails if the
operation becomes terminal first. After that verified handoff, automation
performs no separate screen polling or input. The TUI owns every prompt and
capture cycle; the operator reports `done` after it reaches its terminal
screen. The helper exposes no keyboard-input action. Its read-only `status`
command exists for manual diagnostics but is not part of the automated
enrollment workflow.
It does not change TUI code, authorization, hardware behavior, or retry policy.

`launch-match` applies the same contract to the exact
`/usr/local/sbin/t2-native-match` backend and a separate private Kitty socket.
It waits locally for a stable `PLACE FINGER NOW`; then automation stops reading
the terminal until the operator reports `done`. `match-status` is diagnostic
only and is not part of the physical handoff.

`launch-negative` uses a third private terminal and waits for `PLACE
UNENROLLED FINGER NOW`. The backend retries image-quality-only failures and
exits successfully only for one exact matcher no-match; any positive result is
a hard failure. `negative-status` is diagnostic only.

One owner launches the bounded operation once. Keep existing authorization
with the task instead of asking again for routine UI plumbing.

The helper selects Hyprland instance 0 explicitly (`--instance` overrides it),
and opens a named held Kitty terminal with a private per-boot Unix socket.
Remote control is enabled only on this terminal's socket, not globally or over
its TTY. It resolves the single terminal's exact Kitty window ID for screen
readback. No focus switching, keyboard injection, screenshots, OCR, or
application-specific prompt guessing is used. A lock prevents concurrent
helper calls from interleaving. Multiple windows on the socket are rejected.
These commands require a terminal launched by the helper; an older terminal
has no such socket. Do not create a duplicate to work around that limitation.

Dwindle gets right preselection; scrolling uses normal adjacent-column
insertion without unsupported preselection commands. Existing named enrollment
windows, including held windows, prevent duplicate launch. Readiness polling
stays inside the helper at 100 ms intervals for up to 60 seconds, with a
three-second timeout per external command. Launch is never automatically
replayed. An error after dispatch means inspect the existing terminal, not
launch another one blindly.

Do not use text readback to monitor enrollment after the verified physical-
readiness handoff. The operator's `done` message is the handoff back to
automation.

For other system control, prefer direct CLI/API reads and targeted actions,
batch independent checks, and read back the relevant postcondition once.
Refresh observations when state changes or becomes uncertain. Use existing
sudo authority without redundant password validation. Codex relaunch, reboot,
checkpoint, and Gitea procedures are outside this change.
