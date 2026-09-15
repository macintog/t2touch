# Troubleshooting

Start with the installed diagnostic:

```sh
sudo t2-touchid-doctor
```

Keep password authentication available while diagnosing Touch ID. The doctor
reports failed components without exposing keybag or biometric identifiers.

## Installation stops for the applesmc prerequisite

The running kernel must publish typed SEP boot state through applesmc. If that
publisher is absent, the installer stages the included DKMS prerequisite and
stops before changing biometric, PAM, or service state. Restart at a convenient
time, then rerun `./install-omarchy.sh` as your desktop account.

A module installed on disk does not establish that the currently running
kernel has the capability. The installer checks the live driver.

## Installation reports a different running transport

The installer compares the resident transport with the build before changing
installed state. A different or unidentified resident module stops installation.
A matching-transport userspace reinstall can complete in the current session;
a transport change requires a planned kernel restart.

Do not force-unload the module or unbind its PCI device. SEP retains registered
DMA addresses while the transport is resident. Keep the installed build and
running-driver details in a bug report if the mismatch is unexpected.

## Existing macOS Touch ID state blocks first run

The Linux-native installer creates authority only on blank state. It refuses
to overwrite an existing Apple authority. There is no supported end-user
migration command for a machine retaining macOS Touch ID state.

Booting macOS can reconcile fingerprints from its own database and remove
Linux-only additions. It is not a general recovery step for a Linux enrollment
failure. See [existing Apple state](../README.md#existing-apple-touch-id-state).

## Fingerprint inventory or enrollment is unavailable

An empty inventory is normal before first enrollment and after deleting the
final fingerprint. Use `t2touch enroll` from the active local desktop session.

If the doctor reports failed readiness or an unfinished operation, preserve
its diagnostic and report the failure. Do not delete private state or repeat
an ambiguous enrollment/deletion to clear it: the hardware operation may have
completed even when the client did not receive success. Recovery must reconcile
the existing operation with SEP and the saved Catacomb generation.

The installed services own Bridge network preparation, discovery, authority
activation, and reconciliation. Manual keybag-loading sequences from early
research are not installation prerequisites.

## Deletion failed and enrollment is now blocked

A deletion error can mean SEP removed the fingerprint but local persistence did
not finish. Install the corrected source before retrying enrollment. The startup
reconciler can finish the exact interrupted deletion forward from observed
absence without repeating the hardware command. Successful final-fingerprint
deletion leaves an empty inventory that can enroll Finger 1 again.

If recovery still fails, retain the journal and doctor's result. Do not erase
`/var/lib/t2-touchid`, replace account authority, or repeatedly issue delete.
Use the product command `t2touch delete finger-N`; it authorizes before taking
the reader. Lower-level fprintd deletion clients can hold the reader while
asking PolicyKit to authenticate, causing fingerprint authorization to fall
back to a password.

## A graphical dialog shows an icon, then asks for a password

First identify the action: a permission dialog and the lock screen use different
UI and PAM paths. Icon placement alone does not identify the failing component.
A working `sudo` fingerprint test does not prove either graphical path works.

With the compatible Omarchy integration installed and the shell restarted, the
lock and permission dialogs show preparation followed by the actual placement
message. Wait for that message, then briefly touch and lift. A touch during
preparation may be missed. The final lock test accepted the first ready touch;
the permission dialog still needed a couple of tries. Password fallback remains
available. See the [measured results](GRAPHICAL_AUTH_VALIDATION.md).

If no message appears, check the installer's UI integration notice: unfamiliar
QML versions are skipped without modifying them. Package upgrades can replace
those files. Rerun the installer to reapply a compatible patch, then log out and
back in when convenient. Do not restart the shell during an active authorization
or lock operation merely to test it.

## The display goes black or the compositor crashes on unlock

Recover a usable GUI before further fingerprint tests. Preserve an authenticated
terminal or SSH recovery connection before changing display configuration.
A match-success result does not establish that unlocking returned to the desktop.
Collect the compositor crash report and current display configuration before
adding another workaround; review them for private data before sharing.

The included UWSM snippet excludes a fallback framebuffer only when a native DRM
device has a connected display. It discovers devices at login and respects any
explicit `AQ_DRM_DEVICES`, including an empty setting. Check for an old manual
override before assuming the dynamic selector ran. Do not copy another machine's
card number, PCI address, Intel/AMD policy, or panel name. The
[compatibility contract](COMPATIBILITY.md#display-and-desktop-compatibility)
explains integrated, discrete, and single-GPU behavior.

## Undo the Omarchy desktop integration

The current `uninstall.sh` restores managed PAM state but leaves the optional
Omarchy QML changes and per-user UWSM snippet. To remove the latter, remove
`20-t2touch-drm-devices.sh` from `uwsm/env-hyprland.d` under your
`XDG_CONFIG_HOME` (normally `~/.config`). Its effect ends at the next graphical
login. Capture the effective display configuration first and keep recovery
access available; removing it also removes the fallback-framebuffer workaround.

For QML, the installer prints its backup directory under
`/var/lib/t2-touchid/omarchy-ui-backups/`. Each directory contains originals and
`receipt.json`, with destination paths and the hashes of the installed files.
Before restoring a file, verify that its current hash equals the corresponding
installed hash. If it differs, a package or another edit has changed it: do not
blindly overwrite it with an older backup. Review the current package version
and changes instead.

Restore only matched files to their recorded destinations, preserving each
file's current owner and mode. Backups themselves are private mode 0600, so do
not copy their permissions onto QML files. If several compatible patches were
applied in sequence, undo them in reverse order, checking the receipt at each
step; a later backup may already contain an earlier patch. Log out and back in
after restoration. Keep the backups until the desktop is verified usable.

## Touch ID stops working after suspend

Deep sleep can leave the T2 network transport unusable even when services
still appear active. The installer supplies a systemd sleep policy selecting
`s2idle`; deep-sleep recovery is not supported. A reboot is the known recovery
boundary for an unusable transport. Do not substitute USB or PCI rebinds.

When reporting a suspend failure, include the selected sleep mode, kernel and
bridgeOS versions, whether ordinary startup works, and whether the failure
occurs with the installed s2idle policy. Review diagnostic output for private
identifiers before sharing it.

## Reporting a problem

Include the t2touch revision, Mac model, kernel and bridgeOS versions, the
command that failed, and the doctor's redacted result. State whether the
failure followed an install, upgrade, suspend, or macOS boot, and whether
password authentication still works. Never attach credentials, keybags,
Catacomb archives, or raw biometric captures.
