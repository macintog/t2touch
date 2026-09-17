# Troubleshooting

Start with the installed diagnostic:

```sh
sudo t2-touchid-doctor
```

The doctor requests elevation through `sudo` so its report is complete. The
normal Touch ID prompt and password fallback remain available.

Keep password authentication available while diagnosing Touch ID. The doctor
reports failed components without exposing keybag or biometric identifiers.

## Installation stops for the applesmc prerequisite

The running kernel must publish typed SEP boot state through applesmc. If that
publisher is absent, the installer stages the included DKMS prerequisite and
stops before changing biometric, PAM, or service state. Restart at a convenient
time, then rerun `./install-omarchy.sh` as your desktop account.

A module installed on disk does not establish that the currently running
kernel has the capability. The installer checks the live driver.

## applesmc reports `response-received:3` after reboot

The publisher is loaded and has received a firmware response. EFMS result 3
means `BootPolicyReboot`; it is not a missing driver or the ready result 1.
Fresh product setup stops without replaying the transaction, rebuilding the
module, or starting SEP applications. Retain the boot ID, kernel applesmc
messages, and result for diagnosis if a normal reboot leaves it unchanged.

An already-running installation is different. When its resident transport
matches the requested build, its root-private configuration is intact, and the
complete prerequisite service chain is active, the installer permits an
in-place userspace upgrade and restarts only the upper service chain. If an
older userspace defect left that chain unhealthy, the installer also admits a
repair only after proving that the installed product is intact, the resident,
installed, and requested transports are identical, and the root-private
Linux-native provisioning authority represents a completed installation. For
an identified transport replacement, `--prepare-transport-update` records a
root-private proof bound to either a healthy installation or validated completed
native authority, matching resident/on-disk modules, both old/new module
identities, and the required intervening host boot. This also permits preparation
when the old userspace is broken; it never replaces the resident driver live.
The next installer run may use that proof; it is removed only after setup becomes
ready. This does not relax the result-1 requirement for fresh or partial setup or an unprepared replacement.

The earlier update workflow removed the units that served as its own upgrade
proof and could therefore strand a completed Linux-native installation at this
gate. Such a system is recovered only when the installed product and transport
are absent and the protected provisioning journal, enabled mapping, and their
recorded generations validate exactly. A partial fresh installation cannot
satisfy those checks.

Earlier installers either collapsed this reply into “missing, ambiguous,
failed, or unsupported” or blocked an otherwise healthy userspace upgrade.
Current diagnostics print the result and distinguish those two cases.
Other failed or unknown replies remain blocking, and result 1 still requires the
independent service readiness checks before PAM is installed. See the
[boot-policy reference](research/boot-and-storage.md#publishing-boot-state).

## fprintd dependency failure during native first run

Inspect `journalctl -b -u t2-native-first-run.service` and the kernel journal;
fprintd's dependency message alone does not identify the failed prerequisite.
A fixed driver bug counted initial provisioning as an already-attempted
replacement, blocking the later activation-bundle create during the same boot.
The fix counts only an armed replacement create and preserves its no-replay guard.

When updating an installation that has the old transport loaded, use:

```bash
git pull --ff-only
./install-omarchy.sh --prepare-transport-update
# Restart when the preparation command requests it.
./install-omarchy.sh
```

Keep `/var/lib/t2-touchid` and its journals intact. An interrupted
`absence-reconciled` operation is resumed from saved activation material with
fresh absence checks; deleting its journal would discard that recovery evidence.
The prepared-update proof is likewise stored below this root-private directory.
If preparation stops before requesting a reboot, resolve the reported failure
and rerun the same command. Its recovery hold and prepared-update proof remain
in place across a retry. Reboot only after preparation reports success.

## fprintd dependency failure after a cold bridgeOS boot

If `t2-native-first-run.service` and `t2-biometric-ready.service` pass but
`t2-touchid-post-reboot.service` reports `external-deletion-reconciliation`,
inspect that service's journal. The automatic management child previously
mistook a cold unloaded Catacomb for an external fingerprint deletion and
stopped with “SEP Catacomb is not clean after the external deletion.”

The exact recoverable generation has an absent Catacomb, empty live inventories,
and only a clean master component. A cold T2 reports that master at state 1
(unloaded); after an abrupt host exit bridgeOS can retain it at state 3
(securely loaded) while the selected-user component is absent. State 1 remains
the ordinary guarded cold-load path. State 3 is different: bridgeOS rejects a
direct saved-user load until the missing master/user components are admitted at
the pre-client protocol boundary.

Normal startup therefore fails closed with
`retained-master-recovery-required`; it does not replay a rejected load or
mistake the empty inventory for an external deletion. Preserve private state
and journals, then run the explicit recovery under the installer's persistent
service hold:

```bash
./install-omarchy.sh --prepare-native-recovery
sudo t2-touchid-manage recover-native-state \
  --acknowledge-retained-master-recovery
./install-omarchy.sh
```

This recovery fails closed if bridgeOS rejects the saved selected-user
Catacomb. It preserves the enrolled local archive and stops before creating or
persisting an empty generation. A normal install or upgrade never opts into
fingerprint loss. If preserving the existing enrollment has proven impossible
and the operator explicitly accepts deleting its local association and
reenrolling, resume with both acknowledgements:

```bash
sudo t2-touchid-manage recover-native-state \
  --acknowledge-retained-master-recovery \
  --acknowledge-fingerprint-loss-and-reenrollment
```

The recovery requires the exact stable state-3 master-only surface and unchanged
mapped Linux authority. It durably records intent before the pre-client
master-then-user `0x31` sequence, accepts only prepared state 1 or 5 for the
selected user, loads the saved user once, verifies the exact committed identity
set and group absence, persists any state-7 user/master Catacombs through the
existing typed save transaction, restores rolling BioLockout state, and finally
requires a clean stable readback. If accepted preparation instead exposes the
selected user as loaded and dirty with no identities, the same journal proves
that exact empty surface, removes only that user once, saves and confirms the
dirty master, and reruns component admission from the resulting master-only
surface. If this bridgeOS build again produces state 7 for the empty selected
user, the command preserves the exported intermediate master, derives the
recorded retained-master candidate without replacing canonical state, and
reports that a cold bridgeOS restart is required. After a different Linux boot,
rerun the same recovery command. It proceeds only from an exact state-1 cold
surface, loads the canonical enrolled master once, and then loads its matching
saved user once. Earlier recovery code instead loaded the exported empty-
generation master; bridgeOS accepted that master but rejected the enrolled user.
Such a journal is redirected through one more cold boundary and never replays
the rejected command. A Linux reboot that leaves bridgeOS warm does not satisfy
either gate.

On bridgeOS 23P6068 the canonical-master `0x40` load can return a nonzero reply
while independently moving the exact cold master from state 1 to state 3. The
journal treats the reply as terminal until a later stable read proves precisely
that master-only transition with zero identities and groups. It then records
that the load was not replayed and proceeds to the matching saved user once.
An unchanged state-1 master or any additional component remains blocked.
This is the narrow production form of the recorded compatibility repair; it
does not admit a loaded user containing an identity. A rejected or
transport-ambiguous command is never replayed. Foreign, grouped, changed,
nonempty, or otherwise ambiguous state remains blocked for evidence-based
recovery.

If the canonical user is then explicitly rejected, the enrolled archive does
not belong to the master generation retained by bridgeOS. Recovery does not
repeat either rejected load, does not try an older backup blindly, and stops
with the enrolled archive preserved. Only the separate
`--acknowledge-fingerprint-loss-and-reenrollment` option permits the following
empty reprovision. From the exact clean master-only, zero-identity, zero-group
surface, that explicitly destructive path admits a fresh empty selected-user
component at the pre-client boundary, exports the resulting user/master pair,
normalizes the master enrollment count to zero, and atomically commits both
components while preserving the prior generation in the private backup store.
The Linux account/keybag authority is unchanged, but the old fingerprint is
unrecoverable and `t2touch enroll` is required after installation finishes. Any
different live surface remains blocked.

Each recovery invocation uses a separate root-private activation-journal file
while retaining the recovery operation ID inside that journal. A completed
ready activation from an earlier invocation is preserved as evidence and does
not prevent the recovery transaction from resuming. An unresolved or malformed
activation history still stops the command before biometric recovery dispatch.

## Another operating system changed the enrolled fingerprints

Startup validates the configured account's keybag and activation authority. It
then compares independently collected per-user and global T2 inventories with
the saved Linux inventory. A new or replaced fingerprint within that authorized
account is reconciled regardless of which operating system enrolled it.

The reconciler preserves surviving neutral handles, assigns available handles
to newly observed identities, and saves the current opaque user/master Catacombs.
It does not enroll, delete, reload an old fingerprint, or change the account or
keybag. A private component backup and a durable journal precede the save.
Inventory changes during the save prevent success from being reported.

An interrupted save remains blocking with its recovery evidence intact. Only an
intent that demonstrably stopped before dispatch can close automatically: the
prepare/commit directories must be absent, the account mapping unchanged, and
the current components byte-identical to their validated backup. Do not erase a
pending journal to bypass this check.

Account authorization remains required. An unrelated account's keybag cannot
be adopted merely because its fingerprint is visible in a global inventory.

## Enrollment remains on “Preparing sensor” without a permission dialog

Preparation includes caller authorization before the reader is armed. Inspect
the enrollment worker and PolicyKit journals. A 120-second `PolkitGrantError` /
`TimeoutExpired` means authorization timed out; it is not evidence that the
sensor failed to initialize. The current TUI does not distinguish that wait
from sensor preparation.

After a first installation, log out and sign back in before enrollment. The
UWSM selector and QML integration take effect in the next desktop session.
On the reference installation, the old session still exposed a phantom
`Unknown-1` output and the operator saw no permission prompt. The prompt's
location was not captured, so invisible-output placement remains an inference.
A fresh session had one real display and actual fingerprint unlock succeeded.

The lock preview is a layout demonstration with input disabled. It neither
starts PAM nor proves fingerprint readiness. Use an actual authentication
request to test the preparation/placement messages and final unlock.

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

The same ownership rule applies when another Linux volume last activated its
own T2 identity. A new volume cannot adopt a retained fingerprint from the T2
alone: the template remains bound to that installation's protected keybag,
activation material, and Catacomb state. The post-reboot service reports
`foreign-live-authority` instead of treating this as an external deletion.
Boot the installation that owns the live identity, or migrate its complete
private state through an explicit native account rebind and live validation.
State imported from macOS additionally requires the matching
keybag and Catacomb control archives; a fingerprint template by itself is not
an authority credential.

For state copied from another t2touch Linux installation, preserve the former
`/var/lib/t2-touchid` as a rollback backup and run:

```bash
sudo t2-native-authority-rebind --linux-uid 1000 \
  --acknowledge-complete-native-authority-migration
```

This validates the complete imported Linux-native authority and binds its
unchanged history to the current local account. It does not apply to macOS
state, which still has no supported end-user migration command.

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
preparation may be missed. Another touch may be needed after readiness;
password fallback remains available.

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
