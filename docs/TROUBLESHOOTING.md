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

## Two Linux installations or restored system snapshots

Touch ID state is shared hardware state; independent host archives are not
independent fingerprint stores. Cloning the account mapping and keybags can let
both installations authenticate to the same T2 while retaining different saved
generations. A warm boot can hide this until the next cold load.

If startup reports `installation-inventory-conflict`, preserve both stores and
journals and stop automatic Touch ID startup on the stale installation. Do not
reset enrollment or restore an older filesystem snapshot as a biometric repair.
Identify the latest completed, account-bound user/master save before attempting
a cold restore. Root access to a second installation does not by itself prove
its archives belong to the selected account. See the
[reference investigation](RECOVERY_RELEASE_GATE.md#firmware-log-follow-up).

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
[boot-policy reference](https://github.com/macintog/t2-platform-research/blob/423d2b056b69764876097818b3efc74319a7f944/docs/storage/sep-persistence-and-nvme.md#publishing-boot-state).

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

Recovery could not restore the reference machine's saved fingerprints after a
cold reset. Whether those fingerprints can be recovered remains unknown; see
the [recovery findings](RECOVERY_RELEASE_GATE.md). Keep the saved files and
journals intact before attempting further recovery. The commands below have
not been shown to restore those fingerprints.

If the post-reboot service reports `pending-biometric-mutation`, run
`sudo t2-touchid-manage status`. Its `native_state_recovery_pending_count`
and `native_state_recovery_pending_phases` fields identify an unfinished
native-state recovery even when enrollment, rename, and deletion counts are
zero. Older diagnostics reported this failure as `reason: null` and omitted
native recovery from status. Preserve that journal and resume the existing
recovery under the installer hold described below; rerunning normal setup
does not complete it. A `cold-restart-prepared` recovery requires a different
Linux boot and an independently verified cold T2 surface before it can proceed.
Do not remove the journal or accept fingerprint loss merely to clear the gate.
Normal setup now validates the native recovery journal before releasing the
service hold. An unfinished or invalid journal keeps automatic services paused
and reports the pending phase; reinstalling userspace cannot complete that
hardware transaction. Once explicit recovery reports `complete` or
`already-complete`, normal setup can release the hold.

If `t2-native-first-run.service` and `t2-biometric-ready.service` pass but
`t2-touchid-post-reboot.service` reports `external-deletion-reconciliation`,
inspect that service's journal. The automatic management child previously
mistook a cold unloaded Catacomb for an external fingerprint deletion and
stopped with “SEP Catacomb is not clean after the external deletion.”

The recognized restore candidate has an absent Catacomb, empty live inventories,
and only a clean master component. A cold T2 reports that master at state 1
(unloaded); after an abrupt host exit bridgeOS can retain it at state 3
(securely loaded) while the selected-user component is absent. State 1 remains
the ordinary guarded cold-load path. State 3 is different: a direct saved-user
load has failed on the reference machine. Recreating missing components at the
pre-client boundary has also failed to restore the enrollment; that is not a
qualified preservation procedure.

Normal startup therefore fails closed with
`retained-master-recovery-required`; it does not replay a rejected load or
mistake the empty inventory for an external deletion. Preserve private state
and journals under the installer's persistent service hold:

```bash
./install-omarchy.sh --prepare-native-recovery
sudo t2-touchid-manage status
```

The generic `--acknowledge-retained-master-recovery` acknowledgement no longer
permits component recreation/removal. Those steps can invalidate the T2
generation while leaving host archives intact, so the separate fingerprint-loss
acknowledgement is now required **before** them as well as before empty
reprovision. Cold readback and saved-generation load continuations retain their
existing checks. A normal install or upgrade never opts into fingerprint loss.

Only if the operator explicitly accepts possible loss and reenrollment may the
generation-changing path proceed with both acknowledgements. This is not a
remedy for the unresolved persistence defect:

```bash
sudo t2-touchid-manage recover-native-state \
  --acknowledge-retained-master-recovery \
  --acknowledge-fingerprint-loss-and-reenrollment
```

The historical `CANONICAL_USER_LOAD_REPLY_REJECTED` milestone does not by itself
prove a firmware rejection: older code used it for malformed replies and
unexpected callbacks too. Such status-less records remain readable but cannot
authorize empty reprovision, even with the loss flag. Current recovery records
the validated nonzero firmware status for explicit rejections and records an
unknown outcome for malformed replies. Neither outcome is replayed. Missing
historical evidence must not be fabricated by editing the journal.

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

On bridgeOS 23P6068 a rejected canonical-master `0x40` load can still expose
an empty master in state 3. Firmware logs recovered status `0x8002`, which
Apple's host implementation classifies as a corrupt Catacomb. The state-3
readback does not prove the saved master loaded. Recovery therefore stops after
a rejected master and refuses legacy `CANONICAL_MASTER_REPLY_RECONCILED`
continuations before another device command. Old journals remain readable;
no command is replayed and no history is rewritten to manufacture success.

If the canonical user is then explicitly rejected, the saved archive has not
been restored. A master/user generation mismatch is a hypothesis; the rejection
alone does not establish the cause or prove permanent loss. Recovery does not
repeat either rejected load, does not try an older backup blindly, and stops
with the enrolled archive preserved. Only the separate
`--acknowledge-fingerprint-loss-and-reenrollment` option permits the following
empty reprovision. From the exact clean master-only, zero-identity, zero-group
surface, that explicitly destructive path admits a fresh empty selected-user
component at the pre-client boundary, exports the resulting user/master pair,
normalizes the master enrollment count to zero, and atomically commits both
components while preserving the prior generation in the private backup store.
The Linux account/keybag authority is unchanged, but the old enrollment is
removed from the active Linux archive and `t2-touchid-enroll` is required after
installation finishes. This does not establish why the old load failed. Any
different live surface remains blocked.

Both the direct cold canonical-master path and the older derived-master
redirect path can reach that explicitly rejected user boundary. Recovery
recognizes their exact journal prefixes separately. Older code recognized
only the redirect path and incorrectly reported the direct path as an
ambiguous command outcome, even with the fingerprint-loss acknowledgement.
The repair does not replay either rejected load or relax the empty-surface
readback, account binding, or fingerprint-loss acknowledgement.

Each recovery invocation uses a separate root-private activation-journal file
while retaining the recovery operation ID inside that journal. A completed
ready activation from an earlier invocation is preserved as evidence and does
not prevent the recovery transaction from resuming. An unresolved or malformed
activation history still stops the command before biometric recovery dispatch.

## Another operating system changed the enrolled fingerprints

Startup validates the configured account's keybag and activation authority and
compares independently collected per-user/global T2 inventories with the saved
Linux inventory. A mismatching nonempty live inventory now stops startup with
`installation-inventory-conflict`. Preserve the saved generations and establish
which installation owns the current state before further recovery.

Earlier versions automatically saved newly observed identities. On the
reference machine a second cloned Linux installation had the same protected
account authority, so that save advanced shared hardware state while the first
installation retained an older archive. Separate host directories do not create
independent Touch ID stores. Automatic startup no longer chooses a persistence
owner this way. Explicit recovery persistence retains its account checks,
private backups, journaled save, and independent inventory readback.

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

## A working compatibility install lost fingerprint sign-in

A completed compatibility label rename changes the imported user Catacomb.
The original import archives and disabled mapping must remain intact. Runtime
authority accepts one completed rename only when its private journal anchors
the exact original backup, unchanged account and identity metadata, unchanged
unrelated components, and the committed user-file hash. The rename's authority
generation must match the completed compatibility proof chain. Incomplete,
torn, multiple, or unrelated mutation histories remain blocked; this is not
general support for further compatibility mutations. Do not reimport or delete
journals to work around this refusal. Validate checkout status before updating
the installed authority readers or restarting services. This continuation has
synthetic coverage. One MacBookPro15,2 completed the capacity-fix recovery,
label migration, automatic keybag unlock after Linux reboot, post-reboot
rename reconciliation, a fingerprint match, and fingerprint-on-sudo. macOS
worked after recovery; macOS behavior after the label rename and negative
authentication controls remain unverified. This observation does not qualify
other hardware or firmware.

An installation that predates the Linux-native lifecycle uses
`T2_TOUCHID_AUTHORITY_MODE=macos-control-oracle`. Current startup requires a
complete hardware proof chain for that mode: an imported keybag, a matched
keybag-UUID discriminator, either a clean first-attempt alias bind or an
ambiguous alias-bind retry with a reconciled state capture, and a completed
later-boot alias unlock. An installation created before
those proofs were recorded fails `t2-keybag-load.service` with
`compatibility authority is invalid`, and `fprintd.service` then fails with a
dependency error. `sudo t2-touchid-doctor` reports both failed units and the
`compatibility-transition` phase.

Inspect the missing step without touching the SEP:

```bash
sudo t2-touchid-migrate-compatibility status
```

The report names the current phase and the exact command to run next. Each
hardware stage must run on a later Linux boot than the one before it, so the
sequence is normally:

```bash
sudo t2-touchid-migrate-compatibility import \
  --linux-user <linux-user> --apple-uid <apple-uid> \
  --keybag-archive <keybags.tar.gz> \
  --catacomb-archive <catacomb.tar.gz> \
  --acknowledge-macos-control-oracle
# reboot
sudo t2-touchid-migrate-compatibility discriminate \
  --linux-user <linux-user> --acknowledge-one-shot-sep-discriminator
# reboot
sudo t2-touchid-migrate-compatibility bind \
  --linux-user <linux-user> --acknowledge-one-shot-sep-alias-binding
# For a clean bound-and-persisted result, skip reconcile.
# Run reconcile only when status requests needs-alias-reconciliation.
# reboot
sudo t2-touchid-migrate-compatibility reconcile \
  --linux-user <linux-user> --acknowledge-one-shot-read-only-alias-reconciliation
```

The archives are the private keybag and Catacomb captures exported from macOS;
the import stage does not run without its acknowledgement flag.

This helper is research-grade. Its stages are the same maintained one-shot
modules, but the end-to-end transition has not been verified on hardware.
The compatibility proof chain accepts a clean first-attempt `bound-and-persisted`
bind without reconciliation. The former standalone `unlock` stage is disabled:
kernel operation `0x04` requires the loaded keybag handle and alias binding to
remain active on the same transport owner, but the old staged workflow unloaded
the handle before opening a new unlock transport. Do not invoke that old command
or create an unlock journal manually. A normal atomic activation command remains
future work; `status` fails closed without suggesting the broken one-shot path.
The ambiguous-bind path continues to require read-only reconciliation.
If an unlock journal exists but does not prove success, status reports
`alias-unlock-recovery-required`. Preserve that journal: rebooting does not
reset the one-shot operation. A `bound-and-persisted` result proves persistence
after handle unload in that session, not across reboot. The normal keybag
loader requires completed authority and cannot bootstrap an incomplete chain.

For a validated clean first bind followed by exactly a pre-state-only failed
unlock (no password dispatch), status offers one explicit `recover` command.
On a later boot than that failure, it requires an absent alias, loads and checks
the imported keybag, binds and checks the alias, unlocks while the temporary
handle remains active, then unloads and checks persistence. Three new exclusive
recovery journals link the original history to the new observations; the
original journals are retained. No reboot is required between the recovery bind
and unlock.

```bash
sudo t2-touchid-migrate-compatibility recover \
  --linux-user <linux-user> --password-prompt \
  --acknowledge-one-shot-alias-recovery \
  --acknowledge-research-mac-and-macos-recovery
```

The hidden prompt requests the password for the imported macOS keybag. Recovery
is restricted to an explicitly designated research Mac with a working macOS
recovery path; the separate acknowledgement flag records this precondition.
Older checkout revisions requested a 4-byte response for raw AKS operation
`0x04`, while the kernel ABI requires the 16-byte lock-state response. The
kernel rejected that shape before password dispatch. Preserve journals from
such a failure; do not treat it as evidence of an incorrect password.
`--password-stdin` is also available. Except for the exact historical
response-capacity generation described below, any existing recovery artifact or
failure that crossed the unlock mutation boundary prevents another command. A
present alias (even a matching one), mismatched keybag, ambiguous handle release,
failed unlock, or incomplete journal stops recovery. Do not delete artifacts to
repeat it. Successful recovery must validate the entire linked proof chain
before status reports `complete`.

One historical candidate recovery could itself reach an exact terminal failure:
its parent stopped at `unlock`, its bind completed after unloading the keybag,
and its unlock command raised because operation `0x04` advertised only four
response bytes. Only that exact immutable chain is eligible for the distinct
capacity-fix continuation shown by `status`:

```bash
sudo t2-touchid-migrate-compatibility recover-capacity-fix \
  --linux-user <linux-user> --password-prompt \
  --acknowledge-one-shot-capacity-fix \
  --acknowledge-known-predispatch-capacity-defect \
  --acknowledge-research-mac-and-macos-recovery
```

This is not a generic retry. It requires a new boot and runtime, an absent alias,
and no capacity-fix artifacts. It binds the exact imported keybag, performs one
unlock dispatch while the handle remains active, then unloads and reads back.
The extra pre-dispatch acknowledgement records that the operator verified the
old installed client used the known four-byte response implementation; the
failure journal by itself cannot distinguish that local rejection from every
possible transport exception.
Any new artifact, including a dangling symlink or terminal failure journal,
permanently removes the command from `status`.

**macOS coexistence:** recovery uses the existing imported keybag and derived
alias. It does not reset or erase the SEP, provision a Linux-native user, change
the password, modify partitions, write Catacomb data, or enroll/delete
fingerprints. It is still a hardware-mutating research operation, tested with
fake transports only. macOS boot, login, and Touch ID must be verified on the
actual machine before claiming dual-boot compatibility; a successful Linux
unit test is not that verification. Keep password fallback and macOS recovery
available. On failure, preserve evidence and stop; there is no automatic
rollback or repeated recovery attempt.
Keep `/var/lib/t2-touchid` and the exported archives intact while diagnosing.
Do not edit or delete proof journals to force progress. Once `status` reports
`complete`, rerun `./install-omarchy.sh` so the stack installs PAM.

## Fingerprint inventory or enrollment is unavailable

An empty inventory is normal before first enrollment and after deleting the
final fingerprint. Use `t2-touchid-enroll` from the active local desktop session.

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
Use the product command `t2-touchid-delete finger-N`; it authorizes before taking
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
still appear active. `s2idle` has also failed to wake the MacBookPro16,1 host.
Neither mode is qualified here. T2Touch no longer selects a sleep mode and
retires its unchanged older override; review [the migration](SLEEP_POLICY.md)
before upgrading. A reboot is the known recovery boundary for an unusable
transport. Do not substitute USB or PCI rebinds.

A contributor traced a deep-sleep transport failure on MacBookPro16,2 to
`t2bce_vhci` and proposed upstream fixes. The
[disposition](dispositions/t2bce-stateful-resume-bulk-out.md) summarizes the
report, external fix proposals, and remaining qualification limits.

When reporting a suspend failure, include the selected sleep mode, kernel and
bridgeOS versions, whether ordinary startup works, and whether the failure
occurs with an operator or distribution sleep override. Review diagnostic output for private
identifiers before sharing it.

## Reporting a problem

Include the t2touch revision, Mac model, kernel and bridgeOS versions, the
command that failed, and the doctor's redacted result. State whether the
failure followed an install, upgrade, suspend, or macOS boot, and whether
password authentication still works. Never attach credentials, keybags,
Catacomb archives, or raw biometric captures.
