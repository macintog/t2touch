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
