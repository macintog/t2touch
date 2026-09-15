# MacBookPro16,2: bridgeOS 23P2048

MacBookPro16,2 / J214K with bridgeOS 23P2048 requires identity-create version 4.
Select it explicitly before installation. Other firmware builds remain
unvalidated; see the hardware coverage below.

## Select the creation version

For a machine confirmed to run this firmware, configure version 4 **before
loading the transport**:

```sh
printf '%s\n' 'options t2_sep_transport identity_create_version=4' |
  sudo tee /etc/modprobe.d/t2-sep-create-version.conf
```

Follow the [installation instructions](../README.md#try-it-on-omarchy), then
check that the loaded policy reports `4`:

```sh
cat /sys/module/t2_sep_transport/parameters/identity_create_version
```

If an older transport is already resident, use
`./install-omarchy.sh --prepare-transport-update`, restart when instructed, and
resume installation. Do not unload a SEP-pinned transport to switch versions.

The parameter is read-only after load. Kernel and userspace enforce the selected
request and response version for both identity creation and replacement.
Version 5 remains the default. Neither model detection nor a failed creation
triggers an automatic fallback.

Version 4 has a 76-byte minimal request instead of version 5's 88 bytes;
changing the version word alone is insufficient. The negotiated AKS envelope
version is separate from this operation-body version. The
[decoder and dispatcher reference](research/create-v4-j214k.md) documents the
wire format and firmware evidence.

## Recover an interrupted installation

`./install-omarchy.sh --prepare-native-recovery` installs the software and loads
the transport after network readiness while preserving journals and private
state. It holds automatic first-run, biometric readiness and reconciliation,
adaptive sync, and fprintd activation, including across reboot and D-Bus
activation requests. It does not start PAM or desktop UI setup.

After reconciling private state, rerun the normal installer without the recovery
flag to clear the hold and resume setup. Failed preparation leaves the hold in
place. Recovery enables the existing gated provisioning and replacement
capabilities, but does not itself dispatch an identity mutation.

An ambiguous creation outcome requires reconciliation. Mailbox status -13 alone
does not establish that creation was rejected before execution; preserve the
journal and state rather than deleting them or retrying the operation.

## Hardware coverage

The [contributor report](https://github.com/macintog/t2touch/pull/1) records a
Linux-only Omarchy run on 2026-09-15, using bridgeOS 23P2048 and kernel
`7.1.8-arch1-Watanare-T2-3-t2`. It tested the v4 changes on base revision
`24f450b`; these observations do not qualify every later source revision.
No macOS installation or firmware flash was required.

Reported results:

- Linux-native identity creation and activation completed.
- One fingerprint enrolled as `finger-1`; `t2touch verify` returned
  `verify-match (done)` with exit 0.
- Fresh `sudo -K` followed by `sudo -v` authenticated using the fingerprint
  without password entry.
- After restart, services started automatically and the same fingerprint
  remained enrolled and verified successfully, without identity recreation or
  pending mutation reconciliation.
- Password fallback was retained. Negative-finger controls, separate graphical
  lock/PolicyKit transactions, additional fingerprints, and deletion were not
  tested. Omarchy UI integration was installed.

This evidence covers one machine and firmware combination. It does not
establish support for all T2 Macs or replace mutation and recovery safeguards.
