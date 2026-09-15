# MacBookPro16,2: bridgeOS 23P2048

Linux-only Omarchy validation on 2026-09-15 used MacBookPro16,2 / J214K,
bridgeOS 23P2048 and kernel `7.1.8-arch1-Watanare-T2-3-t2`.
No macOS installation or firmware flash was needed.
The hardware run used these changes on source revision `24f450b`; the PR is
rebased onto `d79b4c1`, with software tests and builds repeated there. The
upstream changes between those revisions were not part of the hardware run.

## Firmware-specific creation version

This firmware's operation-1 decoder supports creation body versions 0–4.
The previous installer sent version 5 and received mailbox status -13 before
identity creation ran. Version 4 omits the final v5 scalar and optional blob;
the minimal body is 76 bytes instead of 88. Changing the version word alone
is insufficient. See the [recovered decoder and dispatcher evidence](research/create-v4-j214k.md).

For a machine independently confirmed to run this firmware, select version 4
**before loading the transport**:

```sh
printf '%s\n' 'options t2_sep_transport identity_create_version=4' |
  sudo tee /etc/modprobe.d/t2-sep-create-version.conf
```

Then follow the normal installer instructions. Check the loaded policy with:

```sh
cat /sys/module/t2_sep_transport/parameters/identity_create_version
```

The parameter is read-only after load. Kernel and userspace both enforce the
selected request/response version, including identity replacement. Version 5
remains the default; neither model detection nor a failed creation triggers
an automatic fallback. Negotiated AKS envelope version 2 does not determine
the identity-create body version. Other firmware builds remain unvalidated.

If an older transport is already resident, use the documented
`./install-omarchy.sh --prepare-transport-update` procedure, restart, and resume
installation. Do not unload a SEP-pinned transport to switch versions.

## Recovering an interrupted installation

`./install-omarchy.sh --prepare-native-recovery` installs the software and
loads the transport after network readiness without starting first-run,
fprintd, or PAM/UI setup. It preserves the existing journals and private state. A persistent recovery hold
blocks automatic first-run, biometric readiness/reconciliation, adaptive sync
and fprintd activation, including after reboot and D-Bus activation requests.
After reconciling private state, rerun the normal installer without the recovery
flag to clear the hold and resume setup. A failed preparation leaves the hold
in place; it does not authorize journal replay.
It enables the normal narrowly gated provisioning/replacement capabilities
so a recovery owner can inspect and reconcile state; it dispatches no identity
mutation itself. This mode does not clear an ambiguous outcome or authorize
replaying one.

The validated machine had an exact known version-5 rejection. Its original
journal was privately archived only after matching firmware, request/source
provenance, journal integrity, a new boot, the loaded module, absence of local
mapping/keybag, and two fresh kernel-attested absent-primary observations.
The decoder/dispatcher proof establishes non-creation for that specific case.
Status -13 alone is not enough. There is intentionally no generic journal
deletion or retry command.

## Enrollment recovery and installation permissions

This firmware reached the terminal fingerprint result through the existing
stable-readback recovery path. That path now publishes the committed rolling
BioLockout head before reporting success, just like normal enrollment. Without
it, the fingerprint was persisted but subsequent inventory/verification failed
because the rolling state was absent. Publication does not recapture or remove
the fingerprint.

The installer also makes its public Python runtime readable/executable by the
desktop user when invoked with a restrictive umask. Credentials, keybags,
Catacombs and journals remain outside that software directory and retain their
private permissions.

## Hardware evidence and limits

- Linux-native identity creation and activation completed.
- One fingerprint enrolled and was listed as `finger-1`.
- Desktop-user `t2touch verify` returned `verify-match (done)` and exit 0.
- Fresh `sudo -K` followed by `sudo -v` succeeded; the tester confirmed
  fingerprint-only authentication, without password entry.
- After restart, services started automatically, the same finger remained
  listed, and verification again returned `verify-match (done)`, exit 0.
- The startup reconciler reported no pending mutation and no fingerprint
  mutation; identity setup reported no state change.
- Password fallback was retained. Separate negative-finger controls, graphical
  lock/PolicyKit transactions, additional fingerprints and deletion were not
  validated in this run. Omarchy UI integration was installed.

This is one-machine hardware evidence, not qualification of all T2 firmware.
The kernel change affects creation/replacement validation, so it carries
authentication-state mutation risk despite keeping existing ownership and
one-shot gates. Preserve private state for recovery; do not infer hardware
safety from codec tests alone.
