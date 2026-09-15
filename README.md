# t2touch

Touch ID integration for Intel Macs with Apple’s T2 chip, using the standard
Linux `fprintd` interface.

This is an early proof of concept. Keep password authentication enabled and
available. Hardware validation currently covers one `MacBookPro16,1`; other T2
models need testing.

## Try it on Omarchy

Run as your normal Omarchy desktop user:

```bash
git clone https://github.com/macintog/t2touch.git
cd t2touch
./install-omarchy.sh
```

Follow the installer’s instructions, including any restart or recovery steps.
Rerun the installer when instructed:

```bash
./install-omarchy.sh
```

After installation completes, **log out and sign back in**.

Enroll a fingerprint, then check and test it:

```bash
t2touch enroll
t2touch status
t2touch verify
```

Follow the prompts and wait for the reader-ready message before touching the sensor.

The enrollment command opens the Touch ID terminal interface. Briefly touch and
lift the same finger as prompted. SEP reports real, non-linear progress; the
fingerprint graphic fills to match that percentage. Enrollment returns success
only after the new fingerprint is durable and ready for immediate use.

Afterward, any enrolled finger can authenticate through:

- `sudo`
- graphical PolicyKit prompts
- the Omarchy lock screen
- applications using the standard fprintd D-Bus API

Your normal Linux password remains available as fallback. Sensor setup is not
instant: wait for the placement prompt before touching. The service emits that
prompt and the optional sound only once the reader is armed. On compatible
Omarchy lock UI versions, the installer adds a preparation/placement message
below the password field and wakes the panel once when the first prompt arrives.
The graphical permission dialog also shows the preparation/placement message
instead of hiding it behind a fingerprint icon.
The password field remains available throughout. It also corrects the upstream
check that mistakes “no fingers enrolled” for an enrolled fingerprint.

This small QML integration preserves originals under
`/var/lib/t2-touchid/omarchy-ui-backups/`. It checks all integration points before
writing any of the three files and skips unfamiliar UI versions without changing them.
Omarchy package updates may replace it; rerunning the installer reapplies it
when compatible. The UI change takes effect at the next shell start/login.

The Omarchy installer also installs a small UWSM environment drop-in for the
next graphical login. When boot-framebuffer devices and a connected native DRM display exist,
it excludes the boot framebuffer from Hyprland, preventing the observed crash
when unlocking re-enabled a phantom display. It discovers device paths at each
login, prefers a connected internal panel regardless of GPU vendor, then other
connected displays, retains the remaining native GPUs, and
preserves an explicit `AQ_DRM_DEVICES` selection. Native-only and
framebuffer-only systems, and native GPUs without connected displays keep
Hyprland's default selection. Remove
`~/.config/uwsm/env-hyprland.d/20-t2touch-drm-devices.sh` to undo this part
(or the corresponding path under `XDG_CONFIG_HOME`).

## Everyday commands

```bash
# Enroll another fingerprint
t2touch enroll

# Show the service and neutral fingerprint slots
t2touch status

# Test any enrolled fingerprint
t2touch verify

# Delete one fingerprint
t2touch delete finger-2
```

Deletion first opens the system authorization dialog. Authenticate with an
existing fingerprint or your password; only then does deletion take the reader.
Cancelling that dialog leaves the fingerprint unchanged.

Fingerprint names are five neutral slots: `Finger 1` through `Finger 5`. They
do not claim which physical finger you used. Deleting one slot never renumbers
the others; the next successful enrollment takes the lowest vacant slot. An
empty inventory therefore starts at `Finger 1`. Failed or cancelled enrollment
does not create a slot.

All enrolled fingerprints are equivalent for authentication. Existing and new
entries use the same fprintd inventory and the same add, verify, and delete
operations; their origin is not an authentication distinction. Deleting the
final named fingerprint produces a clean, enrollable empty inventory; the next
successful enrollment is `Finger 1`. A batch delete-all operation is not
exposed. If another trusted owner, such as macOS, removes the final fingerprint,
the service detects the stable empty SEP inventory and reconciles Linux before
fprintd starts.

## Requirements

- An Intel Mac with an Apple T2 chip
- Omarchy with the T2 Linux kernel and matching headers. The installer supplies a DKMS build of the
  typed `applesmc` SEP boot-state publisher from
  [`linux_native/patches/applesmc-t2-sep-boot-state.patch`](linux_native/patches/applesmc-t2-sep-boot-state.patch).
  It is used only when the running kernel does not already provide that
  capability.
- An active local desktop session for the account that will use Touch ID
- Secure Boot configuration that permits the locally built DKMS module

The Omarchy installer installs `base-devel`, `dkms`, `fprintd`, Python, and
the headers matching the running kernel through `omarchy pkg add`. It detects
the Apple T2 network interface, creates an encrypted Linux-owned identity
credential, builds the transport with DKMS, starts the complete service chain,
and installs reversible PAM integration.

If the running `applesmc` driver lacks the boot-state publisher, the first
installer run stages the included `applesmc-t2touch` DKMS prerequisite and
stops before changing biometric, PAM, or service state. Follow the installer’s
restart or recovery instructions, then rerun `./install-omarchy.sh`. The installer never reboots the machine itself.

Run the installer as your desktop account, not as root. It invokes `sudo` only
for the system changes it owns.

## Existing Apple Touch ID state

The quick-start path creates a Linux-owned authority only when the T2 has no
existing fingerprint authority. It refuses to overwrite an existing one.

Compatibility code for machines retaining macOS Touch ID state is preserved,
but this release does not yet provide a supported end-user migration command.
It refuses the Linux-native first-run rather than overwrite that authority.
The architectural boundary and contributor work are described in
[`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md). Once connected, imported and
Linux-enrolled fingerprints are designed to share one neutral fprintd inventory
and the same verify/delete behavior without regard to origin; that migration is
not part of the four-command proof of concept.

Booting macOS may reconcile SEP from macOS’s own database. Linux-only additions
therefore are not currently guaranteed to survive a later macOS boot. When
macOS removes the sole remaining fingerprint, Linux automatically discards its
stale local inventory entry and permits a new `t2touch enroll`; it does not
restore or replace the fingerprint macOS removed. This does not affect
Linux-only systems.

See the [changelog](CHANGELOG.md) for release notes and the
[documentation index](docs/README.md) for service contracts, research, and
recorded validation.

## Troubleshooting

```bash
sudo t2-touchid-doctor
```

The doctor reports the failed component without exposing private biometric
identifiers or keybag material. Normal installation should not require manual
service sequencing or research acknowledgement flags.

Upgrades validate Linux account authority, biometric readiness, pending
mutation reconciliation, and fprintd as separate stages. A stopped stage leaves
fingerprints, keybags, mappings, and mutation journals intact and prints that
unit's bounded status. Account-generation changes are never rebound
automatically: use the redacted mapping status named by the installer, then
perform the explicit disabled-rebind and live-reconciliation procedure only
after confirming that the mapped Linux account is still the intended account.

## Uninstall

Restore the original PAM configuration and remove the software while preserving
the encrypted configuration and biometric state for a later reinstall:

```bash
sudo ./uninstall.sh
```

The uninstaller stops the userspace integration in the current session and
does not require a reboot. A transport already pinned by SEP remains safely
resident but is disabled for future kernel starts. The uninstaller
intentionally preserves the private authority and fingerprint state so
reinstall remains possible. The current uninstaller leaves the Omarchy QML
changes and user UWSM snippet in place; follow the
[desktop rollback steps](docs/TROUBLESHOOTING.md#undo-the-omarchy-desktop-integration)
to remove those as well.

## What has been proven

On the `MacBookPro16,1` reference system, Linux created its own T2 fingerprint
authority from blank state, enrolled multiple fingerprints, authenticated with
any enrolled fingerprint, deleted individual fingerprints without affecting
survivors, deleted the final named fingerprint back to a clean empty inventory,
and retained populated inventories across service and machine restarts.
Standard fprintd clients, `sudo`, graphical PolicyKit, the Omarchy lock path,
and password fallback all completed successfully. A matching-transport
userspace reinstall also completed without a reboot or hardware unbind.

The public claim is intentionally narrower than broad hardware support: this
remains a single-model proof of concept until other T2 Macs reproduce it.
[Graphical validation](docs/GRAPHICAL_AUTH_VALIDATION.md) records the actual
lock and permission-dialog results, the approximately 48% reduction in measured
reader preparation time, and the remaining retry and hardware limits.

Architecture, protocol provenance, and security boundaries are documented in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). The small reusable protocol
reference is published separately as
[`t2touch-mini`](https://github.com/macintog/t2touch-mini).

## License

The integration is licensed under GPL-2.0-only. The separately identified
research reference subset in `docs/research/` is MIT licensed.
