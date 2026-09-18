# t2touch

Touch ID integration for Intel Macs with Apple’s T2 chip, using the standard
Linux `fprintd` interface.

This is an early proof of concept. Keep password authentication enabled and
available. Full end-to-end validation covers the `MacBookPro16,1` reference model;
other model and firmware combinations have narrower coverage.

**Recovery may require enrolling your fingerprints again.** On the reference
machine, recovery could not restore the existing fingerprints after a cold
reset, although their saved files remained intact. Whether those fingerprints
can be recovered is still unknown. A reset and fresh enrollment worked, and
the new enrollment survived a T2 and host reboot. The recovery code involved
is also present in `v0.0.8`. Read the [recovery findings](docs/RECOVERY_RELEASE_GATE.md)
before attempting recovery on an installation you rely on.

MacBookPro16,2 with bridgeOS 23P2048 additionally requires explicit creation
version 4 selection. See the [setup and hardware validation report](docs/MACBOOKPRO16_2.md)
before installing on that firmware.

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
t2touch list
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

Suspend/resume is unqualified on the MacBookPro16,1 reference machine.
T2Touch leaves sleep mode selection to system policy and retires its unchanged
legacy s2idle override on upgrade. Read [sleep policy and migration](docs/SLEEP_POLICY.md)
for the consequences, including the remaining risks of both s2idle and deep.

```bash
# Enroll another fingerprint
t2touch enroll

# Show the service and neutral fingerprint slots
t2touch status

# List only the enrolled neutral slots, or print their count
t2touch list
t2touch count

# Emit machine-readable, privacy-safe status
t2touch status --json

# Test any enrolled fingerprint
t2touch verify

# Delete one fingerprint
t2touch delete finger-2

# Delete every fingerprint (prompts before authorization)
t2touch purge
```

Deletion first opens the system authorization dialog. Authenticate with an
existing fingerprint or your password; only then does deletion take the reader.
Cancelling that dialog leaves the fingerprint unchanged.

`t2touch purge` confirms the full scope, obtains a separate fresh system
authorization, and deletes the inventory in its recorded slot order. The
operation is durable rather than atomic: if power, transport, or persistence
fails after some deletions, it reports incomplete progress and keeps all other
fingerprint mutations blocked. Run the doctor, then continue the exact recorded
operation with `t2touch purge --resume`. For noninteractive use, the initial
command requires `t2touch purge --yes`.

Run deletion commands as the mapped account in an active local desktop session,
outside SSH. `--yes` skips the confirmation, but still requires authorization.
Successful purge confirms that no fingerprints remain enrolled. Subsequent
`count` and `list` reflect the deletion immediately: an empty inventory prints
`0` or `No fingerprints enrolled.`, and JSON output contains count `0` and an
empty fingerprint list.

Fingerprint names are five neutral slots: `Finger 1` through `Finger 5`. They
do not claim which physical finger you used. Deleting one slot never renumbers
the others; the next successful enrollment takes the lowest vacant slot. An
empty inventory therefore starts at `Finger 1`. Failed or cancelled enrollment
does not create a slot.

All enrolled fingerprints are equivalent for authentication. Existing and new
entries use the same fprintd inventory and the same add, verify, and delete
operations; their origin is not an authentication distinction. Deleting the
final named fingerprint produces a clean, enrollable empty inventory; the next
successful enrollment is `Finger 1`. Purging fingerprints preserves the mapped
account, keybag, activation authority, recovery evidence, and installer state.
If another trusted owner, such as macOS, removes the final fingerprint,
the service detects the stable empty SEP inventory and reconciles Linux before
fprintd starts.

## Requirements

- An Intel Mac with an Apple T2 chip
- Linux 6.12 or newer headers for the DKMS transport (`<linux/hex.h>`, `<linux/unaligned.h>`, and `pcim_iomap_region()`)
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

The installer exits `3` when a reboot is required before it can continue
(staging the applesmc boot-state publisher, or `--prepare-transport-update`).
That is an expected stop, not a build failure: a labelled `NEXT STEP` block is
printed on stdout. Other non-zero exits are failures.

Run the installer as your desktop account, not as root. It invokes `sudo` only
for the system changes it owns.

## Existing Apple Touch ID state

The quick-start path creates a Linux-owned authority only when the T2 has no
existing fingerprint authority. It refuses to overwrite an existing one.

This also covers an identity retained after booting another Linux volume. The
fingerprint template on the T2 is cryptographically tied to that volume's
keybag, activation material, and Catacomb state, so a fresh installation cannot
adopt the template from sensor state alone. It reports a foreign live authority
and keeps both sides unchanged. Reuse requires an explicit migration of the
complete private authority followed by native account rebinding and live
validation.

For another t2touch Linux installation, copy its complete root-private
`/var/lib/t2-touchid` directory while both installations' fingerprint services
are stopped, retaining the destination directory as a backup. Then bind the
intact authority to the destination account without rewriting its protected
history:

```bash
sudo t2-native-authority-rebind --linux-uid 1000 \
  --acknowledge-complete-native-authority-migration
sudo systemctl start t2-native-first-run.service \
  t2-biometric-ready.service t2-touchid-post-reboot.service fprintd.service
sudo t2-touchid-doctor
```

The rebind command accepts no identity or digest from the command line. It
derives the current local account, validates the imported mapping and complete
post-reboot enrollment authority, and publishes one root-private binding. A
missing keybag, authority journal, or mapping lineage stops the rebind.

Compatibility code for machines retaining macOS Touch ID state is preserved,
but this release does not yet provide a supported end-user migration command.
It refuses the Linux-native first-run rather than overwrite that authority.
The architectural boundary and contributor work are described in
[`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md). Once connected, imported and
Linux-enrolled fingerprints are designed to share one neutral fprintd inventory
and the same verify/delete behavior without regard to origin; that migration is
not part of the supported administration surface.

Booting macOS may reconcile SEP from macOS’s own database. Linux-only additions
therefore are not currently guaranteed to survive a later macOS boot. When
macOS removes the sole remaining fingerprint, Linux automatically discards its
stale local inventory entry and permits a new `t2touch enroll`; it does not
restore or replace the fingerprint macOS removed. This does not affect
Linux-only systems.

The `status` and `list` commands obtain one caller-bound inventory through the
same fprintd D-Bus interface used by desktop clients. Their JSON output contains
only service readiness, neutral `finger-N` handles, display labels, and a count;
it never exposes SEP identity UUIDs or biometric data. `count` prints only the
decimal count for scripts.

macOS `bioutil` informed this small administration surface, but its system
preferences do not map directly onto Linux. t2touch does not expose Apple Pay,
timeout, global enable/disable, cross-user, or private-authority purge commands.
See the [administration decisions](docs/ADMINISTRATION.md).

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
mutation reconciliation, and fprintd as separate stages. A failed stage stops
installation and prints that unit's bounded status. Earlier stages may already
have completed; the installer does not roll them back. Account-generation
changes are never rebound automatically: use the redacted mapping status named by the installer, then
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

Full end-to-end coverage remains limited to the reference model. The
[MacBookPro16,2 report](docs/MACBOOKPRO16_2.md) records additional
firmware-specific results and their limits.
Graphical authentication may require another touch after the reader becomes
ready. Keep password fallback available; results on the reference laptop do
not establish the same behavior on every hardware or desktop combination.

Architecture, protocol provenance, and security boundaries are documented in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). The small reusable protocol
reference is published separately as
[`t2touch-mini`](https://github.com/macintog/t2touch-mini).

## License

The integration is licensed under GPL-2.0-only. The separately identified
research reference subset in `docs/research/` is MIT licensed.
