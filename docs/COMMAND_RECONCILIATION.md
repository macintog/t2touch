# Command migration and enrollment

Version 0.1.0 uses `t2-touchid-*` for installed desktop commands. Existing
`t2touch COMMAND` invocations remain compatibility aliases to the same shared
implementation. The project name, PAM integration and DKMS names are unchanged.

## Everyday commands

Run these commands as the mapped account in an active local desktop session.
After first installation, log out and sign back in before enrolling.

| Command | Behavior |
| --- | --- |
| `t2-touchid-enroll [start]` | Open the desktop fprintd enrollment interface, without sudo. |
| `t2-touchid-status [--json]` | Show service availability and your redacted fingerprint inventory. |
| `t2-touchid-list [--json]` | List the same validated inventory. |
| `t2-touchid-count` | Print the number of enrolled fingerprints. |
| `t2-touchid-verify` | Test an enrolled fingerprint through fprintd. |
| `t2-touchid-delete N` | Obtain fresh PolicyKit authorization, then delete one fingerprint. |
| `t2-touchid-purge [--yes] [--resume]` | Confirm and authorize journaled deletion of the full inventory, or resume that operation. |

The canonical commands are installed in `/usr/local/sbin`; the compatibility
`t2touch` dispatcher remains in `/usr/local/bin`. Inventory JSON schema version
1 and operation exit statuses are unchanged. See the [README](../README.md#everyday-commands)
for neutral slot names, purge interruption, and password fallback.

## Enrollment behavior changes

Previously, `t2-touchid-enroll start` selected an administrative capture path.
It now opens the same desktop fprintd interface as `t2-touchid-enroll` and
`t2touch enroll`. Old direct-capture options, including `start --name ...` and
research acknowledgement flags, are rejected rather than silently ignored.

Do not use sudo for desktop enrollment. If fprintd is unavailable or not ready,
the command fails without falling back to direct native capture. Explicit
native research uses the maintained interfaces under `/opt/t2-touchid/bin`
and retains their original acknowledgement requirements.

Administrative enrollment subcommands `status`, `list`, `preflight`,
`verify-post-reboot`, `recover-outcome`, `recover-local`, and `recover-observed`
retain their meanings and limits. In particular, native `recover-local` still
fails closed where unsupported. Administrative status and inventory outputs
are not interchangeable with the desktop commands above. See
[administration](ADMINISTRATION.md) before using them.

## Enrollment safeguards

The desktop command uses the existing fprintd TUI and caller-bound worker.
Changing the entry point does not change the biometric protocol or recovery
algorithm:

- fprintd binds the claimant; the worker revalidates the caller and account
  authority after handoff.
- The worker chooses the lowest vacant neutral slot. A request token such as
  `finger-1` does not authorize replacing an existing fingerprint.
- First enrollment must establish verified runtime account authority before
  success. An additional enrollment must verify the newly added fingerprint.
- Reaching 100% capture progress is not completion. Persistence, inventory
  reconciliation and completion policy must also succeed.
- Cancellation, transport loss, or an uncertain result retains the original
  journals and recovery requirements. A failed command does not establish
  that retrying a biometric mutation is safe.

Delete and purge retain fresh PolicyKit authorization before acquiring the
reader. Their privileged helpers still require the mapped caller and native
account authority. Purge confirmation and interrupted-operation recovery are
unchanged.

## Upgrade and rollback

Use the complete product installer so the launchers and shared implementation
are staged together. Copying a launcher alone is unsupported. Upgrade also
[retires recognized obsolete PATH tools](TOOL_RETIREMENT.md), preserving
unknown edits and archival conflicts. Uninstall removes the desktop commands
while retaining configuration, biometric state and recovery evidence under
its existing preservation rules.

Roll back command software as a complete package. Software rollback cannot
undo enrollment or deletion; the original journal and recovery contract still
govern the result. Fingerprint-preserving recovery remains unresolved as
described in the [recovery findings](RECOVERY_RELEASE_GATE.md). This migration
does not establish a new hardware qualification or repair suspend/resume.
