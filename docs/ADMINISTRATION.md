# Product administration decisions

macOS `/usr/bin/bioutil` is a useful interface reference because it separates
protected biometric settings from template inventory and deletion. Its runtime
model is not portable: it depends on MobileKeyBag, BiometricKit, Apple policy
preferences, and private entitlements. t2touch uses a Linux-owned keybag and
ACM authority, exposes a fprintd service, and integrates authentication through
PAM and PolicyKit.

## Adopted ideas

### Explicit list and count

`t2touch list` returns the complete neutral inventory for the current mapped
desktop user. `t2touch count` prints the size of that same inventory. Both use
`ListEnrolledFingers` on the project's fprintd-compatible D-Bus service, so the
existing sender, account, session, mapping, and live-reconciliation checks stay
authoritative.

The CLI invokes an unprivileged D-Bus client in the installed Python environment
and validates its complete JSON response shape. The client converts only the
typed fprintd `NoEnrolledPrints` error into an empty inventory; permission,
transport, and service errors remain failures. The CLI accepts at most five
unique canonical `finger-N` handles, sorts them by slot, and rejects malformed,
anatomical, duplicate, or oversized results.
Service errors and rejected response shapes do not leak their raw diagnostic
text to the terminal.
The daemon sends expected typed D-Bus errors without logging them as failed
asynchronous callbacks.

### Structured status

`t2touch status --json` reports service readiness and the validated redacted
inventory. When the service is unavailable, the fingerprint count and list are
`null`; the command does not turn an unavailable inventory into an empty one.
Human-readable status uses the same result rather than parsing or forwarding
localized `fprintd-list` output.

An empty inventory is a successful result: `count` prints `0`, `list` prints
`No fingerprints enrolled.`, and JSON output contains an empty fingerprint
list with count `0`. The native presentation cache checks protected Catacomb
and mutation-journal metadata on every access, so mutations through separate
administrative helpers refresh subsequent inventory queries. A journal append
or incomplete Catacomb transaction also prevents reuse of the older list.

### Fresh authorization for deletion

The existing `t2touch delete finger-N` behavior already applies the useful
part of `bioutil`'s protected mutation boundary. It obtains fresh PolicyKit
authorization before taking the reader or mutation lock, then performs one
journaled deletion with stable live readback and recovery handling.

### Delete-all with explicit partial-progress semantics

`t2touch purge` addresses account retirement, sensor reset, and replacement of
the complete enrolled set. It prompts before opening PolicyKit, uses a distinct
fresh-authorized helper, and records the complete initial neutral inventory in
the shared root-private mutation registry. Each item gets durable outer intent
before the normal single-delete transaction begins and durable completion only
after that transaction reconciles.

Deletion requires the mapped account's active local desktop session. SSH
attempts are rejected before confirmation or authorization with an explanation
of that requirement; `--yes` skips only confirmation, not authorization.
PolicyKit cancellation and denial report that deletion did not start. A helper
failure retains its partial-progress and recovery diagnostic. Successful purge
reports the deleted count and confirms that no fingerprints remain; purging an
already empty inventory reports that there is nothing to delete.

Delete-all is resumable rather than described as atomic. An interrupted batch
blocks unrelated biometric mutations. `t2touch purge --resume` obtains fresh
authorization, requires the live inventory to equal the recorded remainder,
and treats a pending item as complete only when that exact handle is the sole
observed delta. The terminal reports a redacted completed count when available.
Purge deletes fingerprint identities while preserving the mapped Linux account,
Linux-owned keybag, activation authority, journals, and recovery material.

## CLI JSON schemas

Both `t2touch status --json` and `t2touch list --json` use `schema_version: 1`.
`status` is the service-health view; `list` is inventory only. `service_ready`
appears on `status` only.

| Field | `status --json` | `list --json` |
| --- | --- | --- |
| `schema_version` | `1` | `1` |
| `service_ready` | boolean | omitted |
| `fingerprint_count` | integer, or `null` when the service is down | integer |
| `fingerprints` | `{handle, label}` list, or `null` when the service is down | `{handle, label}` list |
| `identifiers_redacted` | `true` | `true` |

Answering `n` to `t2touch purge` returns exit status `2` so scripts can
distinguish a declined confirmation from a helper failure.

## Deliberately excluded behavior

| macOS behavior | t2touch decision |
| --- | --- |
| Global biometric enable/disable | Do not equate service state, PAM installation, or protected mapping enablement. A future toggle needs one explicit Linux policy consumed by every authentication surface. |
| Unlock preference | PAM stacks are installed and backed up as a transaction; changing one stack would not represent a complete product preference. |
| Apple Pay preference | No corresponding Linux consumer exists in this project. |
| Biometric, match, and passcode-input timeouts | fprintd calls, PAM conversations, worker operations, and sensor protocols have separate bounded timeouts with different meanings. |
| All-user count or deletion | The product supports one mapped active desktop account and rejects cross-user delegation. |
| Private account/keybag purge | Fingerprint purge intentionally retains Linux-native account authority and recovery evidence. Removing that state needs a separate uninstall or account-retirement design. |
| Password-backed macOS credential sets | Linux-native activation uses its protected saved keybag and creation-time ACM material. It does not reuse or imitate a macOS password context. |

Enrollment and interactive verification remain first-class t2touch extensions
because they are useful Linux operations even though macOS `bioutil` does not
provide them.

## Installed commands

Product, admin, pkexec, PAM, and systemd helpers install on PATH under
`/usr/local/{bin,sbin}`. Research and test launchers install under
`/opt/t2-touchid/bin` and are not on PATH. Systemd unit `ExecStart` paths are
unchanged.

| Command | Location | Role |
| --- | --- | --- |
| `t2touch` | `/usr/local/bin` | Everyday enroll, list, verify, delete, and purge |
| `t2-touchid-doctor` | `/usr/local/sbin` | Privacy-safe stack report |
| `t2-touchid-user-map` | `/usr/local/sbin` | Redacted Linux-native account mapping |
| `t2-native-authority-rebind` | `/usr/local/sbin` | Explicit native authority rebind |
| `t2-touchid-delete` | `/usr/local/sbin` | pkexec helper for one-slot deletion |
| `t2-touchid-purge` | `/usr/local/sbin` | pkexec helper for batch deletion |
| `t2-fprintd-enroll-tui-launch` | `/usr/local/sbin` | Product enrollment TUI used by `t2touch enroll` |
| `t2-touchid-manage` | `/usr/local/sbin` | Admin mutations, adaptive sync, and explicit retained-master recovery |
| `t2-fprint-enrollment-worker`, `t2-fprint-delete-worker` | `/usr/local/sbin` | Root workers launched by the daemon |
| `t2-aks-tool` | `/usr/local/sbin` | AKS helper used by PAM and keybag units |
| `t2-pam-unlock`, `t2-pam-fingerprint-ready`, `t2-pam-fingerprint-prompt` | `/usr/local/sbin` | PAM stack helpers |
| `t2-sep-transport-load`, `t2-sep-transport-unload` | `/usr/local/sbin` | Transport unit `ExecStart`/`ExecStop` |
| `t2-bridge-network-prepare`, `t2-bridge-network-ready` | `/usr/local/sbin` | Bridge network units |
| `t2-biometric-ready`, `t2-biometric-port-refresh` | `/usr/local/sbin` | Readiness units |
| `t2-keybag-load`, `t2-keybag-unlock`, `t2-credential-unlock` | `/usr/local/sbin` | Compatibility-authority units |
| Research `*-test` helpers and negative/native TUI launchers | `/opt/t2-touchid/bin` | Contributor tools; invoke by absolute path |
