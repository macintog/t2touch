# Product architecture

`t2touch` presents the T2 Touch ID sensor through the standard fprintd D-Bus
interface. Applications do not need a T2-specific authentication path: `sudo`,
PolicyKit, the Omarchy lock screen, and normal fprintd clients all consume the
same enrolled inventory.

The supported product sequence is deliberately small:

```text
install in the current session
  -> t2touch enroll
  -> fingerprint is durable and immediately usable
  -> verify or delete through ordinary fprintd semantics
```

No normal install, enrollment, deletion, upgrade, or uninstall operation
requires a reboot.

## Runtime layers

```text
sudo / PolicyKit / lock screen / fprintd clients
                         |
                         v
                fprintd-compatible service
                         |
            reconciled user authority + inventory
                         |
            BridgeXPC / BiometricKit      AKS / ACM
                         |                   |
                   CDC-NCM network      SEP transport
                          \                 /
                           bridgeOS + SEP
```

- The fprintd facade implements the standard user-facing enrollment,
  verification, listing, and deletion contracts.
- Lifecycle owners serialize mutation, keep credentials and biometric state
  private, and publish an identity only after persistence and fresh-owner
  verification succeed.
- BridgeXPC and BiometricKit carry sensor events and matching operations over
  the T2 CDC-NCM interface.
- The allowlisted kernel transport exposes only the AKS and ACM operations the
  lifecycle owners need. It does not expose a general raw SEP command channel.
- systemd orders network preparation, transport loading, first-run authority,
  biometric readiness, and fprintd. Starting fprintd pulls in the complete
  chain.

## Authority and first enrollment

On a blank T2 fingerprint authority, first run creates a Linux-owned SEP
identity, saves its encrypted keybag, and verifies it through a new transport
owner before enabling the Linux account mapping. The installer refuses to
replace an authority that already exists. Machines retaining macOS Touch ID
state use the separate [compatibility workflow](COMPATIBILITY.md).

The first successful enrollment persists the Catacomb and rolling BioLockout
state, reconciles host and SEP inventory through a fresh Bridge connection,
and publishes runtime authority before reporting success to the TUI. A failed
or cancelled enrollment publishes nothing and does not consume a numbered
slot.

Later enrollments use the same inventory. Entries are neutral `Finger N`
slots from 1 through 5; the system does not infer or require a physical finger
name. Retained slots never move after a deletion, and the lowest vacant slot is
used by the next successful enrollment. Any enrolled finger can satisfy
authentication, regardless of whether it was imported or enrolled on Linux.

## In-place lifecycle

The service loader owns transport configuration. During install or upgrade it
keeps a matching live transport bound, restarts this product's userspace
service chain, and starts fprintd again in the same running system. SEP retains
the transport's registered DMA addresses, so a changed kernel module is staged
for the next planned kernel restart rather than unsafely unbound. Uninstall
stops userspace while leaving a pinned live transport safely resident.

Ambiguous transport failures fail closed. They are reported by
`t2-touchid-doctor`; they are not converted into a successful authentication
or a blind mutation retry.

## Durable and volatile state

Durable private state lives under `/var/lib/t2-touchid` and binds one local
account generation to its SEP keybag, mapping, Catacomb generations, mutation
journals, and runtime authority. The encrypted first-run credential lives in
the systemd credential store. Volatile locks, sockets, and readiness state live
under `/run/t2-touchid` and are never treated as durable authority.

Uninstall preserves private state for reinstall. The proof of concept does not
expose Linux-initiated final-identity deletion or a private-state purge. A
stable external deletion of the sole identity is handled separately: the
startup reconciler commits an empty Linux projection before fprintd starts,
without issuing an SEP deletion or restoring the removed identity. The next
enrollment reuses that empty authority and persists a fresh one-identity
generation.

## Security boundary

Fingerprint matching is a local authentication convenience. Password
authentication remains enabled and independent. The service accepts a match
only when SEP returns a validated enrolled identity in the selected user's
reconciled inventory; sensor presence or transport success alone is not an
authentication result.

T2 Linux normally does not have Apple's Secure Boot trust chain for its Linux
kernel. This integration therefore is not equivalent to FileVault or a
hardware-attested Linux boot. Private templates, keybags, stable identifiers,
and credentials must never enter logs or the repository.

## Current support boundary

The complete product path has been validated on one `MacBookPro16,1`. The
architecture selects protocol capabilities rather than hard-coding finger or
user assumptions, but additional T2 models still need reproduction evidence.
Historical protocol recovery and hardware experiments are retained in
[`docs/research/`](research/); they are provenance, not product instructions.
