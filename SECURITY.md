# Security model

This is experimental authentication software, validated on one MacBookPro16,1.
Keep password authentication and an authenticated recovery terminal available
while changing PAM or the desktop integration. See the
[tested scope](README.md#what-has-been-proven).

## Trust boundaries

The T2 SEP owns fingerprint templates and makes the biometric decision. The
root fprintd-compatible service trusts its installed code, Python environment,
kernel transport, bridgeOS, and protected Linux account mapping. It accepts a
match only after fresh private inventory reconciliation, an unambiguous SEP
match against that set, and post-match attestation. Missing, malformed, stale,
timed-out, rejected, or differently scoped results fail closed. Finger presence,
a UI prompt, or successful transport exchange is never authentication.

A successful list may supply single-use presentation metadata to the same
caller's next verification. Concurrent callers may share an inventory read
while it is running. Neither optimization caches an authentication verdict or
replaces the native verifier's live authority checks. Sound and UI notifications
are outside the decision path.

The installed service enables enrollment and named single-fingerprint deletion.
D-Bus claims bind the unique sender, pinned process identity, account generation,
and active local session. Mutation workers independently revalidate authorization,
protected mapping capabilities, current identity state, and the operation journal
before dispatch. A privileged PAM verification claim cannot become self-service
mutation authority. Bulk deletion remains disabled.

The product command `t2touch delete finger-N` obtains fresh PolicyKit
authorization before claiming the reader or taking its operation lock. Its root
helper validates the original caller and configured account, then uses the same
journaled deletion and reconciliation machinery. This ordering lets the reader
authenticate the deletion without contending with the deletion itself.

The protocol does not expose fingerprint templates to clients. Private identity
UUIDs, keybags, Catacomb data, and biometric payloads remain within protected
service state. Clients receive neutral slot names and bounded progress/results.

## Credentials and persistent state

The native installation creates a Linux-owned credential. Its activation bundle
also preserves the saved keybag and a 16-byte creation-time secret needed to
activate through a fresh owner. Bundle checksums detect mismatched generations;
they do not encrypt the files. Root-only ownership and modes protect this state
from ordinary users; filesystem encryption protects it at rest. Neither protects
it from a compromised root account while the system is running.

Compatibility code for retained macOS authority uses separate keybag and password
material. Password-dependent operations run in short-lived workers with systemd
credentials; the long-lived fprintd service does not retain that password.
Compatibility migration is not a supported end-user installation path. Linux and
macOS passwords are not assumed to match.

Private files must be root-owned and inaccessible to group/other. Never publish
credentials, keybags, Catacombs, captures, private device identifiers, identity
UUIDs, raw BridgeXPC replies, or biometric payloads. Uninstall preserves private
state for reinstall; it does not erase fingerprints from SEP.

## PAM and desktop recovery

The installer preserves password fallback and original managed PAM files in
`/var/lib/t2-touchid/pam-backups`. Sudo and PolicyKit can continue to password
authentication. Omarchy's lock screen has separate fingerprint and password PAM
paths; the fingerprint-only service is not a substitute for the password path.
Use `sudo tools/rollback-pam.sh` to restore managed PAM originals.

Validate successful and unsuccessful fingerprint attempts, password fallback,
and return to a usable desktop. A successful biometric result alone does not
prove the lock screen or compositor survived. Back up display configuration
before changes and retain a recovery access path. The optional Omarchy QML and
UWSM changes have separate [rollback instructions](docs/TROUBLESHOOTING.md#undo-the-omarchy-desktop-integration).

## Scope and reporting

This stack does not establish Apple's Secure Boot trust chain or provide
FileVault-equivalent guarantees. Multi-user operation and broad hardware support
remain unproven. Root is a trusted part of this implementation; security review
must still examine unprivileged D-Bus callers, privileged helpers, authorization
binding, mutation recovery, and secret handling.

Use a private security advisory on the project's hosting service for secrets,
authentication-bypass details, or raw protocol evidence. Public issues should
contain only reviewed, redacted diagnostics.
