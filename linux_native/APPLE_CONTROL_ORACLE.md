# Apple-control interoperability oracle

This path validates the existing-state compatibility machinery without making
macOS a Linux-native prerequisite. State captured from the temporary macOS
control installation is evidence about AppleKeyStore and Catacomb bindings;
it is not evidence that Linux created either object.

## Import boundary

`t2_apple_control_import.py` accepts exactly two root-private archives and an
administrator-selected local Linux account plus numeric Apple UID. It:

1. validates every keybag tar member and the complete candidate map;
2. permits file or directory candidates but selects only direct `user.kb`
   files and requires all selected views to be byte-identical;
3. validates the direct system-Catacomb tar as exactly master, user, and
   bio-lockout records with safe captured ownership and modes;
4. decodes those records through both the strict codec and its independent
   semantic oracle;
5. creates a deterministic metadata-bearing Catacomb backup for the existing
   local-store pipeline;
6. writes an immutable private intent before converging archive backups,
   canonical `user.kb`, the local Catacomb, and one disabled user mapping; and
7. commits a root-only provenance record with origin
   `macos-control-oracle-v1` and `sep_keybag_uuid_verified=false`.

Existing files are accepted only when byte-identical. A conflict is never
overwritten. The public result contains counts and booleans only. Identifiers,
paths from the capture, archive digests, keybag bytes, and Catacomb bytes stay
private.

## Activation boundary

Import does not authorize authentication. The mapping remains disabled until a
different, activation-ready transport generation loads the saved keybag on one
exclusive descriptor and operation `0x06` returns the exact Catacomb-bound bag
UUID. The live handle must be unloaded on that same descriptor. A timeout or
lost handle is outcome-unknown and is not retried before reboot.

Only after that read-back may compatibility activation bind the derived
negative Apple UID alias and test password unlock. fprintd, PAM, enrollment,
and biometric mutation stay disabled throughout this oracle experiment.

The implementation is `t2_apple_control_discriminator.py`, invoked only by
the acknowledgement-gated `t2-discriminate-apple-control.py` in a separately
prepared activation-ready boot. It first rehashes every protected imported
artifact without opening the device. Its fixed root-private journal is created
exclusively, so an interrupted or completed generation cannot be replayed.
Public output is limited to match/release/outcome booleans and contains no UUID
or digest.

The Linux-native completion gate remains separate: it must create and export a
new Linux-owned keybag and construct its first Catacomb without importing any
artifact described here.

The subsequent compatibility-only alias discriminator is implemented by
`t2_apple_control_alias_discriminator.py`. It requires the exact completed
matched-keybag journal and a different boot/runtime generation. It first proves
the derived alias absent, then performs one load, stable UUID verification, one
alias bind, typed alias UUID/state read-back, one positive-handle unload, and a
second alias read-back. Its independent fixed journal prevents replay. It does
not unlock the alias, enable the mapping, start authentication services, change
PAM, or request a biometric operation.

If bind read-back is ambiguous after the positive handle is proven released,
`t2_apple_control_alias_reconciliation.py` validates both immutable attempt
journals and permits only a later-boot read-only closure. It double-reads the
derived alias UUID, privately captures and decodes the bounded version-1 state
blob when the UUID matches, then double-reads UUID again. Raw state remains a
root-only local diagnostic and is wiped from process storage. The kernel may
log only redacted envelope metadata on structural rejection. This path cannot
repeat bind or perform any other mutation.

On the reference control, that closure proved a stable matching alias and
captured an exact ten-field state dictionary. Apple encoded the SET members in
schema order rather than DER lexicographic order. Removing only the decoder's
member-order requirement made the immutable capture decode with its queried
alias handle intact; exact membership, duplicate, encoding, bounds, UUID, and
handle checks remain fail-closed. No hardware retry was needed.

The next compatibility-only discriminator is a separate later-boot password
unlock of that already-reconciled alias. It validates the entire immutable
proof before accepting bounded wipeable password input, journals intent before
one unlock dispatch, and independently reads alias UUID/state afterward. It
does not load or bind a keybag, promote the mapping, start services, change
PAM, or request biometrics. The reference oracle credential is literally
`test`; the operator designates it non-secret test input, and it is never
written into the operation journal.

## Reference import result

On the MacBookPro16,1 control generation, the transaction committed one unique
saved keybag represented by two identical capture views, three Catacomb
components containing one enrolled identity, one normalized backup, and a
disabled mapping. Independent read-back verified all private digests and the
Catacomb account/bag tuple. The provenance deliberately remains
`sep_keybag_uuid_verified=false`; no transport operation occurred during
import.
