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

A clean first-attempt `bound-and-persisted` journal is also accepted as alias
authority. Its reader requires the exact ten milestones, one operation ID,
import and matched-keybag bindings, distinct boot/runtime generations, absent
pre-state, consistent handle, successful release, and persisted matching alias.
It skips reconciliation but still requires a later-boot unlock proof. Runtime
authority uses the bind operation ID directly; the historical unlock baseline
field `reconciliation_operation_id` carries that bind ID on this path. The
reconciled path retains its existing authority-generation inputs unchanged.
This reader and transition have hardware-free regression coverage; end-to-end
fingerprint authentication through the clean path is not yet hardware-verified.

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
unlock of that cleanly bound or already-reconciled alias. It validates the entire immutable
proof before accepting bounded wipeable password input, journals intent before
one unlock dispatch, and independently reads alias UUID/state afterward. It
does not load or bind a keybag, promote the mapping, start services, change
PAM, or request biometrics. The reference oracle credential is literally
`test`; the operator designates it non-secret test input, and it is never
written into the operation journal.

## Reference import result

### Pre-state-only unlock recovery

`t2_apple_control_alias_recovery.py` handles one narrowly defined bootstrap gap:
the clean first bind completed, but a later unlock stopped at pre-state without
password dispatch, and no recovery artifacts exist. On a still later boot and
fresh runtime, it reuses the imported keybag for an absent-alias bind and unlock
in the same session. This does not assume an alias persists across reboot.

The exclusive `apple-control-alias-recovery.jsonl` envelope binds the import,
matched-keybag, original bind, failed unlock, recovery bind and recovery unlock
operation IDs. The latter two retain the existing strict journal formats in
`apple-control-alias-recovery-bind.jsonl` and
`apple-control-alias-recovery-unlock.jsonl`. The original failed unlock remains
untouched. Recovery authority requires exact completion of all three new
journals, with matching boot/runtime for the new bind and unlock and distinct
boot/runtime from the failed attempt. The generation additionally incorporates
the recovery, failed-unlock and recovery-bind operation IDs. Existing direct
clean/reconciled authority generations do not change.

The new stage does not relax normal unlock reboot checks: the historical bind
remains its authority, while the envelope additionally proves a new binding in
the recovery session. A present alias prevents load/bind/unlock. Every operation
has durable intent in its child journal; any ambiguous result blocks reuse.
No reset, erase, native provisioning, Catacomb write, or biometric mutation is
part of this flow. It is restricted to an explicitly designated research Mac
with a working macOS recovery path. Hardware risk is limited in command scope, not eliminated:
tests use synthetic journals and fake transport, and live Linux authentication
and continued macOS boot/login/Touch ID are pending operator verification.

The one historical recovery generation affected by both the old four-byte
operation `0x04` response capacity and unload-before-unlock ordering has one
separate continuation. `apple-control-alias-capacity-fix.jsonl` and its distinct
bind/unlock children are accepted only after exact validation of the failed
recovery parent, completed bind child, and five-record rejected unlock child.
The continuation requires a later boot, a runtime distinct from every prior
relevant runtime, and an absent alias. Its corrected transaction unlocks while
the loaded handle is active, then unloads and verifies persistence. It permits
one bind, unlock, and unload dispatch and has no replay path.

### Original control capture

On the MacBookPro16,1 control generation, the transaction committed one unique
saved keybag represented by two identical capture views, three Catacomb
components containing one enrolled identity, one normalized backup, and a
disabled mapping. Independent read-back verified all private digests and the
Catacomb account/bag tuple. The provenance deliberately remains
`sep_keybag_uuid_verified=false`; no transport operation occurred during
import.
