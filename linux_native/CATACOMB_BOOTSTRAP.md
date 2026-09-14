# First Linux-native Catacomb bootstrap

**Status:** completed. D197 persisted and reconciled the first native
user/master/BioLockout generation, D200 verified it across reboot at E4, and
D218 extended it to two identities — 2026-09-13

## Scope

This note records the host-persistence boundary used for the first built-in
fingerprint. It is a completed design record, not authorization for another
enrollment. Provisioned xART/gigalocker storage, a committed Linux-owned AKS
identity, a different-boot load/unlock/UUID check, the negative UID alias, an
explicitly empty biometric inventory, and ACM authorization were prerequisites.

The first user Catacomb is an enrollment result, not an enrollment
prerequisite. Linux must not invent an empty user component in advance.

## Exact first-identity inputs

The successful terminal enrollment result (`0xe3ff8003`) supplies the numeric
user ID, identity UUID, and accessory descriptor. Matching host behavior adds
an identity with type `1`, attribute `0`, entity `0`, the current creation
time, flags `0`, and zero match, continuous-match, and update counters.

The built-in accessory and group use zero UUIDs, the name `Builtin`, type `1`,
and accessory flags `6`.

| Archive field | Authority |
| --- | --- |
| Secure user `LTFC` | Exact command `0x3e` result for the selected user |
| Account UUID | Committed AKS creation intent reconciled with primary inventory |
| Keybag UUID | Operation-`0x02` saved object, verified again after load/operation `0x06` |
| Identity UUID and metadata | Terminal enrollment result plus stable post-enrollment inventory |

No UUID may be copied from stale cache state or generated to fill a missing
result.

## Transaction order

1. Double-read command `0x3c` and reject unstable or non-empty state.
2. Mark the selected user dirty; stage the master component last.
3. Run prepare `0x3d` and complete `0x3e`, validating their exact lengths.
4. Encode and stage the user and master components from those authoritative
   results.
5. Preserve the recovered confirm/host-commit ordering; an ambiguous outcome
   is not retried.
6. Obtain the secure bio-lockout `HRLB` with command `0x4a` and stage it in the
   final batch.
7. Read back and reconcile the live SEP identity set and all committed local
   components before declaring enrollment durable.

`src/t2_catacomb_codec.py` provides
`encode_initial_builtin_user_catacomb`, `encode_initial_master_catacomb`, and
`encode_initial_biolockout_catacomb`. They accept exact secure outputs and
binding identifiers; they do not perform transport or choose policy.

`build_linux_native_empty_baseline` records this state as journal baseline
version 2: no identities, no host components, no imported backup, and an
absent SEP Catacomb hash bound to the live nonzero namespace UUID. The existing
enrollment coordinator can select it only with an explicit account/bag binding
and rejects simultaneous host inventory or backup input. The finalizer then
creates all three components through the existing two-batch crash-safe store
and requires same-generation host/SEP reconciliation.

`CatacombEnrollmentCount` remains an explicit orchestrator input. Preserved
host evidence shows `1` for the first retained generation and `2` after the
next enrollment, but does not establish reset, restore, or wrap semantics.
The Linux journal must therefore own and reconcile this monotonic hint rather
than letting the codec guess it.

## Validation boundary

Before live validation, one synthetic three-component set passed strict codec
and independent-oracle round trips. D197 then proved empty-store creation
through E3 on hardware, D200 proved different-boot E4, and D218 proved the
existing-state extension path. No broad compatibility matrix is claimed.
Extraction
of the matching bridgeOS `BiometricSupport` image found only message-data
support exports, while `bkremoted` is the wire relay; neither is a hidden host
Catacomb constructor. Host archive construction consequently belongs in the
Linux userspace transaction owner.

The original design work made no live request; the later D197-D218 experiments
supersede that historical limitation. Production service and PAM integration
remain separate.
