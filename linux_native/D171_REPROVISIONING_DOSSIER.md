# D171 reconciled identity-replacement dossier

**Status:** completed and historical. D172/D173 completed reprovisioning;
D178/D179 completed activation; D196-D218 subsequently proved enrollment and
the native biometric lifecycle — 2026-09-13

This dossier preserves the executable safety contract used to replace D137 with the
first T2 identity whose creation-time activation secret survives reboot. It is
subordinate to [`ACTIVATION_PLAN_OF_RECORD.md`](ACTIVATION_PLAN_OF_RECORD.md)
and makes that document's selected lifecycle concrete. The transaction is
closed; this is not an active hardware instruction or permission to retry it.

## Superseding D172 live-state addendum

The one D171 start proved the current primary absent with two stable signed
operation-`0x51` status-`-3` observations. It stopped before journal creation,
ACM acquisition, delete/create intent, or SEP mutation. Therefore every later
section that assumes a present D137 primary or requires operation `0x49`
documents the retained `replace-present` branch only; it is not the next
hardware instruction.

The current `reprovision-absent` contract is:

1. validate immutable D137/D138/D170 evidence and the exact stale host mapping;
2. on one descriptor, obtain two stable absent-primary reads and write
   `ABSENT_REPROVISION_PREPARED` with `delete_required=false`;
3. acquire the mapped-user creation ACM context, durably stage its exact
   16-byte external form, and obtain two more stable absent-primary reads;
4. write `ABSENCE_RECONCILED`, arm direct CREATE, write CREATE intent, and
   dispatch operation `0x01` exactly once—never send operation `0x49`;
5. export, UUID-verify, publish the complete activation bundle, archive the
   exact stale mapping, atomically install the new mapping disabled, and
   release the handle; and
6. reboot before running the distinct activation broker described below.

If the process dies before activation material is staged, a different boot
may archive the operation only after fresh stable absence. If it dies after
staging, a different boot may write `ABSENCE_RECONCILED`; if it dies after that
record, another fresh owner must write `ABSENCE_RECONFIRMED`. Once CREATE
intent exists, only the existing exact-UUID ambiguous-create recovery applies;
CREATE is never redispatched. No absence record may be rewritten as a deletion
record.

D172 has now executed this contract once. CREATE returned success directly;
the complete bundle, disabled schema-2 mapping, and stale-mapping archive all
verify against the ten-record `mapping-committed` journal. Only created-handle
unload was ambiguous (host errno `-13`, SEP status zero). No descriptor holder
remains, but completion requires a fresh boot to prove the exact intended
primary and absence of live handles. The activation broker remains gated until
that record is appended and another boot is crossed.

D173 supplied that fresh boot and found two stable absent-primary results with
no live handles. Because the saved keybag had not been loaded, primary absence
is the expected live state, not a failed CREATE. The corrected completion
record is `HANDLE_RECONCILED_PRIMARY_ABSENT`; it is admitted only after the
final bundle, disabled mapping, and stale-mapping archive all re-verify. It
never claims primary persistence and does not load or mutate the identity.

## Fixed conclusion and predicted result

D137 cannot be activated. Its flags-`6` creation derived the persisted
verifier from the raw 16-byte ACM external form, and Linux destroyed that
form. The replacement keeps the same flags and wire contract but durably
retains its creation-time external form before identity creation can commit.

After a different boot, Linux will install those retained 16 bytes as type-5
data in a fresh mapped-user ACM input context and send the fresh context's
external form through identity operation `0x21`, option `0x100`. Matching SEP
will extract the saved 16 bytes and derive the same candidate it stored at
creation. The predicted result is raw SEP status zero, followed by successful
authorization of a distinct policy-1007 target, successful operation `0x18`,
and an independent unlocked-alias read-back. A final comparison mismatch
(`-5`) falsifies the selected reconstruction. A missing or stale context
(`-1`) is an implementation/lifetime failure, not a credential verdict.

## Evidence that must remain immutable

Before any replacement mutation, verify all of the following without copying
secret values into logs:

- the D137 post-create and D138 different-boot evidence snapshots and their
  manifests;
- the D170 final-comparison snapshot and its manifest;
- the current D137 account UUID, bag UUID, saved-keybag digest, journal head,
  and mapping generation against the protected records;
- one stable primary-inventory result whose returned `uuid` equals D137's
  account UUID; and
- no live AKS handle, ACM context, T2 device holder, enrollment transaction,
  downstream service, fprintd consumer, or PAM hook.

D137's saved keybag, mapping, journals, and snapshots are archived as evidence
before canonical paths are prepared. They are never presented as rollback
authority: the missing D137 activation input makes restoration unable to
recover the goal.

## Exact supported removal operation

Matching 24G830 AppleKeyStore exports `AKSIdentityDelete`. Its kext method
`AppleKeyStore::identity_delete` at `0xffffff8001acd786` accepts one 16-byte
identity object and sends endpoint-7 operation `0x49` through
`__ipc_invalidate_keybag` at `0xffffff8001a8d72f`. For D137 the object is the
account/user UUID already proved to flow from create input to primary
inventory key `uuid`.

The exact unversioned request body is 36 bytes:

```text
u32 result_placeholder = 0
u64 fresh_nonzero_session
blob compatibility_input = empty
blob account_uuid = exactly 16 bytes
```

The expected success body is one zero `u32`; a nonzero SEP status is failure.
Matching J152f descriptor `0x1146f8` routes operation `0x49` through decoder
`0x0cc6ec`, wrapper `0x0cc89c`, and handler `0x0edbdc`. The handler resolves
the supplied object, compares its UUID against every live bag, and refuses a
matching live instance before reaching durable invalidation at `0x0e11e4`.
It does not accept or validate D137's missing credential.

Deletion is reconciled through the already recovered, read-only operation
`0x51` suboperation 0. The only accepted successful transition is:

```text
before: one stable primary whose uuid == D137 account UUID
0x49:   exact D137 account UUID, one dispatch
after:  two stable primary-inventory reads report absent
```

If the direct reply is lost, close the descriptor and classify only a later
stable primary read. Old UUID present means not deleted. Absent means deleted.
Any other UUID, malformed record, unavailable inventory, or disagreement
between reads is quarantined. Never resend `0x49` to resolve uncertainty.

## Durable activation bundle

The keybag and activation secret form one generation even though the secret
must reach durable storage before operation `0x01` can commit. Implement this
with a root-owned mode-`0700` pending generation directory on the same
filesystem as its final location:

```text
pending generation/
    activation.secret   # exactly 16 bytes, root-owned mode 0600
    user.kb              # exported saved keybag, root-owned mode 0600
    manifest.json        # IDs, lengths, digests, phase; never secret bytes
```

The transaction writes `activation.secret` with `O_EXCL|O_NOFOLLOW`, syncs the
file and directory, and verifies its length, ownership, link count, mode, and
digest before deletion or creation. It must not log, encode in the journal,
pass on a command line, or expose the value through JSON. The manifest and
journal contain only its SHA-256 digest and fixed length.

After export, write and sync `user.kb` and the complete manifest in the same
pending directory, re-open and verify both files, sync the directory, then
atomically rename that directory to its final generation name and sync the
parent. The disabled mapping points directly at that generation's `user.kb`
and binds both artifact digests. No mapping or consumer may use a pending or
partially populated directory.

At this research stage, root ownership and exact `0700`/`0600` modes are the
at-rest boundary. Any backup is valid only as a private, access-equivalent copy
of the complete generation; neither artifact may be backed up alone. Loss or
suspected disclosure of `activation.secret` requires identity replacement.
Hardware-bound sealing is required before downstream PAM enablement if the
final product threat model includes offline root-filesystem disclosure.

Every userspace copy is a bounded mutable buffer and is wiped on every exit.
The ACM context is destroyed after the AKS transaction, and target then input
contexts are destroyed in reverse order during activation. A digest is an
integrity locator, never a replacement secret.

## D171 transaction order

One exclusive owner and one write-ahead journal perform this order:

1. Verify the immutable D137 evidence and stable present-primary precondition.
2. Allocate a fresh operation ID, account UUID, and nonzero session. Record
   only their permitted metadata and digests.
3. Create the mapped-user type-5 ACM context from the ordinary creation
   credential and externalize it.
4. Durably stage and verify that exact 16-byte external form as
   `activation.secret` while the context remains live.
5. Journal delete intent, send operation `0x49` exactly once for D137's account
   UUID, and obtain two stable absent-primary operation-`0x51` reads. A lost
   reply stops this boot and enters reconciliation; it never falls through to
   creation.
6. Journal create intent and send exactly one operation-`0x01` v5 request with
   internal flags `0x4100`, original flags `6`, effective handle `-1`, the
   staged external form as raw item 1, the fresh account UUID, and empty
   optional items.
7. From the returned positive handle, export once with operation `0x02`, copy
   the live bag UUID with operation `0x06`, and require the UUID to be nonzero.
8. Complete and atomically publish the activation bundle. Commit a disabled
   mapping bound to the new account UUID, bag UUID, keybag digest, activation-
   secret digest, Linux account generation, and exact generation paths.
9. Unload the owned live handle, destroy the creation ACM context, prove no
   holders remain, and retain a privacy-safe terminal record.

No enrollment, Catacomb mutation, fprintd action, PAM change, or physical
finger interaction belongs to D171.

## Crash and ambiguous-outcome matrix

| Last durable fact | Reconciliation | Only permitted continuation |
| --- | --- | --- |
| Secret staging incomplete; no delete intent | Verify old primary present | Remove the incomplete pending directory and start a new operation |
| Delete intent/dispatch; reply lost | Stable operation-`0x51` primary read | Old UUID present: close not-deleted. Absent: continue only on a fresh connection/boot. Anything else: quarantine |
| Delete proven; no create intent | Stable absent primary plus intact pending secret | Resume the same operation on a fresh boot; do not delete again |
| Create intent; reply lost | Stable primary inventory against the journaled new account UUID | Absent: close not-created. Exact new UUID: recover that identity. Any other result: quarantine |
| New identity exists; handle/export unavailable | Open the durable identity by its exact 16-byte account UUID through the matching `identity_open` operation-`0x03` form | Prove live UUID, export operation `0x02`, unload, and finish the same pending bundle; never create again |
| Export reply lost or local keybag commit failed | Re-open only the exact new account UUID and verify its UUID | Repeat the read-only export, then finish the same bundle |
| Bundle published; mapping absent | Re-open and verify both bundle digests plus stable new-primary inventory | Reconstruct only the disabled mapping |
| Disabled mapping committed; handle release incomplete | Different boot, stable exact new primary, and no kernel-owned handle | Close the replacement journal without recreating or deleting |
| Disabled mapping committed; activation proof incomplete | Different boot, exact bundle and mapping | Run activation proof; never recreate or delete |

The UUID-based recovery form is supported by matching
`AppleKeyStore::identity_open` at `0xffffff8001acd168`, which sends a fixed
16-byte identity object through operation `0x03` and returns a positive live
handle. Its Linux exposure must be narrower than the general saved-keybag load:
only the journaled new account UUID, only in an outcome-unknown replacement
phase, and followed immediately by UUID read-back, export or cleanup, and
owned-handle unload.

## Different-boot activation gate

On the next reconciled boot, verify the final bundle, disabled mapping, source
version, and new primary inventory before opening either device. Then:

1. Load the exact saved keybag and prove its operation-`0x06` UUID equals the
   bundle and mapping.
2. Bind only the derived negative alias and prove the positive handle retains
   the same UUID.
3. Read `activation.secret` into one bounded mutable buffer; create a fresh
   mapped-user ACM input context with those bytes as type-5 data; wipe the file
   buffer after the context is established.
4. Create a distinct same-user policy-1007 target while the input remains
   live. Send operation `0x21` option `0x100` with input then target.
5. Require raw status zero and satisfied target policy, then send fixed
   operation `0x18` using only the target.
6. Destroy target then input, unload the positive handle, and independently
   read the alias as unlocked on a fresh owner.

D170's exact final-comparison `-5` is the negative control for the same normal
option-`0x100` verifier path. The new positive result must differ for the one
predicted reason: its type-5 data equals the replacement's retained creation
input. Only after that contrast is immutably reconciled may the existing empty-
Catacomb enrollment path ask for the operator's physical finger.

## Implementation and opening gates

Before D171 hardware execution:

- [x] Add exact operation-`0x49` and UUID-open codecs, userspace adapter, and
  kernel validators, each reachable only in an explicitly armed replacement
  phase. The extra kernel admission parameter defaults off.
- [x] Strictly decode present-primary inventory, retain only its caller-owned
  account UUID plus an evidence digest, and admit terminal unload only for the
  exact created or recovered handle owned by the current arm.
- [x] Bind the initial delete arm to the live externalized ACM material, but
  bind a later create arm directly to the durably staged 16 bytes. The latter
  deliberately survives loss of the live ACM context across a crash/reboot
  after deletion; stable absent-primary inventory and the journal remain
  mandatory.
- [x] Implement the bundle store, journal transitions, recovery matrix, and
  activation-secret reader with no secret-bearing public representation.
- [x] Implement the dependency-injected coordinator with durable intent before
  each mutation, no delete/create retry path, exact UUID recovery, convergent
  partial/final bundle publication, idempotent disabled mapping commit, and
  direct or fresh-boot handle-release closure.
- [x] Separate old-primary inventory from live ACM production: the former runs
  first because it clears authorization; staging, DELETE arming, and dispatch
  then occur inside the subsequently created live identity-secret context.
- [x] Update mapping policy to bind the activation-secret digest and
  generation.
- [x] Close process-loss windows at bare DELETE, CREATE, and EXPORT intent;
  reconfirm an already-proven deletion on a fresh boot/connection before
  creation, and retire a pre-delete crash only after fresh exact old-primary
  proof.
- [x] Add the fixed-purpose `t2-native-replace` broker and an atomic mapping
  handoff that durably archives exact D138 authority before replacing it with
  the disabled activation-bundle mapping.
- [x] Pass the focused 19-test journal/coordinator/bundle/mapping gate plus
  Python compilation and installer shell syntax through fresh required test
  workers. Earlier focused C-backed validators and the module build remain
  clean at this source boundary.
- [x] Implement and focus-validate the different-boot activation broker. Its
  separate hash-chained journal admits one activation attempt per Linux boot,
  records every load/bind/configure/authorize/unlock/unload intent, requires a
  fresh-owner ready read-back before mapping promotion, and resolves an
  interrupted attempt on a later boot as ready, safely retryable, or
  quarantined without blind redispatch. A fresh bounded worker passed Python
  and installer syntax, diff integrity, and all three focused positive,
  crash-recovery, and mismatch-quarantine tests; no device was opened.
- [x] Install without live reload and reconcile exact installed sources. Root
  snapshots 121 and 122 preserve the before/after boundary; installed source
  and both replacement executables match the committed files, the next-boot
  module option contains `enable_identity_replacement=1`, the live D170 module
  remains unchanged, journals remain absent, and consumers remain gated.
- [x] Commit the executable activation source boundary and obtain exact private
  Gitea push/read-back: commit
  `9d782cbf55aff5fb686f85d7378ba11cfbc7c573`, tree
  `5e2223de39baa27939309298dd632f7315497330`.
- [x] Cross the D171 controller-attested reboot and reconcile the complete
  installed boundary.
- [x] Classify the single D171 inventory result: stable absent primary, with
  no journal or mutation.
- [x] Implement and focus-validate the explicit absence preparation,
  reconciliation, crash-reconfirmation, and direct-create path without a
  delete transition.
- [x] Checkpoint and install the D172 userspace generation without live module
  reload. Private Gitea read back source commit
  `bdf8fcf3a5370e3239d5da212039241b2b392532` and tree
  `ef04e0f9633e9e95d330cb6e4b286a8067f0427c`; root snapshots 124/125
  preserve the exact pre/post install boundary.
- [x] Cross the D172 controller-attested reboot and run exactly one no-delete
  reprovision transaction. CREATE/export/bundle/mapping succeeded; snapshots
  126/127 preserve the pre/post result.
- [x] Checkpoint the `mapping-committed` result and cross D173. One resume
  proved stable pre-load primary absence and no holders without mutation.
- [x] Implement and focus-validate the explicit unloaded-primary completion
  record with bundle/mapping/archive re-verification.
- [x] Checkpoint and install the D173 correction. Private Gitea read back
  commit `b63f5a9b59d8a8ca3e2fbb0a39c2039c89af330b` and tree
  `35089e3c8e8ac55008e5d453125454c096e413e7`; snapshots 128/129 preserve the
  exact install boundary without module reload.
- [x] Cross D174 and run one replacement resume. Two stable pre-load-primary
  status-`-3` reads, exact bundle/mapping/archive verification, and zero live
  handles appended `HANDLE_RECONCILED_PRIMARY_ABSENT`; the journal is complete
  with 11 records and root snapshot 130 preserves it.

Any failed gate blocks the mutation. It does not authorize a reduced journal,
plaintext logging, raw option `0x200`, create flag `0x100`, a second identity
creation, or a speculative reboot.
