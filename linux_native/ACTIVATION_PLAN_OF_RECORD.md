# Linux-native T2 identity activation plan of record

**Status:** completed. D178 proved native activation, D179 proved it survived a
fresh boot, and D196-D218 carried that authority through native enrollment,
matching, deletion/recovery, and continuous second-finger enrollment —
2026-09-13

This document preserves the plan and evidence that crossed the former
AppleKeyStore identity-activation boundary before the first Linux-native T2
fingerprint enrollment. The ordered plan below is historical, not an active
runbook. Its result remains the novel foundation of the project: Linux
activated a clean-wipe, Linux-created identity and carried it into native
enrollment without relying on macOS state at runtime.

The 2026-09-12 multi-project review is summarized by the
[public research credits](../docs/research/artifacts-and-method.md#research-credits). KAIT2EN now
independently proves verification of macOS-enrolled fingers on T2, but does not
create, activate, or enroll a Linux-native identity. Its direct-password AKS
operation `0x04` is the separate path already modeled by `unlock_alias`; it is
not a replacement for selector-`0x9a`'s fixed ACM-bearing operation `0x18`.
T1Bridge corroborates retained-secret and authorized-enrollment lifetimes, but
its T1 operation ordering is not T2 authority. Matching J152f recovery and T2
hardware observations remain the basis for the `0x21` then `0x18` sequence.

The current objective is product integration: adapt the proven owners into a
narrow broker and libfprint/fprintd backend, then validate PAM and independent
password fallback. The remainder of this document records the completed
D137-D179 reasoning and transaction.

## Decisive result

D137 and D170 use the same final derivation primitive but feed it different
bytes. The mismatch is deterministic, not a flaky transport or UI result.

For D137, original flags `6` leave create-time ACM extraction disabled. The
operation-`0x01` v5 handler normalizes item 1 through `0x102904` with mode zero,
which takes `0x1027c0`'s raw allocation/copy branch. The 16-byte externalized
ACM context reference itself therefore becomes the KDF input. Creation helper
`0x0e39e0` reaches `0x0de814`, which generates a 16-byte salt at bag offset
`+0xcc`, selects a platform-dependent work factor through `0x0d70c8`, stores
that factor at `+0xe0`, and calls common derivation helper `0x0db30c`. The
resulting 32-byte verifier is linked into the bag's credential records.

For D170, operation `0x21` option `0x100` tells `0x1027c0` to resolve the new
live ACM reference and extract its type-5 password bytes. Verifier helper
`0x0eaf9c` passes those bytes, the restored salt, and the restored work factor
through `0x0da028`/`0x0db2cc` to the same `0x0db30c` derivation helper. Its only
raw `-5` assignment on this path is the final comparison mismatch at
`0x0eb4e2`–`0x0eb4f2`.

The create mode value is `9` and the verify mode value is `1`, but their bits
examined by `0x0db30c` are equivalent on these paths. The byte source—not the
KDF, salt, work factor, output size, loaded handle, or optional authorization
target—is the material difference.

## Creation-versus-verification field map

| Field | D137 creation | D170 verification | Classification |
| --- | --- | --- | --- |
| Input object | creation-time live type-5 ACM external form | later live type-5 ACM external form | same container class; identifier equality untested and immaterial to the observed mismatch |
| Normalization control | original flag `0x100` clear | option `0x100` set | different |
| Bytes sent to KDF | raw 16-byte external reference | extracted account-password bytes | different, decisive |
| Salt | generated/stored at bag `+0xcc` | restored from bag `+0xcc` | same durable field |
| Work factor | selected by `0x0d70c8`, stored at bag `+0xe0` | restored from bag `+0xe0` | same durable field |
| Derivation core | `0x0db30c`, 32-byte result | `0x0db30c`, 32-byte candidate | same |
| Mode bits used by core | mode `9` | mode `1` | equivalent for tested bits |
| Persisted verifier | credential record linked at bag `+0x2a0` | final candidate comparison | same verifier lifecycle |
| Output authorization context | none during creation | none in D170 | same/irrelevant |

Operation `0x02` exported the bag after creation and D138 restored it with
operation `0x03`. D170 reaching the final comparison after that different-boot
reload independently proves the salt, work factor, and verifier lifecycle
survived persistence. A serializer field-by-field annotation remains useful
documentation, but is no longer a blocker to the causal conclusion.

## D137 recoverability boundary

The original raw external reference was not retained by the Linux transaction.
The D137 owner wiped its request, response, external-form buffer, and secret
buffers, then deleted the ACM context. Its journal contains only digests and
metadata. The immutable post-D137 filesystem snapshot contains the saved
keybag and transaction records but no separate 16- or 32-byte activation-secret
object. D168 proves a deleted reference cannot later be dereferenced as an ACM
context. D167/D170 prove that option `0x100` extracts the new context's inner
type-5 bytes and that those password bytes do not reproduce D137's raw-reference
verifier. They did not compare independently created external identifiers, and
this plan does not claim that they did.

The 162-byte operation-`0x01` output was also wiped. Matching host code labels
that output `OTI + KEK`, wraps it separately, and passes it only to the APFS
VEK-binding path; it exports and saves the reloadable bag independently. The
identity-verification path accepts the saved bag plus credential objects and
has no input edge from this create output. Even if an unparsed subfield had
contained the reference, Linux retained none of its bytes. It therefore cannot
recover D137.

The derivation path closes the serialized-bag escape as well. `0x0de814` passes
the raw input to `0x0db30c`, returns only its 32-byte result, and does not copy
the raw input into the bag. `0x0e39e0` retains the salt, work factor, and derived
credential record. Operation `0x02` can serialize that state but cannot export
bytes the creation path never retained.

The matching operation-`0x07` change-secret handler at `0x0ea204` closes the
last repair escape for this bag. It normalizes distinct old and new credential
pairs, derives a 32-byte candidate from the first pair through `0x0da028`, and,
for D137's populated credential-record state, checks that candidate through
`0x0e3094`. Only after that succeeds does `0x0e39e0` construct replacement
credential state from the second pair. There is no old-secret-free branch for
the D137 state.

The discarded reference has 128 bits and is consumed through a salted,
iterated KDF; recovering it from the saved verifier is not viable. D137 is
therefore **non-activatable**. Preserve it as creation/export/reload evidence,
but deliberately replace it before enrollment.

## Ordered proof and implementation plan

### 1. Adopt the selected credential lifecycle

Use the ordinary recovered request-10 creation contract unchanged:

1. Create the mapped-user ACM context, install the creation credential, and
   externalize it.
2. Preserve the exact 16-byte creation-time external form as an opaque,
   root-only **T2 activation secret before** operation `0x01` can commit.
3. Create the identity with original flags `6`. Matching SEP therefore derives
   its verifier from those exact 16 bytes.
4. Export and atomically persist the saved keybag and activation secret under
   one journaled transaction. Neither artifact is valid alone.
5. On activation, create a fresh mapped-user ACM input context and install the
   saved 16-byte activation secret as its type-5 data. Externalize that context
   and send it through the normal identity option `0x100`; SEP extracts the
   type-5 bytes and reconstructs the creation-time KDF input.
6. When authorization output is required, keep that input context live while
   creating a distinct policy-1007 target context. Operation `0x21` verifies
   the input and authorizes the target; fixed operation `0x18` receives the
   original input reference as the login credential while the authorized
   target remains live. Destroy both in reverse order.

This is selected over raw option `0x200`: matching host identity verification
uses option `0x100`, and the live input/output-context lifecycle is already
recovered and implemented. It is selected over adding original flag `0x100`:
that would change the ordinary flags-`6` creation contract and switch the
durable verifier to account-password bytes without a matching host-policy
precedent. The exact T1 secret, size, codec, and USB transport remain rejected;
only its explicit credential-continuity lesson is adapted.

The activation-secret origin gate is complete in matching captured firmware.
SCRD command 1 reaches fresh-context helper `0x0bc408`, which requests exactly
16 bytes through `0x0ccee8`. That wrapper obtains the shared `ccrng` object
through the SCRD import at `0x0d04b8`, shared-library getter `0x027224`, and
initializer `0x027158`. The initializer locates the `TRNG` driver and installs
generator `0x0271c8`; its integrity and failure strings identify
`ccrng_sep_trng_generate`, `Could not locate TRNG driver`, and `Failed to
generate entropy`. SCRD compares every candidate against two reserved values
and all existing live handles through `0x0ce6b8`, regenerating on any match.

The saved external form is therefore an opaque 16-byte, SEP-TRNG-backed,
uniqueness-checked handle—not a predictable counter or host-selected label.
Once retained, it must be treated as a bearer secret rather than an ordinary
identifier: root-only storage, no logs or command-line exposure, no value in
journals, bounded mutable copies, explicit wiping, and fail-closed loss
semantics are mandatory. No hardware entropy discriminator is needed.

### 2. Hold implementation to the specified reprovision transaction

The executable
[`D171_REPROVISIONING_DOSSIER.md`](D171_REPROVISIONING_DOSSIER.md) fixes:

- the exact create input, raw normalization, saved activation-secret bytes,
  option-`0x100` reconstruction, and later authorization request;
- root-only at-rest protection, atomic persistence, wiping, backup, and loss
  semantics for any separate bearer secret;
- exact stable inventory and a branch selected before ACM acquisition: delete
  only when the old UUID is present, or explicit no-delete reprovision when
  the primary is absent;
- preservation of the D137 keybag, journal, mapping, and immutable evidence;
- rollback boundaries when SEP state changes but local persistence fails;
- a different-boot load/UUID/credential proof before any Catacomb mutation;
  and
- service/PAM gating until positive and negative controls pass.

The single D171 live start found two stable signed status-`-3` primary reads,
then stopped before journal creation or mutation. The old identity therefore
cannot and need not be deleted. Its immutable host evidence remains protected;
the stale canonical mapping is archived only when the new disabled mapping is
atomically committed.

The no-delete path must never be represented by the deletion state machine.
It begins with `ABSENT_REPROVISION_PREPARED` and `delete_required=false`,
durably stages the creation-time secret, proves absence again on the exact
create owner, and reaches CREATE only through `ABSENCE_RECONCILED`. A crash
requires fresh-owner absence proof or safe abandonment. An intended CREATE is
never redispatched.

### 3. Implement and validate without hardware

Make the smallest code change that realizes the selected lifecycle and its
transaction. Add or update only tests that protect a named durable-secret,
wire-shape, or ambiguous-outcome invariant. Run the smallest relevant gates
once through the required fresh test worker. Install without live module
reload, reconcile exact sources, and checkpoint through the required fresh
Gitea worker before any reboot.

### 4. Open one pivotal D172 transaction

D171 may open only when its record states in advance:

- the exact matching-code finding that requires the change;
- the smallest wire/state delta from the failed lifecycle;
- the predicted mailbox status and subsequent state transition;
- the success criterion and independent read-back;
- the meaning of every expected failure class;
- bounded cleanup and outcome-unknown handling;
- whether D137 is preserved or replaced; and
- the single next action for either outcome.

The transaction has two separately reconciled hardware phases. The first boot
reconfirms primary absence, creates, exports, and atomically commits exactly
one fresh identity plus its activation secret, and archives the stale mapping
without sending delete. The second boot loads that exact keybag, proves UUID
equality, binds the alias, verifies the saved secret through a fresh type-5
input context, authorizes a distinct policy-1007 target, and independently
reads back the unlocked state. Only that positive and a negative-control
rejection may proceed to the already-built empty-Catacomb enrollment path and
physical fingerprint interaction.

## Viability

The project remains technically viable, and this analysis is material
progress. Linux already creates and exports a T2 identity, persists and reloads
it across boots, verifies its UUID, reaches the exact firmware credential
comparison, and cleans up safely. D170's failure is explained by a concrete
byte-level lifecycle defect, D137's recovery escapes are closed, and one
matching-host/firmware-compatible correction is selected.

D137 cannot be activated because Linux omitted its creation-time KDF input,
and D171 now proves its old primary is absent after the later cold lifecycle.
That is a supersedable provisioning-generation failure, not evidence that
native T2 enrollment is impossible. Linux already proved the create/export
machinery from the same absent-primary state, while D172 now preserves the
missing input. The remaining decisive risk is specific: whether SEP accepts
that retained value through operation `0x21`, authorizes operation `0x18`, and
reports independently ready after a different boot. The project remains
credible, but no end-to-end success claim is warranted until that hardware
result exists.

D172 materially strengthens that assessment: direct CREATE returned success
with the retained input already durable, and the exported keybag, bundle,
disabled mapping, and old-mapping archive all reconcile. The sole incomplete
replacement record is ambiguous live-handle unload, which is intentionally
resolved only by a fresh boot. After that closure and another reboot, hardware
operation `0x21` is the remaining decisive activation discriminator.

D173 confirmed that the per-boot primary is absent before the saved keybag is
loaded, while the exact bundle and disabled mapping remain intact and no live
handle survives. Replacement completion therefore records verified bundle,
mapping, archive, stable primary absence, and zero handles. It does not demand
live-primary persistence that the activation transaction itself is designed
to establish by loading the saved object.

D174 executed that corrected completion path exactly once. It issued two
operation-`0x51` reads, received stable status `-3`, emitted no CREATE or
DELETE, required zero kernel handles, and appended
`HANDLE_RECONCILED_PRIMARY_ABSENT`. The hash-chained replacement journal is now
`complete` with 11 records, the mapping remains disabled, and no replacement-
activation journal exists. Root snapshot 130 preserves the terminal boundary.
The next hardware action belongs to a further boot and only to
`t2-native-replace-activate start`.

## D177 closes the login-carrier ambiguity

D177 loaded the exact replacement keybag, verified its UUID, bound its alias,
resolved configuration, and completed option-`0x100` operation `0x21` with a
distinct policy-1007 target. The target's final policy check was satisfied.
Operation `0x18` then returned signed SEP status `-5`; independent read-back
remained device-locked. No physical prompt, Catacomb request, enrollment
mutation, mapping enablement, retry, or surviving handle followed. The
hash-chained replacement-activation journal preserves the interrupted unlock
boundary.

Exact macOS 26.6.2 LocalAuthenticationCore closes what the earlier firmware
analysis left ambiguous. `authenticateUser:credential:domain:disk:contextRef:`
passes `LACUserCredential.password.contextRef` as the authentication input and
the separately supplied `contextRef` as the authorization output target.
Later, the login closure again extracts
`LACUserCredential.password.contextRef` and passes that original credential to
`loginUser:credential:session:disk:error:`. AppleKeyStore's XPC client likewise
serializes distinct `acmcred_in` and `acmcred_out` fields for authentication,
while login serializes only one caller-selected `acmcred`.

The D177 request used the authorized output target as the login credential.
Matching firmware's operation-`0x18` unwrap consequently derived the wrong
key and returned `-5`. The selected D178 delta is now exact: retain both live
contexts, preserve successful target authorization as the admission proof,
but carry the original input reference in operation `0x18`. The kernel must
require that request/input equality independently from authorized-target/live-
target equality. This is a caller-contract correction backed by the exact
Apple call chain, not another speculative payload variation.

## D178 proves native activation; D179 closes cleanup reconciliation

D178 validated the selected correction on hardware. Operation `0x21` again
authorized the distinct policy target; operation `0x18` using the original
input returned status 0, and immediate alias observation was `ready`. This is
direct evidence that Linux reconstructed and activated the new Linux-created
identity correctly.

The journal stopped after the `REPLACEMENT_ALIAS_UNLOCKED` record because one
or more explicit ACM deletes reported failure as the authorization context
manager unwound. The primary body had already completed, including status-0
unlock and readiness read-back. Closing the ACM descriptor then exercised the
kernel's fixed two-attempt cleanup owner, and a fresh descriptor opened without
the poison flag. D179 may accept only that cleanup-only case after forcing the
close and requiring the clean reopen. It must never suppress a primary
operation error or accept a poisoned endpoint. A fresh boot then repeats the
activation once so unload, independent-owner readiness, and mapping enablement
can complete under the existing journal contract.

D179 crossed the required fresh boot and needed no activation redispatch. A
fresh owner observed the exact alias already ready, which independently proves
D178's activation survived descriptor and boot boundaries. The owner then
enabled the exact disabled mapping and completed the journal. The plan-of-
record activation milestone is closed; native enrollment is now authorized
under the existing empty-baseline and Catacomb transaction gates.
