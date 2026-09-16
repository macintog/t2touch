# AppleKeyStore identity persistence transaction

**Status:** completed on the reference machine. D172/D173 persisted the
activation-bearing generation, D178/D179 activated it across reboot, and
D196-D218 used it for the native biometric lifecycle — 2026-09-13

This document separates two artifacts that were previously conflated: the
optional KEK returned by identity creation and the saved keybag object needed
to reload that identity after reboot. The recovery is from the signed x86_64
AppleKeyStore artifacts and matching J152f bridgeOS `23P6068` SEP application
recorded in [firmware provenance](../docs/research/artifacts-and-method.md#firmware-identities). D137/D138 sent
the create, export, persistence, and different-boot reload sequence to the
reference T2; the later activation and biometric results remain separately
journaled and are complete through D218.

## Create does not return the reloadable object

The selector-`0x76` helper in `applekeystored` returns a live handle and a
structured byte output. Its caller logs `Saving OTI + KEK`, wraps that byte
output in `CFData`, and supplies it to
`APFSVolumeBindNewKEKToVEKWithOptions`. Earlier static analysis of the J152f
create-v5 handler incorrectly concluded that its second output was never
populated. D137 directly observed a successful 162-byte returned blob on the
reference firmware, so that negative static claim is withdrawn. Zero length
remains structurally representable, but is not the observed D137 result.

The endpoint-7 operation-`0x01` response body is therefore:

```text
u32 version = 5
i32 live_handle
blob optional_kek_material
```

Operation failure is reported by the signed status byte in the endpoint-7
mailbox reply. It is not a leading status word in this response body. The
strict decoder in [`src/t2_aks_identity_create.py`](../src/t2_aks_identity_create.py)
reflects that distinction.

Linux has no macOS APFS VEK-binding side effect in the native Touch ID path.
The returned material must never be mistaken for the reloadable keybag.
D166's recovered identity-verification path consumes the saved keybag and an
input credential without directly accepting this create output. Matching SEP
recovery after D170 shows D137 derived its verifier from the raw 16-byte
creation-time ACM external reference, while Linux discarded both that
reference and the 162-byte output. The host labels the latter `OTI + KEK` and
passes it through a separate APFS VEK-binding path. The verifier path has no
input edge from that output; creation retains the derived record rather than
the raw reference. The corrected Linux transaction must therefore atomically
persist the saved keybag and the exact creation-time external form as separate
root-only artifacts; the returned `OTI + KEK` remains outside the native
Touch ID persistence contract.

## The reloadable object is a second operation

After create succeeds, `applekeystored` calls `identity_copy_keybag_data` with
the live handle. That helper invokes AppleKeyStore user-client selector `3`
and receives a saved identity object. The daemon then commits it under
`/var/keybags` using a temporary path. Its reload path reads that object and
passes the bytes to `aks_load_bag`, which reaches endpoint-7 operation `0x03`.

In the matching kext, `AppleKeyStore::copy_keybag` calls
`__ipc_copy_keybag_v1`, which sends endpoint-7 operation `0x02`. The v1 record
has these direction-dependent bodies; a blob is a little-endian length, bytes,
and zero four-byte alignment padding:

```text
request:
    u32 version = 1
    u64 generation_session
    i32 live_handle
    blob optional_compatibility_input

successful response:
    u32 version = 1
    blob saved_keybag
```

The hardware-free module now provides strict
`AKSIdentityCopyKeybagV1Request` and `AKSIdentityCopyKeybagV1Response` codecs.
The response rejects an empty saved object, trailing data, malformed length or
padding, and the wrong version. This is a serialization boundary only; it
exposes no transport and grants no permission to retry.

`src/t2_aks_provisioning.py` now supplies the non-secret durable state chain:

```text
create intent -> create succeeded -> export intent -> export succeeded
-> saved keybag committed -> live UUID verified -> mapping committed
-> different-boot load and UUID verified -> mapping enabled
```

The first intent requires explicit xART-ready, stable-inventory, and primary-
identity-absent attestations. Create and export are bound to the same fresh
session and live handle. An ambiguous create or export can transition only to
`outcome-unknown`; the journal has no retry transition. It records only
digests, lengths, UUIDs, and booleans—never the saved keybag or KEK.
Every proposed transition is validated against an in-memory extension of the
hash chain before it can be appended, so an invalid call cannot durably poison
an otherwise recoverable journal.

`SavedKeybagStore` exclusively creates `user.kb` in a pre-existing private
caller-owned directory. It verifies the exact journaled export digest, writes
and syncs a mode-`0600` temporary file, atomically renames it without replacing
an existing destination, syncs the directory, and wipes the caller's mutable
buffer on every exit.

`src/t2_aks_provisioning_operation.py` is the dependency-injected transaction
owner. It binds the exact preflight digest and Bridge connection generation to
the create intent, consumes one nonzero 16-byte ACM external form, sends create
and export through an owned transport, validates responses without copying KEK
bytes, wipes every ACM/request/response/secret buffer, persists the export,
checks the live bag UUID, and commits the mapping. A separate entry point can
close the journal only after another Linux boot loads the saved object and
reproduces that UUID.

`src/t2_user_mapping_store.py` supplies the first Linux-owned mapping writer.
It reopens and hashes `user.kb`, emits the strict existing mapping schema with
the entry disabled, and atomically creates the mapping file. Repeating the
commit after an interrupted journal append succeeds only when the existing
mapping is byte-for-byte identical; any binding drift remains a collision.
Only exact different-boot load/UUID verification can atomically replace those
bytes with the corresponding enabled mapping. The journal records both mapping
generations, so a disabled mapping can never become runtime authority merely
because the provisioning process exited successfully.
If the process stops after recording reboot verification but before promotion,
the same boot may resume directly. After any further reboot it must load and
verify the saved keybag again and record `AKS_REBOOT_REVERIFIED`; it cannot
strand the mapping or reuse stale live-handle evidence.

As with create, operation failure is in the mailbox status byte rather than a
body status field. `_code_ipc_copy_keybag` at `0xffffff8001a8ea10` selects the
request fields at record offsets `+0x58`, `+0x60`, and `+0x68/+0x70`, and the
response blob at `+0x78/+0x80`. `__ipc_copy_keybag_v1` at
`0xffffff8001ad5821` sends operation `2` and copies that response blob to its
caller. Both request and response buffers are scrubbed by
`_post_process_ipc_copy_keybag`.

The matching J152f operation-2 descriptor begins at `0x113ac8`. Its execution
wrapper at Thumb address `0x0be988` dispatches version 1 to `0x0e3c28`. That
handler resolves the live object by the session/handle pair and calls
`0x0d8ad8` to serialize the saved keybag. On this build the optional
compatibility input is not consumed, matching the host daemon's supported
null-input path. This is exact-reference evidence, not permission to remove
the versioned field for other implementations.

The serializer clears live-object save-state fields after export. Despite the
host API's `copy` name, a timeout cannot be treated as permission to repeat
operation `0x02`.

## A reloaded identity unlocks through an ACM state transition

D161 proves that load, UUID verification, negative-alias binding, and
configuration resolution are necessary but not sufficient when followed by
raw password operation `0x04`: the alias remains device-locked. The matching
24G830 `applekeystored` path instead uses
`service_identity_login_with_acmcred`. User-client selector `0x9a` reaches
`AppleKeyStore::unlock_the_device`, then `device_state_transition`, and sends
endpoint-7 operation `0x18`.

For the reference firmware, its request body is one fixed 48-byte record:

```text
u32 version/result = 0
u64 generation_session = 1
i32 bound_negative_alias
u32 transition = 0
u64 flags = 0x100
u32 credential_length = 16
u8  externalized_acm_credential[16]
```

The successful response is exactly 20 bytes: a zero `u32` followed by two
opaque `u64` outputs. Linux validates the fixed envelope, immediately wipes
and ignores both opaque outputs, and treats a separate alias-state read-back
as readiness authority.

The matching J152f SEP operation table independently maps operation `0x18` to
the recovered decoder and handler. That handler admits transition zero and
retains flag `0x100` through its supported mask. The request-10/type-5 ACM
identity-secret context is creation material, not the login credential: D162
and D163 reached this transition with Linux- and Apple-user contexts
respectively and SEP returned status `-5` both times. D164 then created the
correct Apple-user policy-1007 context but attempted its operation-`0x21`
password binding against the still-locked negative alias; that operation
returned status `-5` before `0x18`. D165 moved the same selector-42 request to
the exact positive load handle and received the same status, falsifying the
target-handle hypothesis.

Selector 42 uses option `0x200`. The exact 24G830 identity path instead uses
option `0x100`, which reconstructs its secret field as an ACM external form
and extracts type-13/purpose-701 credentials or type-5 data. D166 paired that
option with plaintext and returned `-1`. D167 supplied one valid ACM reference
as both secret and optional target but returned `-5`. Recovered Apple APIs and
the request-21 packer resolve the distinction: the input credential and target
authorization context are separate. D168 destroyed its staged input before
creating the target and returned `-1`, proving that deletion invalidates the
external form. D169 keeps the password/type-5 input live while creating a
distinct policy-1007 target. Successful `0x100` verification reads the live
input and authorizes only the target. Fixed operation `0x18` then consumes the
original input reference as its login credential against the bound negative
alias while that authorized target remains live. Both contexts are destroyed
in reverse order. Selector-42 compatibility remains `0x200`.

The kernel therefore admits identity-verification option `0x100` only for the
exact owned, bound, non-poisoned positive runtime handle, one exact live
16-byte input reference, and a distinct simultaneously live 16-byte target
context. Only one same-user target create is admitted while the input is the
active externalized context. The input is consumed by the one verifier result,
restored only for reverse-order destruction, and wiped on close or poison.
It admits `0x18` only once per loaded runtime handle and
only when all of these facts agree: the positive handle is live, a successful
operation-`0x0d` reply bound the requested negative alias, operation `0x21`
authorized the still-active policy context against that exact positive handle,
the request has the fixed shape above, its 16 credential bytes equal the
retained original identity input, and the recorded authorized target equals
the still-active ACM target. Load and unload reset this ownership state. The
native owner creates the ACM inputs only after configuration resolution,
consumes the original reference in `0x18`, destroys target then input, reads
the alias independently, and then unloads the positive handle.

T1Bridge remains useful for persisted-user lifecycle ordering, but its T1
model stores a separate random 32-byte user secret and later uses that secret
for unlock. The T2 request-10 identity created in D137 persisted only the
exported keybag; its transient ACM credential came from the account password.
Therefore the T1 lifecycle order is **adapted**, while its separate-secret
persistence and unlock wire model are **rejected** for this T2 identity.

## Required Linux transaction

Once xART durable storage is available and read-only inventory has explicitly
reported empty, provisioning must be one journaled transaction:

1. Atomically record intent: account UUID, transport generation/session,
   exact create-request digest, and expected empty durable state.
2. Send operation `0x01` once.
3. On success, retain the returned live handle and immediately send operation
   `0x02` in the same generation/session with an empty compatibility blob for
   the matching J152f path.
4. Atomically persist the operation-`0x02` saved keybag in a root-only file,
   recording its digest and length; zeroize transient buffers.
5. Commit the account mapping only after the file and journal are durable.
6. On a later boot, load that exact file with operation `0x03` and validate
   the returned identity UUID with operation `0x06` before unlock,
   BiometricKit provisioning, enrollment, or PAM.

If operation `0x01` or `0x02` times out, the journal remains ambiguous and
neither operation may be retried blindly. A successful primary-identity read
can reconcile durable registration against the intended account UUID, but it
cannot reconstruct a lost operation-`0x02` output. Therefore create must not
be enabled until operation `0x02`, atomic local persistence, and a deliberate
ambiguous-export recovery policy are implemented together.

The kernel now admits operations `0x01` and `0x02` only when the off-by-default
`enable_identity_provisioning=1` probe flag is combined with endpoint-7 and ACM
OOL registration, xART OS-UUID publication, versioned SEP-app startup,
capability probing, and `inventory_only=0`. Even then, create requires a
successfully negotiated v2 AKS header. These are protocol/capability gates, not
Mac-model predicates.

An exclusive AKS open owns one per-boot phase machine. It permits one exact
88-byte create, records the validated positive response handle, blocks every
intervening operation except the exact 20-byte export for that session/handle,
and accepts only a nonempty, aligned export response. Failure, malformed reply,
lost userspace response, or closing between create and export poisons
provisioning until reboot. A completed transaction cannot create again in the
same boot, but may issue the one exact same-owner operation-`0x06` UUID read.
Each module registration also receives a nonzero kernel-generated 128-bit
connection generation. A read-only info ioctl reports that generation and the
actual OOL/ACM/xART/version/provisioning, negotiated-header, phase, poison, and
stable-absence state without accepting userspace claims.

Create additionally requires the same open descriptor to observe two exact
absent-primary operation-`0x51` results under the create request's nonzero
session. The kernel resets that evidence on open/close, a different session,
a present/malformed/unavailable inventory response, or an unrelated AKS
operation. The exact request-10 credential producer is the sole permitted
intervening authorization: ACM command `0x28` must set type-5 data on the
currently active context and command `0x13` must externalize it. The kernel
records the successful command-`0x28` context and rejects create unless its
item-1 field, that recorded context, and the still-active non-poisoned ACM
context are byte-identical. Any inventory transition or unrelated AKS
authorization clears the create credential.

`src/t2_aks_provisioning_transport.py` holds that descriptor across the exact
stable-empty observation, create, export, and UUID verification. It is
composed synchronously inside `identity_secret_context`, which mirrors request
10's create/set/externalize/consume/delete lifetime. The fixed-purpose
`t2-native-provision` command owns this sequence without exposing a generic raw
operation API. Operation `0x21` remains a password verifier for an existing
loaded keybag; requiring it for first identity creation would make greenfield
provisioning impossible.

The existing-identity verifier has two separately recovered forms. Both pass
one live externalized ACM credential reference as the verifier input. The
authorization form also passes a distinct output context; the verify-only form
omits it. On the reference host's console-user path the option is `0x100` in
both cases. D170 deliberately exercises only the no-output form, consumes and
cleans the transient input, and never publishes password authorization. Its
`-5` result excludes output-context construction without creating a biometric
or Catacomb mutation path. Matching J152f recovery now proves that verifier
helper `0x0eaf9c` assigns raw `-5` only at its final credential-comparison
mismatch on D170's path. Matching creation-side recovery now closes the main
ambiguity: D137 original flags `6` left ACM extraction disabled, so creation
fed the raw 16-byte external reference into the KDF. D170 option `0x100`
dereferenced a fresh context and fed its inner type-5 password through the same
derivation core with the restored salt and work factor. The final mismatch is
therefore deterministic even when the literal account password is unchanged.

The authoritative
[identity and authorization reference](../docs/research/identity-and-authorization.md#the-retained-creation-input) records the
creation-versus-verification field map, D137's proved non-recoverability, and
the selected replacement lifecycle. The create output was discarded and has
no verifier input edge; creation retains only derived verifier state; and the
matching change-secret handler checks the old derived credential before it
constructs the new one. A new identity or another hardware request is not a
diagnostic shortcut. D171 requires the protected creation-time external form
to be committed as an activation secret, later installed as type-5 data in a
fresh input context for option `0x100`, plus an independently reconciled
replacement/rollback procedure.
