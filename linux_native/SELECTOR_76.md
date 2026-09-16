# AppleKeyStore identity creation: matched host and J152f paths

This document records static interoperability evidence from the x86_64
RecoveryOS artifact in [firmware provenance](../docs/research/artifacts-and-method.md#firmware-identities).
The exact `j152f` bridgeOS `23P6068` restore contains an AppleKeyStore SEP app
with the same `2155.160.13.0.1` source version. Its operation-1/version-5
decoder independently confirms the request field widths and order below. No
endpoint-7 identity-create request described here has been sent to the
reference hardware. The transient endpoint-10 producer used by request 10 has
been validated independently, as recorded below.

## Three distinct protocol layers

| Layer | Recovered value | Meaning |
| --- | --- | --- |
| AppleKeyStore user client | selector `0x76` | macOS host API boundary |
| AppleKeyStore internal IPC | create-keybag record version `5` | kext-side typed record |
| SEP mailbox | endpoint `7`, operation `0x01` | out-of-line request sent to T2 |

Selector `0x76`, endpoint 7, and operation `0x01` are not interchangeable.
In particular, the selector number must not be copied into the Linux kernel's
endpoint-operation allowlist.

## Recovered user-client ABI

The x86_64 `applekeystored` helper at `0x1000043e5` calls
`IOConnectCallMethod(0x76, ...)`. Its caller at `0x100004d95` is in the
`service_identity_create_with_prehash_internal` path.

The call supplies:

- three scalar inputs: effective-bag selector/handle input, flags, and an
  additional scalar whose semantics remain unknown;
- one packed structured input;
- one scalar output containing the returned bag handle; and
- one structured output containing optional KEK material used by the host's
  APFS VEK-binding path.

The input structure is a little-endian item vector:

```text
u32 item_count
repeat item_count times:
    u32 byte_length
    u8  data[byte_length]
    u8  zero_padding[(-byte_length) & 3]
```

Item 0 is a 16-byte account UUID. Items 1 through 3 depend on the creation
variant. The helper emits two, three, or four items. When both optional values
exist, the kext passes item 3 before item 2 to `identity_create`; this ordering
is preserved below.

The exported x86_64 framework entry point
`AKSIdentityCreateKeybagWithHash(uuid, prehash_salt, prehash_iterations,
prehash_acmref, error)` emits XPC request 31. Its daemon handler passes the
ACM reference as item 1, the prehash salt as item 2, the iteration count as
scalar 2, and `-1` as the effective-handle input. This mapping is recovered
for that variant specifically; it must not be generalized to the other
creation entry points.

## Recovered kext call chain

The selector dispatcher validates one scalar output, resolves scalar input 0
with `effective_bag_handle_actual(0x76, ...)`, unpacks the item vector, and
calls:

```text
AppleKeyStore::identity_create(
    u64 session,
    OSData *account_uuid,
    OSData *item1,
    int effective_bag_handle,
    OSData *item3,
    OSData *item2,
    u64 original_flags,
    u32 scalar2,
    OSData *optional_data,
    int *returned_handle,
    OSData **returned_kek_material)
```

The recovered method is at `0xffffff8001acd240`. It validates the UUID as 16
bytes and invokes `__ipc_create_keybag_v5` at `0xffffff8001ad5420`.

The input flag transformations visible in this build are:

- `(original_flags & 1) << 17`, producing internal bit `0x20000`;
- `(original_flags & 4) << 12`, producing internal bit `0x4000`;
- `(original_flags & 2) << 7`, producing internal bit `0x100`; and
- an internal `0x2000` bit under a branch involving original bit 3, scalar 2,
  and the optional data argument.

These are bit-level observations, not semantic flag names.

## Recovered create-keybag-v5 body

After the existing AKS v2 envelope, `_code_ipc_create_keybag` serializes the
following native little-endian request body. A blob is `u32 length`, bytes,
then zero padding to a four-byte boundary.

```text
u32 version = 5
u64 session
u32 internal_flags
i32 effective_bag_handle
blob item1
blob item2
blob account_uuid                 # exactly 16 bytes
blob item3
u64 original_flags
u64 scalar2
blob optional_data
```

The response body is:

```text
u32 version = 5
i32 live_handle
blob optional_kek_material
```

Operation failure is carried in the endpoint-7 mailbox reply's signed status
byte, not in this body. The daemon caller logs `Saving OTI + KEK` and passes
the optional bytes to `APFSVolumeBindNewKEKToVEKWithOptions`. It obtains the
reloadable OTI/keybag in a separate handle-based operation; see
[`IDENTITY_PERSISTENCE.md`](IDENTITY_PERSISTENCE.md).

The pure, strict implementation is
[`src/t2_aks_identity_create.py`](../src/t2_aks_identity_create.py). It rejects
wrong versions, oversized bodies, malformed lengths, nonzero alignment
padding, trailing data, and UUIDs of the wrong size. It intentionally exposes
the unknown fields by structural names and contains no hardware transport.

## Recovered SEP dispatch

AppleKeyStore selects `AppleKeyStore::sep_deliver_msg` when
`apple_coprocessor_version == 0x20000`. `__ipc_create_keybag_v5` calls that
callback with operation 1. `sep_deliver_msg_gated` serializes the body above
into endpoint-7 out-of-line memory and sends a mailbox descriptor whose first
bytes identify endpoint 7, operation `0x01`, and a transaction tag.

This is strong static evidence that the Linux transport operation for this
path is `0x01`. It is not authorization to send that operation.

## Matching J152f SEP decoder

The matching ARMv7 `sks` application registers internal SEP application
endpoint `0x12`. This is an SEP-internal routing value and is not the host
mailbox endpoint 7. The generic workloop separates that route from its
operation table.

In the reconstructed J152f image:

- the operation-table lookup is at `0x0bdc70`;
- operation 1's descriptor is at `0x113a9c`;
- its tagged decoder callback resolves to Thumb address `0x0bdcf4`;
- the decoder accepts record versions 0 through 5 and selects version 5 at
  `0x0be0f2`; and
- the version-5 execution path calls the implementation at `0x0e3220`.

The version-5 decoder writes a temporary record with this sequence:

```text
offset  decoder shape       host-side field
+0x50   u32                 version = 5
+0x54   u64                 session
+0x5c   u32                 internal_flags
+0x60   u32                 effective_bag_handle
+0x64   blob                item1
+0x6c   blob                item2
+0x74   blob                account_uuid
+0x7c   owned/copying blob  item3
+0x84   u64                 original_flags
+0x8c   u64                 scalar2
+0x94   blob                optional_data
```

The blob helper variants differ in ownership/copy behavior inside SEP, not in
their wire representation. The execution wrapper loads those exact fields in
that order before calling `0x0e3220`. This is a second, matching-firmware
recovery of the layout encoded by the x86_64 host path.

## Matching J152f handler constraints

The ARM procedure call boundary can be mapped without assigning names to
Apple-private policy bits. At entry to `0x0e3220`, `r0:r1` is the session,
`r2` is `internal_flags`, `r3` is `effective_bag_handle`, and the remaining
wire fields are consecutive pointer/length or scalar pairs on the stack. This
confirms that the wrapper does not reorder the decoded v5 record a second time.

The handler establishes these admission constraints:

- `item1` and `item2` are independently normalized into temporary buffers.
  Empty inputs are representable. Nonempty normalized values are bounded to
  `0x80` bytes. Original-flags bit `0x100` selects a libDER-based extraction
  path; when that bit is clear, the bytes are copied directly. This describes
  the two observed code paths, not the semantic type of either item.
- A supplied account UUID must be exactly 16 bytes and must not be the null
  UUID. The calls at `0x112d50` and `0x112d60` have the behavior of
  `uuid_copy` and `uuid_is_null`, respectively. Some flag modes allow the UUID
  pointer to be absent, while at least internal bit `0x4000` requires it.
- Effective handle `-1` selects a distinct path. When the effective handle is
  not `-1`, a simultaneously nonempty `item3` is rejected before keybag
  lookup. Session and effective handle are then used together by the lookup at
  `0x0e0f44`.
- Internal bit `0x200000` is rejected at the top of the ordinary path. Bits
  `0x400000`, `0x4000`, and `0x20000`, and the low nibble, select additional
  branches. These are bit tests only; no policy names are assigned yet.
- The handler reads only the low 32 bits of `original_flags`, and only its
  `0x100` bit is used before that register is repurposed. It does not read the
  high 32 bits, `scalar2`, `optional_data`, or the returned-material pointer in
  this J152f build. Those fields remain part of the versioned wire codec and
  must not be removed based on one implementation.
- On success the handler writes the live returned handle through the first
  output pointer. Earlier register-level analysis concluded that this build
  did not populate the second output blob. D137 directly observed a successful
  162-byte blob from the matching reference firmware, so that negative claim
  was incomplete or mapped the output pointer incorrectly. Zero length remains
  a codec-valid outcome, but it is not the observed D137 result.

The first common validation rejection in this function returns raw status
`-11`; another feature-gated rejection returns `-12`. These are protocol-local
numeric observations, not Linux `errno` names.

## Host creation variants

The RecoveryOS XPC dispatcher exposes two distinct callers of the same
selector path:

- Top-level request 10 reads `user_uuid`, `secret`, `session`,
  `session_secret`, and `secret_is_acm`. This XPC `session` is an
  effective-handle selector, not the v5 record's 64-bit session. A missing
  value, `1` through `9`, or another value below `10` maps to effective handle
  `-1`; explicit zero maps to `-4`; values at least `10` map to their negative
  handle. With `secret_is_acm` set, the supplied secret enters the lower create
  path directly. With it clear, the daemon creates an ACM context, sets the
  secret as fixed data type `5`, externalizes the context, and passes that
  16-byte external form to the lower create path.
- Request 31 is the explicitly prehashed API already described above. It uses
  the ACM reference as `item1`, salt as `item2`, iteration count as `scalar2`,
  and effective handle `-1`.

The non-ACM request-10 branch uses this exact endpoint-10 sequence:

1. Create an ACM context.
2. Send command `0x28` with the 16-byte active context, little-endian data type
   `5`, little-endian data length, the secret bytes, and an empty serialized
   parameter array (`u32` count zero). The ACMLib implementation allows at most
   `0xe00` data bytes; the Linux identity-specific API applies the narrower
   `0x80` password bound observed in Apple's adjacent AKS passcode path.
3. Send command `0x13` to externalize the context.
4. Use the same 16-byte context identifier as the ACM external form.
5. Delete the context after the lower operation completes or fails.

For request 10, the lower selector call has the account UUID as vector item 0,
that external form as item 1, optional independently produced session-secret
material as item 2, no item 3, zero `scalar2`, and no optional tail. The Linux
codec exposes only fixed type `5` with an empty parameter array; it does not
expose generic command `0x28`. This closes the formerly unknown asynchronous
plaintext transformation. It does not yet establish the complete clean-wipe
flag/state ceremony or safe recovery after an interrupted identity creation.

### Recovered request-10 storage policy

The ordinary request-10 caller passes the lower creation path two policy
booleans which select a base original-flags value of `6`. It ORs that value
with the one-byte result of `aks_apfs_get_disk_portability`. The helper derives
portability from the APFS volume's controller/protocol characteristics, not
from the Mac model. A controller that supports encryption or reports an
internal/built-in physical-interconnect location is not portable and returns
zero; the conservative external/unknown path returns one.

The wiped reference Mac boots from its internal NVMe storage. Replaying the
recovered host policy therefore selects original flags `6`, which the kext
maps to internal flags `0x4100` (`0x100 | 0x4000`). This is the clean-wipe
reference candidate, not a board constant: storage classification is a typed
lifecycle-policy input, while the flag transform remains recovered
AppleKeyStore behavior. A future external-storage test must classify its
actual topology instead of copying the reference value.

### Matching-handler session-secret discriminator

The matching J152f handler resolves whether request-10 item 2 is required for
that exact candidate. Helper `0x0bd092` compares only the low nibble of its
first argument with its second. `internal_flags=0x4100` therefore takes the
low-nibble-zero new-object branch from `0x0e3334` to `0x0e3442`.

Within that branch, every read of normalized item 2 is dominated by a
condition the request-10 candidate does not satisfy:

- the block at `0x0e34e8` requires `effective_bag_handle + 1 != 0`, while the
  new-identity candidate uses effective handle `-1`; and
- the block at `0x0e3558` requires both the item-3 pointer and length, while
  request 10 supplies no item 3.

The only remaining reference to item 2 is unconditional temporary-buffer
cleanup at `0x0e38ca`. Consequently item 2 may be empty for the exact
internal-storage, effective-handle-`-1`, no-item-3 creation variant. This does
not mean item 2 is optional for other low-nibble modes, existing-handle paths,
or item-3 variants. It also does not yet resolve which session value is valid
for a clean-wipe top-level identity.

The D137 branch then allocates a new bag, generates internal material, and
calls creation helper `0x0e39e0` with the normalized item-1 pointer/length.
D137's internal `0x4000` bit selects the helper branch at `0x0e3a80`, which
passes the account UUID, generated bag fields, item-1 material, and temporary
credential records into `0x0de814`.

That boundary is now recovered. The earlier item-1 normalizer receives
`(original_flags >> 8) & 1`; D137 flags `6` therefore select its raw copy path,
not ACM extraction. `0x0de814` generates the bag salt, selects and records the
work factor, and calls `0x0db30c` over the raw 16-byte external reference. The
32-byte result becomes persisted verifier material. D170 later calls that same
derivation core using the restored salt/work factor but the inner type-5
password extracted from a fresh ACM context, which deterministically explains
its final mismatch. The selected flags-`6`, persisted-external-form,
type-5-reconstruction lifecycle and its replacement gates are in
[identity and authorization reference](../docs/research/identity-and-authorization.md#the-retained-creation-input).

### Recovered v5 session construction

The 64-bit v5 session is not the request-10 XPC field above. In
`AppleKeyStoreUserClient::start`, the signed kext fills
`AppleKeyStore::instance + 0xe0` with eight bytes from `read_random`, obtains
the current process's `proc_uniqueid`, adds the two values, and stores the
result at user-client offset `0xe0`. Selector `0x76` passes that user-client
field into `AppleKeyStore::identity_create`; the value becomes the v5 session
serialized for SEP.

This is a boot-scoped collision-resistant namespace, not an account or
authorization identity. The Linux-native equivalent for the eventual broker
is a fresh nonzero random 64-bit value for each transport generation, held in
root-owned memory and reused only by the operations that must reconcile within
that generation. It must not be derived from a Linux UID, PID, login session,
account UUID, or the macOS audit-session platform field, and it is not durable
keybag material. A reboot or poisoned transport creates a new value.

The matching operation-3 wrapper independently rejects a zero session, and
the host creator never intentionally constructs zero. This supports the
nonzero rule; it does not make the session cookie an authentication secret.

### Live transient-producer validation

After installing and rebooting into the generation-pinned endpoint-10
transport, the root-only fixed-purpose test completed context create, type-5
identity-secret set, context externalization, and mandatory deletion on the
J152f reference hardware. The cleanup state reconciled, identifiers and secret
bytes were not emitted, and neither a keybag nor a fingerprint was mutated.
This validates the producer boundary only; it is not evidence that endpoint-7
operation `0x01` is safe or accepted.

## Evidence status and remaining unknowns

**Recovered from RecoveryOS 26.6.2 build 25G83:** user-client arity and packing;
item ordering; kext method boundary; v5 field sizes/order; blob alignment;
reply shape; endpoint 7; raw operation `0x01`; visible flag transformations;
and the with-hash mapping of ACM reference, salt, and iteration count.

**Recovered from matching firmware:** the exact J152f bridgeOS `23P6068` SEP
payload contains an ARMv7 `AppleKeyStore_SEP` app at source version
`2155.160.13.0.1`. Its operation-1/version-5 decoder independently confirms
the host request layout and its distinct internal endpoint `0x12`.

**Recovered at the durable boundary:** the validated 16-byte account UUID is
copied to live identity offset `+0x18`. Durable registration passes live
offsets `+0x18`, `+0x28`, and `+0x08` to the class-10 record constructor,
which stores them at record offsets `+0x38`, `+0x48`, and `+0x5c`.
Primary-identity readback names these fields `uuid`, `guid`, and `kid`.
Consequently the caller's account UUID is returned as `uuid`; `guid` and
`kid` are distinct AppleKeyStore/SEP-owned identifiers.

**Recovered at the persistence boundary:** selector `0x76` returns a live
handle plus optional APFS KEK-binding material. The reloadable identity object
is exported afterward from that handle through endpoint-7 operation `0x02`
and is the object later consumed by operation `0x03`. The two byte strings are
not interchangeable.

**Unknown:** semantic names for the individual policy bits beyond their
recovered host construction; complete status meanings; and safe
reconciliation after interrupted identity creation while durable backing
storage is unavailable. The host path establishes a nonzero, boot-scoped
random session class rather than one durable numeric constant.
Matching-handler control flow proves that session-secret item 2 may be empty
for the exact internal-storage/effective-`-1`/no-item-3 candidate only. These
constraints do not authorize an identity mutation.

## Mutation gate

Do not add operation `0x01` or `0x02` to the kernel allowlist or issue a
request until a read-only compatibility/preflight argument, one-use
write-ahead intent, bounded create-and-export handling, atomic local
persistence, and post-timeout reconciliation are reviewed. The first hardware
create is a single ambiguous-outcome transaction, never a retryable probe.
