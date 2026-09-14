# AppleKeyStore identity reconciliation boundary

**Status:** the corrected loader/inventory distinction remains authoritative;
the native identity and biometric lifecycle is complete through D218 on the
reference machine — 2026-09-13

This records a corrected negative result: endpoint-7 operation `0x03` is a
keybag loader and cannot answer whether an identity UUID is absent. It must not
be exposed as an absent-identity probe.

## Matching host path

In the matching x86_64 AppleKeyStore kext,
`AppleKeyStore::identity_open` at `0xffffff8001acd168` calls
`__ipc_load_keybag` with operation `0x03`, a session, and a 16-byte identity
form. A successful call returns a live keybag handle. The symbol takes an
untyped byte pointer; it has no query or found/not-found result.

`AppleKeyStore::identity_load` at `0xffffff8001acd8f4` supplies the 16 bytes
from an `OSData`, calls `identity_open`, then calls
`__ipc_make_system_keybag_v1`, and finally unloads the live handle. Its UUID
logging establishes the identity interpretation, while its control flow
establishes that this is a load sequence rather than an inventory query.

The version-0 request and reply are:

```text
u32 result_placeholder = 0
u64 session
u32 identity_form_length = 16
u8  identity_form[16]

i32 status
i32 live_handle
```

Operation `0x05` unloads a known live handle. Neither operation returns a
durable-existence bit.

## Matching J152f SEP evidence

The matching `AppleKeyStore_SEP 2155.160.13.0.1` operation-3 implementation
at Thumb address `0x0e3c74` first passes the supplied bytes to `0x0d9c8c`.
That routine decodes an object, including its raw 16-byte form through
`0x0d8bc0`; it does not search a UUID registry. Decoder and validation errors
are propagated directly.

On successful decode, `0x0e0b48` assigns or validates a live handle, writes
the caller's 64-bit session into the object's session fields at offsets
`0x284` and `0x288`, writes the handle at offset `0x27c`, and links the object
into the live global list. Failures in this phase collapse to generic `-1` in
the operation-3 wrapper. That `-1` is not an absent-UUID status.

This proves there is no status value to recover for the proposed fresh-UUID
test: the test asks the loader to instantiate a transient object. Success
would mean “loaded,” not “previously existed”; failure would be a decode,
validation, collision, resource, or session error rather than proof of
absence.

## Linux correction

The experimental `T2_AKS_IOC_IDENTITY_PROBE`, its random-UUID CLI command, and
their dedicated codecs have been removed before upstreaming. Generic
operation `0x05` remains denied. Operation `0x03` is still named and treated
as `load_keybag`; callers must supply intentional persisted keybag material
and own its lifecycle rather than pass random bytes.

Two earlier random-form attempts received no operation-3 reply and timed out
before a live handle was returned. The kernel poisoned endpoint 7 and did not
send operation 5. Those observations establish only endpoint/application
unavailability in those generations. They are not absence evidence and must
not be repeated.

## Recovered primary-identity readback

The matching host kext supplies the missing read-only primitive.
`AppleKeyStore::identity_get_primary` at `0xffffff8001a7dc58` calls
`__ipc_identity_operation` at `0xffffff8001adc46a`; that IPC wrapper sends
endpoint-7 operation `0x51`. The selected identity suboperation is the 64-bit
zero at body offset `+12`. The same command also carries mutating suboperations
1 and 2, so exposing command `0x51` generically would be unsafe.

The matching J152f descriptor for operation `0x51` is at `0x11485c`. Its
decoder, execution wrapper, and cleanup callbacks resolve to `0x0cdc98`,
`0x0cdecc`, and `0x0cdf74`. The wrapper calls `0x104288`; only its operation-0
branch at `0x1043b2` is relevant here.

That branch calls `0x0f47c4`, which in turn calls the lazy identity-list loader
at `0x0f42bc`. The loader reads durable record class `10` through `0x0ba1a4`.
It treats storage status `-3` as a valid empty list, while other load or decode
failures remain unavailable/ambiguous. Persisted entries are reconstructed as
`0x6c`-byte records. `0x0f47c4` selects the record whose state is `1` and whose
primary flag `0x10` is set; no record returns `-3`.

For a primary record, operation 0 returns a DER dictionary containing exactly
three 16-byte values under the keys `uuid`, `guid`, and `kid`. The key objects
are statically visible through `0x113430`, `0x113348`, and `0x113438`.
Consequently this is durable inventory, not merely a scan of objects created
in the current host session: the in-memory list is populated on demand from
the persistent record before selection.

The create-to-inventory UUID relationship is also recovered end to end. In
the version-5 create handler at `0x0e3220`, the validated 16-byte
`account_uuid` is copied into the new live identity object at offset `+0x18`.
The durable-identity registration caller at `0x0ba83e` (with matching paths at
`0x0bca62` and `0x0e9c48`) passes live-object offsets `+0x18`, `+0x28`, and
`+0x08` as three distinct UUID inputs. `0x0f4f84` forwards those inputs to
`0x0f4b14`, whose new-record path copies them to class-10 record offsets
`+0x38`, `+0x48`, and `+0x5c`, respectively. Operation 0 emits those record
fields as `uuid`, `guid`, and `kid`. Therefore the mapping is:

```text
create account_uuid -> live +0x18 -> record +0x38 -> "uuid"
                      live +0x28 -> record +0x48 -> "guid"
                      live +0x08 -> record +0x5c -> "kid"
```

Only the first chain originates in the caller-supplied account UUID. The
other two fields must remain SEP/AppleKeyStore-owned values and must not be
synthesized from the Linux account UUID.

Linux now admits only this exact 40-byte request:

```text
u32 result_placeholder = 0
u64 nonzero_generation_session
u64 identity_suboperation = 0
i32 handle_selector = -1
u32 empty_input_length = 0
i32 secondary_selector = -1
u32 empty_input_2_length = 0
u32 empty_output_placeholder_length = 0
```

The validator denies every other operation-`0x51` shape. An additional
`inventory_only=1` transport mode denies every endpoint-7 ioctl except this
request and requires xART publication, ACM registration, and capability
probing to be disabled. It exists to obtain one read-only observation on an
unprovisioned clean-wipe machine without exposing the broader research ABI.

## Create-reconciliation boundary

Operation `0x51` operation 0 supplies the durable absent/primary/unavailable
oracle that operation 3 could not. The create account UUID is now mapped to
returned `uuid`. It does not return the host-saved keybag object. Matching host
and SEP paths prove that object is exported separately from the new live
handle through endpoint-7 operation `0x02`; see
[`IDENTITY_PERSISTENCE.md`](IDENTITY_PERSISTENCE.md). Before operation-1
creation can be enabled, the write-ahead transaction must still distinguish:

1. no durable object was committed;
2. create returned a handle but operation-2 export was not durably saved;
3. the intended UUID and its exported saved keybag were both committed;
4. a partial or inconsistent xART/keybag state exists; or
5. the observation itself is unavailable or ambiguous.

Primary inventory can reconcile the caller-supplied UUID after an ambiguous
create. It cannot reconstruct a lost operation-2 response. Since the matching
serializer changes live save-state while exporting, neither create nor export
may be retried after a timeout. The journal must cover operation `0x01`, the
same-generation operation `0x02`, and atomic root-only file commit as one
transaction.

The isolated request was live-tested once on boot
`bd15fe0d-7ba4-4f77-b099-4f4d763c2c62`. Endpoint 7 registered with
`inventory_only=Y`, `register_acm=N`, capability probing disabled, and no xART
OS UUID. Operation `0x51` timed out waiting for its reply after zero unrelated
messages; no DER output was produced. It was not retried, and the module was
not unloaded.

Static recovery locates the blocking boundary more narrowly. Class-10 loader
`0x0f42bc` reaches `0x0ba1a4`/`0x0ba054`; the latter issues command `0x271b`
through the prebound shared-runtime stub at `0x112e00`. Its target in
`libShared_t8012` at runtime address `0x04040b7c` handles commands
`0x271a..0x2721`, packages the per-application backing-store request, and
waits synchronously for its result. Both size and data fetch paths use this
transaction. Thus the live timeout is below the class-10 identity-list logic
in a synchronous backing-store transaction, not evidence that the operation
`0x51` request layout is wrong.

Receiver attribution is now exact. Matching `sks` startup resolves fourcc
`xART` (`0x78415254`) at `0x001048ee..0x001048f4` and stores the returned
service handle in global `0x04117668`. The non-lazy pointer at `0x0011346c`
points to that global. The `0x271b` caller loads that pointer at
`0x001003f0..0x001003fa`; shared runtime preserves it at `0x00040b96`, then
dereferences it at `0x00040d60` as the destination handle immediately before
the synchronous IPC call at `0x00040d6a`.

The live result is therefore an unavailable xART durable read, not durable
absence: the loader never returned its explicit `-3` empty-record status.
Until the bridgeOS-owned gigalocker backing is provisioned or attached and the
readback oracle completes, endpoint-7 operations `0x01` and `0x02` remain
disabled and no identity creation is authorized.

The same exact read was repeated once only after macOS had provisioned working
embedded xART state and Linux had proved a complete authenticated match with
the imported Apple identity. It still timed out after zero unrelated endpoint
messages while xART publication remained deferred and untouched. Kernel
read-back retained stable-absence count zero; no DER object or absence status
was returned. This proves the successful match is an already-loaded-keybag
control, not evidence that the class-10 durable inventory path is available
without a working xART namespace transaction.
