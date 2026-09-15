# 23P2048 identity-create version 4 layout

Offline analysis, 2026-09-15. Primary evidence is Apple's decrypted J214K
23P2048 `sks` module, UUID `9d8aad8b-0dbc-1c37-95f9-cd0316e38d5a`.
Addresses below use the reconstructed sks Mach-O virtual address space.
TEXT and initialized DATA bytes were checked against the decrypted payload;
only detached LINKEDIT metadata was removed from the analysis copy. No
instruction bytes were changed. Firmware binaries are not included here.
No request was sent to hardware for this analysis.

## Exact operation-body shape

```text
request:
    u32 version = 4
    u64 session
    u32 internal_flags
    i32 effective_bag_handle
    blob item1
    blob item2
    blob account_uuid
    blob item3
    u64 original_flags

response:
    u32 version = 4
    i32 live_handle
    blob kek_material
```

Names are matched to the existing version-5 codec in
[`src/t2_aks_identity_create.py`](../../src/t2_aks_identity_create.py), rather
than recovered firmware symbols. Scalar widths and field order are directly
recovered. A blob is little-endian u32 length followed by bytes and padding to
four-byte alignment. Version 4 has neither the version-5 `scalar2` nor its final
`optional_data` blob. Its response has the same field shape as version 5, but
the version word is 4. The response body does not include the mailbox status.

## Decoder evidence

Operation 1 selects descriptor `0x109b7c`; its codec is `0xb56b8`.
The common version word is decoded into record offset `0x50` at `0xb578a`.
The halfword branch table at `0xb57ac` selects `0xb582c` for version 4
(`0xb57ac + 2 * 0x40`). Within that path, different codec directions select
request or response members.

| Request member | Record offset | Helper call site | Helper |
| --- | --- | --- | --- |
| session | `0x54` | `0xb5848` | `0xfdb76`, 8-byte scalar |
| internal_flags | `0x5c` | `0xb5868` | `0xfd970`, 4-byte scalar |
| effective_bag_handle | `0x60` | `0xb5888` | `0xfd970` |
| item1 pointer/length | `0x64/0x68` | `0xb58b2` | `0xfd9be`, blob |
| item2 pointer/length | `0x6c/0x70` | `0xb58dc` | `0xfd9be` |
| account_uuid pointer/length | `0x74/0x78` | `0xb5906` | `0xfd9be` |
| item3 pointer/length | `0x7c/0x80` | `0xb5926` | `0xfdbc8`, blob wrapper |
| original_flags | `0x84` | `0xb5946` | `0xfdb76` |

`0xfdbc8` calls `0xfd9be` at `0xfdc04` with the adjacent pointer and length;
it is not an additional scalar. `0xfd9be` reads the u32 blob length at
`0xfda28`, rounds up through `0xfda2e` and `0xfda42`, and advances by padded
length plus four at `0xfda4c..0xfda56`. The encode direction zeros padding at
`0xfda94..0xfdac0`. `0xfdb76` explicitly bounds-checks eight bytes and copies
two words at `0xfdba2..0xfdba8`.

Response selection branches from `0xb582e` to `0xb5a9a`: the handle at record
`0x8c` is serialized by `0xfd970` at `0xb5ab0`, followed by the pointer/length
pair at `0x90/0x94` through `0xfdbc8` at `0xb5af2`. The common version codec
precedes both request and response selection.

## Execution and ownership

The version table at `0xb5c06` selects `0xb5c18` for version 4. It validates
the session through `0xfe228`, then calls `0xda4a0` at `0xb5cd0` with:

```text
r0/r1: session
r2: internal_flags
r3: effective_bag_handle
stack +00/+04: item1 pointer/length
stack +08/+0c: item2 pointer/length
stack +10/+14: account_uuid pointer/length
stack +18/+1c: item3 pointer/length
stack +20/+24: original_flags low/high words
stack +28: address of live_handle output
stack +2c: address of KEK pointer/length output
```

Thus the u64 following the fourth blob is the same argument position used by
the creation flags in the reference model; it is not a substitute for both
version-5 trailing scalars. Internal flag semantics still require separate
comparison of `0xda4a0` and the reference implementation before hardware use.

Cleanup callback `0xb5e5c` selects `0xb5e7a` for version 4. It releases the
first three allocated blob pointers, the fourth blob if present, and the KEK
output if present (`0xb5e7a..0xb5e98`, then `0xb5ec4..0xb5ed0`). It then
tail-calls shared record cleanup at `0xfe278`. This callback is cleanup, not
the response encoder; the codec above handles both directions.

## Limits

This establishes a concrete version-4 codec contract and the immediate call
ABI. It does not prove enrollment, persistence, authorization, or a safe retry
of a previously journaled uncertain creation. Those require firmware semantic
comparison and an evidence-backed recovery path. Version selection must not
be implemented as blind fallback after any creation error.

## Minimal input semantic trace

For the existing minimal construction (`internal_flags=0x4100`, handle `-1`,
item1 = 16-byte ACM external reference, empty item2/item3, nonzero UUID16,
`original_flags=6`), the immediate execution paths agree with the model in
[Identity and authorization](identity-and-authorization.md):

- `0xda4fa` extracts bit `0x100` from original flags for both normalization
  calls. Flags 6 make this zero. `0xb4c84` forwards that bit to `0xb4b3c`;
  the zero branch at `0xb4b90..0xb4b94` selects `0xb4c1c`, which allocates
  and copies the input bytes unchanged. It avoids the ACM credential-extraction
  calls at `0xb4b96..0xb4bc4`. The reference's retained raw external-reference
  secret is therefore also the creation KDF input here. Empty item2 normalizes
  to pointer/length zero through `0xb4bd0`.
- The predicate `0xb48d2` compares only the low nibble of internal flags with
  its second argument. `0x4100` is type 0, not type 2. Consequently the call at
  `0xda570` branches to `0xda666`, then allocates a new bag at `0xda688`
  through `0xcebc4`; it does not enter the type-2 existing-bag cloning path at
  `0xda578..0xda664`. Handle `-1` satisfies the check at `0xda54c`.
- Input bits 21 and 22 are clear, avoiding the respective special rejection
  at `0xda544` and alternate path at `0xda55c`. Type 0 is accepted by the
  allocator at `0xcebd4..0xcebd8`. Stored bag flags begin with the low nibble
  (`0xcecec..0xcecf2`) plus selected platform bits; the request's `0x100` and
  `0x4000` do not become bag-type bits.
- The raw item1 pointer and length reach the 32-byte derivation wrapper
  `0xd1a7a` at `0xda6ca`. A separate boolean at `0xda52e..0xda542` marks
  input missing/empty **or having a first byte of zero**. This can affect later
  branches, so nonempty length alone does not prove that boolean false.
- With type 0, a supplied account UUID must be exactly 16 bytes and pass the
  zero-UUID check at `0xda8e8..0xda8fe`; it is copied into bag offset `0x18`
  at `0xda90a`. The function at `0xed7dc`, called by `0xda91c`, returns 1
  unconditionally in this image. Empty item3 selects `0xda9a2` and the initial
  identity helper `0xed7e4`, rather than the item3-dependent path through
  `0xd36d8` / `0xedb78`. `0xed7e4` generates fresh material before invoking
  `0xed87c`.
- A live handle is attached through `0xd7f54` at `0xda9e2` and written to the
  caller's output at `0xdaa60..0xdaa66`. Error cleanup can unload that live
  handle at `0xdaa7a..0xdaa82`; this is not proof of rollback of all durable
  identity state.

This is a source-to-call-site comparison with the documented newer reference,
not a byte-for-byte comparison against its unavailable binary. Remaining
uncertainties include platform-dependent KDF/persistence behavior below these
helpers, first-byte-zero handling, returned KEK material, and later export,
activation, enrollment and restart persistence on the actual device.

## Export version 1 compatibility

Operation 2 descriptor at `0x109ba8` contains operation/version words `2,1`
and callbacks `0x040b5ef1`, `0x040b612b`, `0x240b620b`. Its codec at
`0xb5ef0` explicitly selects version 1 at `0xb5fce..0xb5fd0`, and execution
at `0xb612a` accepts versions 0 and 1 (`0xb6146..0xb615c`).

The version-1 body matches the existing export codec exactly:

```text
request: u32 version=1; u64 session; i32 live_handle; blob compatibility_input
response: u32 version=1; blob saved_keybag
```

The request session is at record `0x54` (u64 helper call `0xb6030`), handle
at `0x5c` (u32 call `0xb604a`), and compatibility blob at `0x60/0x64`
(`0xb6062` to `0xb6088`). The response blob is at `0x68/0x6c`, selected
by `0xb6110..0xb611c` into the same blob helper. Execution checks session
via `0xfe228` and calls `0xdabe6` at `0xb61ac`, passing the requested live
handle, compatibility pointer/length and output pointer/length.

`0xdabe6` first looks up the live bag with `0xd834c`; absence returns `-3`
at `0xdac12`. It invokes serializer `0xd0580`, which calls `0xd032c` and
returns allocated serialized bytes through the response pointers
(`0xd05dc..0xd05ec`, with an alternate wrapping path at `0xd05f2`). This
confirms operation and codec availability, not a successful export on hardware.

The retained creation secret is an **input**, not either the create KEK output
or the export output. Raw normalization with flags 6 is confirmed above. The
later operation `0x21` exists with versions 0/1 (descriptor `0x10a0fc`,
execution `0xbd2bc`), and the version-1 path calls `0xe1f12` at `0xbd344`.
That helper preserves option `0x100` in its `0x383` mask at
`0xe1f70..0xe1f78` before its verifier call. Full verification-side credential
extraction, KDF matching, enrollment-target authorization and transition
semantics remain outside this bounded check; a codec match must not be
reported as proven activation compatibility.

## Version-5 rejection precedes creation

The actual codec rejects version 5 before decoding any version-specific
creation input, not merely when the execution wrapper checks its version:

1. `0xb579e` loads the decoded version from record `0x50`.
2. `0xb57a2` compares it with 4; `0xb57a4` branches unsigned-greater to
   `0xb5ba6`.
3. `0xb5ba8` sets `r5=0xffffffff`; `0xb5bb4` clears the wire buffer, and
   `0xb5bcc` returns `r0=r5`, i.e. codec failure sentinel **-1**.

The generic mailbox dispatcher selects operation 1's descriptor at `0xfbc02`,
loads its codec pointer from descriptor `+0x0c` at `0xfbc50`, and invokes it
at `0xfbc62` with decode direction `r0=0` and response-direction selector
`r1=1`. `0xfbc64` adds one to the codec return; `0xfbc66` branches to
`0xfbcdc` when the result is zero. Thus codec **-1** skips the execution
callback at `0xfbc70` entirely. Codec success returns a byte count, so this
is specifically a sentinel check, not a generic nonzero-status check.

The dispatcher initializes its response status byte to `0xf3` at
`0xfbbea..0xfbbec`, which is signed **-13**, before decoding. A codec
failure retains that status. Therefore the observed mailbox -13 can be
explained directly by codec rejection, without ever invoking the creation
wrapper or `0xda4a0`.

The other descriptor-based dispatch path makes the same check at
`0x105a62..0x105a66`, skipping execution `0x105a72` on codec -1. Its initial
result is -1 (`0x1059a0..0x1059a4`), so the response-status detail above is
specific to the mailbox path.

Cleanup still runs at `0xfbce2` (or `0x105a82`). For operation 1 and version
5, cleanup `0xb5e68..0xb5e6a` skips all per-version blob frees directly to
shared record cleanup `0xb5ed4`. The creation execution wrapper also has its
independent version >4 rejection at `0xb5bfa..0xb5c46`, but that is not
reached after the normal decoder rejection.

**Recovery implication:** for this exact firmware and a confirmed operation-1
version-5 wire request, the failed request does not call identity creation.
This is stronger than interpreting status -13 alone: other operations and
other failures may reuse -13. It does not claim that no transport bookkeeping,
cleanup, or unrelated pending work occurred, nor that preceding provisioning
operations were read-only. Reconciliation must still establish firmware
identity, request version, journal ownership and fresh authority inventory.
