# Identity and authorization

Native adoption creates an AKS identity, exports its reloadable keybag, and retains
the exact input used to derive its activation verifier. The keybag and that input
are separate persistent objects. Fingerprint state is a third, separate layer.

## Creation layers and encoding

AppleKeyStore user-client selector `0x76` is a host API selector. The recovered
implementations encode a versioned creation record inside host endpoint-7
operation `0x01`: version 5 on the J152f reference firmware and version 4 on
MacBookPro16,2 / J214K with bridgeOS `23P2048`. Neither number is the internal
`sks` endpoint `0x12`.

The record below was recovered independently from the Intel host implementation
and the matching J152f SEP decoder. All integers are little-endian. `blob` means
a `u32` byte length, that many bytes, and zero padding to a four-byte boundary.
These are operation bodies, after the AKS envelope.

```text
create request (operation 0x01):
    u32 version = 5
    u64 session
    u32 internal_flags
    i32 effective_bag_handle
    blob item1
    blob item2
    blob account_uuid
    blob item3
    u64 original_flags
    u64 scalar2
    blob optional

create response:
    u32 version = 5
    i32 live_handle
    blob optional_kek_material

create-v4 request (operation 0x01):
    u32 version = 4
    u64 session
    u32 internal_flags
    i32 effective_bag_handle
    blob item1
    blob item2
    blob account_uuid
    blob item3
    u64 original_flags

create-v4 response:
    u32 version = 4
    i32 live_handle
    blob optional_kek_material

export request (operation 0x02):
    u32 version = 1
    u64 session
    i32 live_handle
    blob optional_compatibility_input

export response:
    u32 version = 1
    blob saved_keybag
```

The account UUID is a nonzero 16-byte UUID. The minimal v5 construction used on
J152f has an 88-byte create body; the observed v4 construction on J214K has a
76-byte create body because it omits v5's second scalar and optional blob. Both
use the same 20-byte minimal export body. Changing only the version word is not
a valid conversion between these layouts. The creation response has no leading
status word: mailbox status determines whether the response succeeded. Optional
flags and fields have additional branches in the recovered decoders; the
successful minimal constructions do not establish all of their semantics.

The returned KEK material serves the Apple host's APFS key-binding path. Hardware
returned 162 bytes in the first successful creation experiment, correcting an
early static inference that this output was always empty. It is not the saved
keybag. Operation `0x02`, using the returned live handle in the same session,
produces the object that operation `0x03` can load after reboot.

## The retained creation input

With original creation flags `6`, the matched SEP handler derives the identity
verifier from the raw 16-byte ACM external reference. Later verification with
option `0x100` reconstructs an ACM input context and extracts its credential data.
Supplying the account password at this later step therefore hashes different
bytes, even if that password originally helped construct the creation context.
The password-based experiments returned status `-5`.

The successful transaction saves the original 16-byte external reference before
creation and keeps it with the exported keybag. This value is a bearer secret.
The optional KEK output cannot replace it, and inventory cannot recover it.

On a later boot, activation proceeds as follows:

1. Load the saved keybag with AKS `0x03` and verify its UUID with `0x06`.
2. Bind the selected user's negative alias with `0x0d`.
3. Create a fresh ACM input context, set the saved 16-byte value as type-5 data,
   and externalize that context.
4. Create a distinct enrollment-policy target context.
5. Use AKS `0x21` with option `0x100` to verify the input against the positive
   loaded handle and authorize the target context.
6. Send the `0x18` transition with the fresh input context's external reference
   from step 3 while the authorized target remains live.
7. Destroy the target and input contexts in reverse order, and independently
   read back the resulting state.

The input credential and the authorization target have different jobs. Replacing
the input with the target's external reference loses the value verified by AKS.
The target's lifetime also extends beyond the verifier response.

## Inside the matched SEP derivation path

The recovered `sks` creation helper stores a 16-byte salt at keybag offset
`+0xcc`, a platform-selected work factor at `+0xe0`, and links the resulting
32-byte verifier into credential records at `+0x2a0`. Verification reuses the
restored salt and work factor. These are in-memory offsets in the matched
application, not offsets in the exported keybag file.

| Path in `sks` | Recovered role |
| --- | --- |
| `0x102904` → `0x1027c0` | Normalize creation input; flags 6 take the raw-copy branch. |
| `0x0e39e0` → `0x0de814` | Build credential state and generate the salt. |
| `0x0d70c8` | Select the work factor. |
| `0x0db30c` | Common derivation core producing 32 bytes. |
| `0x0eaf9c` → `0x0da028` / `0x0db2cc` | Derive the verification candidate from extracted input and restored parameters. |
| `0x0eb4e2`–`0x0eb4f2` | Final comparison responsible for the observed `-5` mismatch. |

The raw creation input is not copied into the keybag by this path. Export
preserves the derived state, so it cannot recover a discarded input reference.
Changing the secret also verifies the old credential before constructing its
replacement in the analyzed populated-keybag path.

The source of the reference is SCRD's fresh-context helper `0x0bc408`, which
requests 16 bytes through `0x0ccee8`. The shared RNG resolves the `TRNG` driver.
SCRD compares each candidate with reserved values and existing live handles,
regenerating on a collision. This recovered path explains why the retained
reference can serve as an opaque activation secret rather than a predictable
counter. The addresses refer to the [matched SEP artifacts](artifacts-and-method.md).

## Inventory and ownership

AKS operation `0x51`, suboperation 0, reads the primary identity. Its 40-byte
request body is:

```text
u32 0
u64 session
u64 suboperation = 0
i32 selector = -1
u32 empty_blob_length = 0
i32 secondary_selector = -1
u32 empty_blob_length = 0
u32 output_placeholder = 0
```

The returned DER has a SET (`0x31`) of SEQUENCE (`0x30`) entries. Each entry pairs
a UTF8String key (`0x0c`) with an OCTET STRING (`0x04`). The `uuid`, `guid`, and
`kid` values are each 16 bytes. The creation account UUID maps to `uuid`; the SEP
generates the other identifiers. AKS status `-3` explicitly reports absence for
this query. A timeout is not an absent identity.

Suboperations 1 and 2 mutate state. UUID-based `0x03` open is also a loader,
rather than an inventory operation: it creates live handle state. A successful
primary read can reconcile a creation intent with the durable identity, but
cannot reconstruct a lost exported keybag.

An adapter needs a durable association between its Linux account, account UUID,
keybag UUID, saved keybag, and retained secret. Recording creation intent before
sending the request makes an interrupted transaction distinguishable from a
fresh account. Committing the keybag and secret together prevents a saved
identity from becoming unusable merely because one file write completed first.

## Relationship to T1

[T1Bridge](https://github.com/standardagents/t1bridge/tree/7003b8d9f791) helped
establish the retained-secret and enrollment-lifetime model. Its separate random
32-byte user secret is different from the 16-byte creation input observed here.
The useful commonality is the lifetime and persistence of authority; an adapter
still needs the credential representation and protocol selected by its device.
