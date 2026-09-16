# Linux-native T2 Touch ID provisioning

## Objective

Support a clean-wipe Intel T2 Mac from Linux alone. The finished path must
create and persist a Linux-owned SEP keybag identity, bind it to one Linux
account, enroll and verify fingerprints, survive reboot, and expose the result
through fprintd/PAM with password recovery. A macOS installation, exported
keybag, OpenDirectory record, or APFS cryptographic-user record cannot be a
runtime or installation prerequisite.

This is a separate provisioning problem from the existing-user compatibility
path. Recovered macOS behavior is protocol evidence, not a required service to
recreate wholesale.

MacBookPro16,1 is the sole validation platform, not an implementation
allowlist. Protocol behavior must be selected by transport capabilities and
explicit wire versions; board identifiers are evidence labels unless a real
quirk is demonstrated. The extension model for other T2 boards and a possible
T1 backend is recorded in [`../docs/COMPATIBILITY.md`](../docs/COMPATIBILITY.md).

## Installed integration

The installed native path owns account creation, activation, enrollment,
reconciliation, and authentication. Archived research identities must not be
used to seed an installation. See the [product architecture](../docs/ARCHITECTURE.md)
and [integration contracts](../docs/research/integration-contracts.md) for
service ownership, persistent state, and recovery boundaries.

The MacBookPro16,1 reference system has exercised native creation, enrollment,
matching, deletion, restart persistence, fprintd, and password fallback.
Those results do not qualify other hardware or firmware combinations. See
[compatibility](../docs/COMPATIBILITY.md) and the
[T1Bridge comparison](../docs/T1BRIDGE_REFERENCE.md) before adapting the design.

## Protocol references

- [Identity creation](SELECTOR_76.md) separates the host user-client selector
  from the endpoint-7 operation and documents the versioned request layout.
- [Identity persistence](IDENTITY_PERSISTENCE.md) covers exporting a created
  handle and retaining the activation material for later reload.
- [xART identity](XART_IDENTITY.md) describes firmware-owned storage identity
  and the distinction between host PCI and embedded storage paths.
- [APFS and xART storage](APFS_XART_VOLUME.md) describes disk prerequisites.
- [Catacomb bootstrap](CATACOMB_BOOTSTRAP.md) defines the first user/master
  archive inputs and transaction order without an imported prototype.

## Linux-owned authority model

For a Linux-only machine, macOS OpenDirectory and APFS side effects are out of
scope. Their security roles must be replaced explicitly:

1. Bind one numeric Linux UID and account-generation assertion to a random,
   root-owned account UUID.
2. Create one SEP keybag identity, export its saved object from the returned
   live handle in the same transport generation, atomically persist that
   object, and verify its bag UUID after every load. Discard the separate
   create-time APFS KEK output in the Linux-native path.
3. Bind the loaded bag to a single negative alias derived from the selected
   numeric UID; never accept an alias from an untrusted caller.
4. Treat BiometricKit user/Catacomb state as a separate journaled namespace.
   First enrollment creates the user component only after SEP reports a new
   identity; no empty user archive is invented in advance. Build that first
   component from exact SEP results and the reconciled account/keybag tuple,
   not an imported macOS archive.
5. Use the existing UID-bound ACM enrollment authorization and Catacomb
   persistence machinery only after the keybag/account tuple reconciles.
6. Publish readiness only after the required fresh-owner activation and
   inventory proofs agree. Qualify positive/negative matches and restart
   persistence separately; a different boot is not required for every installed
   enrollment.

## Recovered protocol foundation

The current Intel AppleKeyStore implementation establishes:

- user-client item packing, sizes, and alignment;
- the existing v2 AKS envelope and raw endpoint-7 operation `0x01`;
- the create-keybag-v5 body field order and width;
- the versioned live-handle/optional-KEK response boundary;
- the separate operation-`0x02` saved-keybag export and versioned framing; and
- a hardware-free strict codec with no transport entry point.

The reference path requires the exact ACM type-5 credential producer,
stable-absence observation, single-owner create/export, cleanup, saved-object
persistence, and reload verification.
Operations `0x01` and `0x02` remain behind the default-disabled kernel
provisioning gate and exact request validators. Selector `0x76` is not a SEP
opcode, and there is no generic raw command escape hatch. See
[`IDENTITY_PERSISTENCE.md`](IDENTITY_PERSISTENCE.md).

Unknown optional flags and cross-version variants remain portability questions,
not blockers for the exact J152f transaction that succeeded.

## Artifact workflow

Matching Apple binaries may be obtained from Apple-hosted recovery/install
assets and inspected locally for interoperability. They belong under
`linux_native/artifacts/`, are ignored by Git, and must never be committed or
redistributed. Record only public symbols, structure layouts, operation
semantics, hashes, and redacted observations.

The completed first extraction targeted the Intel AppleKeyStore client/kext
path implementing selector `0x76`; the second recovered
`applekeystored` packing and durable-material serialization. Future artifact
work should still prefer the smallest signed recovery asset containing the
required components.

Always record the host OS build, AppleKeyStore source version, Mach-O UUIDs,
and T2 bridgeOS build separately. Cross-version agreement is corroboration,
not a substitute for matching-firmware evidence.
