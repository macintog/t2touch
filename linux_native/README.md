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

## Current achieved boundary

The product-boundary correction and completed outcome are summarized in the
[integration contracts](../docs/research/integration-contracts.md). D220–D228's
macOS-state recovery is superseded. Native research proof below remains valid,
but archived working identities cannot seed the new installed demonstration.
Fresh creation, first enrollment, standard service use, automatic reactivation
after reboot, additional enrollment/deletion, and PAM must work through the
installed native path. The source integration now connects a blank-only
multi-boot first-run owner that composes the proven legacy create with schema-2
activation-bundle creation, the exact pre-E4 enrollment bootstrap, native
post-reboot activation dispatcher, ACM-capable deletion worker, and E4-native
PAM gate. Final focused offline validation and installed greenfield hardware
proof remain the current required work.

The complete research authority and biometric chain is observed on the
reference machine. D172 created and atomically published the Linux-owned
activation-bearing AKS identity and its retained 16-byte creation input. D178
completed the retained-secret `0x21`/original-input `0x18` activation; D179
independently observed readiness and enabled the schema-2 mapping. No macOS
keybag, Catacomb, OpenDirectory record, or APFS cryptographic-user record was
an input.

D196-D200 captured the first Linux-native fingerprint, persisted the first
user/master/BioLockout Catacomb generation, reproduced it on another boot, and
published E4 authority. D204 and D205 then proved exact native positive and
negative matching. D217 proved exact one-fingerprint deletion, paired
user/master recovery, and different-boot survivor verification.

D218 is the strongest current boundary: one uninterrupted same-boot process
verified D200, offered an explicit Add/Finish choice, proved the candidate
distinct, enrolled it to 100 percent, finalized the extended version-1 witness
through a fresh Bridge generation while retaining AKS/ACM authority, persisted
all components, reconciled two identities at E3, and immediately matched only
the addition. Its immutable 41-file artifact is
`D218-continuous-second-finger-ceremony-20260913`, manifest SHA-256
`52f960e06e35e462326c89109597c586b6bd5d3376fa91011d2a93660eb6dd25`.

The product boundary is now installed and proven through the narrow fprintd
facade, standard clients, sudo/PAM, and independent password fallback. The
remaining release boundary is packaging/CI and broader hardware/lifecycle
coverage; no additional reference-machine enrollment is required.

See [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) for the complete
layer model and
[`../docs/T1BRIDGE_REFERENCE.md`](../docs/T1BRIDGE_REFERENCE.md) and the
[research credits](../docs/research/artifacts-and-method.md#research-credits)
for the public-project comparison and activation/enrollment crosswalk.

## Evidence that led to the current boundary

- The target is the 2019 Intel MacBookPro16,1 T2 (`iBridge2,14`, `J152fAP`,
  board code `0x3A`) running bridgeOS 10.6 build `23P6068`. Host macOS recovery
  binaries are a separate source of static evidence and must not be described
  as the target firmware.
- At the initial wiped baseline, no keybag, Catacomb, or prior export existed.
  D137 created the first proof keybag, whose later primary absence was
  reconciled; D172 created the current activation-bearing keybag. D197 created
  and persisted the native Catacomb, D200 proved it across reboot, and D218
  advanced it to two identities.
- Initial SEP mailbox discovery and endpoint-7 OOL registration worked while
  capability negotiation timed out. D130 later established the exact EFI
  boot-state publication and negotiated AKS v2; D135/D136 then proved stable
  primary-identity absence.
- CDC-NCM, RemoteXPC discovery, and BridgeXPC 39 work after the guarded carrier
  recovery.
- The initial read-only BiometricKit inventory for numeric user IDs 0, 501,
  and 1000 returned the same stable empty-namespace shape rather than rejecting
  an unknown account. This enabled the current native baseline design but does
  not prove that first enrollment will accept it.
- The recovered Apple host path creates a top-level identity through
  AppleKeyStore user-client selector `0x76`. Its reply contains a new live bag
  handle and optional APFS KEK-binding material, not the reloadable identity.
  The host immediately exports that identity from the handle through
  endpoint-7 operation `0x02` and atomically saves the result. Static analysis
  of RecoveryOS 26.6.2
  recovered the user-client item vector, the internal create-keybag-v5 body,
  and endpoint-7 operation `0x01`; see
  [`SELECTOR_76.md`](SELECTOR_76.md). The exact J152f bridgeOS `23P6068` SEP
  app has the identical AppleKeyStore source version, and its
  operation-1/version-5 decoder independently confirms the same field layout.
  Optional-field semantics and cross-version behavior remain unproven; the
  exact minimal J152f construction used by D137 succeeded.
- Matching bridgeOS and SEP artifacts established the xART OS-identity
  operation, its volume-group/partition UUID selection, and the separate
  gigalocker backing-file lifecycle. D111-D124 later proved the host PCI
  opcode-8 route was the wrong service and retired it as a native prerequisite;
  see
  [`XART_IDENTITY.md`](XART_IDENTITY.md).
- The clean-wipe disk prerequisite and the generic `apfsprogs` volume-role
  contribution are recorded in
  [`APFS_XART_VOLUME.md`](APFS_XART_VOLUME.md).
- The first built-in user/master/bio-lockout archive boundary is now encoded
  without an imported Catacomb prototype; exact inputs and transaction order
  are recorded in [`CATACOMB_BOOTSTRAP.md`](CATACOMB_BOOTSTRAP.md).

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
6. Publish fprintd/PAM readiness only after a different-boot load, unlock,
   identity inventory, and positive/negative match controls all agree.

## Recovered protocol foundation

The current Intel AppleKeyStore implementation establishes:

- user-client item packing, sizes, and alignment;
- the existing v2 AKS envelope and raw endpoint-7 operation `0x01`;
- the create-keybag-v5 body field order and width;
- the versioned live-handle/optional-KEK response boundary;
- the separate operation-`0x02` saved-keybag export and versioned framing; and
- a hardware-free strict codec with no transport entry point.

Later matched-firmware recovery and the D135-D138 hardware results closed the
creation semantics needed for the reference path: the exact ACM type-5
credential producer, stable-absence observation, single-owner create/export,
cleanup, saved-object persistence, and different-boot reload are all proven.
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

## Completion gates

- [x] Strict codecs, owner state machines, and journals reject malformed,
      interrupted, late, duplicate, or unbound operations.
- [x] Stable read-only inventory selected the no-delete replacement branch.
- [x] One mutation created/exported an identity after durable staging of its
      activation input, with atomic bundle persistence and no ambiguous retry.
- [x] Same-boot live UUID, disabled mapping, stale-mapping archive, and a later
      boot's stable unloaded-primary/zero-handle state all reconcile.
- [x] D174 closed the replacement journal without loading, creating, deleting,
      exporting, activating, or enrolling.
- [x] D175 proved the activation preflight reaches the live current ABI; its
      stale flag mask failed closed before a journal or AKS operation, and the
      exact correction is installed for a fresh boot.
- [x] D176 created the journaled activation baseline but stopped before keybag
      load because the legacy-only path allowlist rejected the exact D172
      bundle; different-boot recovery and the narrow correction are preserved.
- [x] A further boot activates the exact bundle through successful `0x21`,
      fixed `0x18`, independent readiness, and enables only that mapping.
- [x] One native enrollment reaches E3 and persists a complete first Catacomb
      generation without an imported Apple artifact.
- [x] A different boot reproduces that generation and publishes E4 authority.
- [x] Native positive and negative match controls pass directly against E4.
- [x] Exact deletion and different-boot survivor verification pass.
- [x] One continuous same-boot second-finger ceremony reaches
      `addition-verified` and immediately matches only the new identity.
- [ ] Native positive and negative controls pass through the final fprintd
      consumer using only E4-derived state.
- [ ] PAM preserves a successful password path when Touch ID rejects, times
      out, is unavailable, or has not yet been activated.
- [ ] The full path is packaged as a supported clean-machine workflow.
