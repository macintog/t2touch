# T2 SEP and Touch ID research

These notes describe how Linux created its own T2 account identity, enrolled
fingerprints, and restored them after reboot. They cover the Secure Enclave
services, wire formats, and persistent state behind that result.

## Parallel publication

This research bundle is published in both t2touch and t2touch-mini. A fact that
belongs in mini's protocol-reference scope must be applied to the same relative
file in both repositories; product-only material belongs outside this directory.
The two `docs/research` trees remain byte-identical, including their file lists.
From either checkout, verify the paired working trees with:

```bash
python3 scripts/check-doc-parallelism.py --other ../t2touch-mini
```

Use `--other ../t2touch` when running from t2touch-mini.

| Read | For |
| --- | --- |
| [SEP architecture](sep-architecture.md) | Host transports, internal services, mailbox framing, and request ownership. |
| [Identity and authorization](identity-and-authorization.md) | Creating a keybag, preserving its activation input, and authorizing enrollment. |
| [Boot and persistent storage](boot-and-storage.md) | EFI startup, xART, gigalocker backing, and embedded NVMe namespaces. |
| [Fingerprint lifecycle](fingerprint-lifecycle.md) | First enrollment, Catacomb construction, restore, matching, and deletion. |
| [Integration follow-up](integration-followup.md) | Subsequent installed results, mutable identity sets, stable names, and interrupted-operation recovery. |
| [Artifacts and method](artifacts-and-method.md) | Firmware identities, analysis tools, and ways to reproduce the findings. |
| [Findings index](findings.json) | Machine-readable entry points into the same explanations. |

## Demonstrated result

The reference machine was a 2019 MacBookPro16,1, with T2 board J152fAP
(`iBridge2,14`, board `0x3a`) running bridgeOS 10.6 build `23P6068`.
Linux created and saved an activation-bearing identity without importing a
macOS keybag, Catacomb archive, OpenDirectory record, or APFS cryptographic-user
record. Subsequent experiments activated it after reboot, enrolled a first
fingerprint, restored the saved biometric state on another boot, and checked
both matching and nonmatching fingers.

A narrower contributor result also covers MacBookPro16,2 / J214K with bridgeOS
`23P2048`: its AKS identity-create body uses version 4 rather than version 5.
That machine completed Linux-native creation, enrollment, verification, sudo,
restart persistence, and password-fallback checks in t2touch. It does not extend
the reference machine's full lifecycle and graphical coverage to that model.

The work also demonstrated deletion of one fingerprint with verification of a
survivor after reboot. A continuous second-finger session checked for a duplicate,
completed enrollment, saved the resulting state, reconciled two identities, and
matched the newly added finger.

The completed installed greenfield work exercised standard fprintd first and
additional enrollment, positive and negative verification, selected deletion,
durable neutral naming, and automatic post-reboot reconciliation. Final
inventory was `finger-1`, `finger-2`, and `finger-4` under the historical
allocator. The product now exposes five stable slots, never renumbers retained
identities, and fills the lowest vacancy. Unattended service startup, real
sudo/PAM fingerprint authentication, and independent password fallback with
fprintd unavailable were also demonstrated. The
[follow-up](integration-followup.md) separates those results from source-only
repairs and explains the client boundaries used for the observations.

The installed t2touch product subsequently demonstrated named final-fingerprint
deletion through a clean empty inventory, immediate use after enrollment,
graphical PolicyKit, the Omarchy lock screen, and matching-transport userspace
reinstall. Omarchy installation and the applesmc prerequisite are packaged in
t2touch; mini remains a protocol reference. Later graphical work added visible
readiness feedback, corrected a display failure on unlock, and measured reduced
reader preparation time. See the
[graphical follow-up](integration-followup.md#graphical-integration-and-measured-readiness)
for the successful lock/permission tests and their remaining limits.

The Mac continues to run Apple's bridgeOS and SEP firmware. Multi-user
operation, batch deletion, deep-sleep recovery, cross-macOS persistence, and
broader hardware coverage remain outside the demonstrated scope. The original
research checkpoints below retain their narrower historical evidence boundary.

## Reuse

This directory is available under the [MIT license](LICENSE) in both t2touch and
t2touch-mini. The notes are original explanations of the research findings.
Each reference names the tested or analyzed build where that affects the result.
Protocol identifiers belong to their stated interface: an AKS operation number, a BiometricKit command, and an
internal SEP service handle can have the same value without naming the same thing.
