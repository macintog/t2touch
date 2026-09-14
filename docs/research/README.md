# T2 SEP and Touch ID research

These notes describe how Linux created its own T2 account identity, enrolled
fingerprints, and restored them after reboot. They cover the Secure Enclave
services, wire formats, and persistent state behind that result.

| Read | For |
| --- | --- |
| [SEP architecture](sep-architecture.md) | Host transports, internal services, mailbox framing, and request ownership. |
| [Identity and authorization](identity-and-authorization.md) | Creating a keybag, preserving its activation input, and authorizing enrollment. |
| [Boot and persistent storage](boot-and-storage.md) | EFI startup, xART, gigalocker backing, and embedded NVMe namespaces. |
| [Fingerprint lifecycle](fingerprint-lifecycle.md) | First enrollment, Catacomb construction, restore, matching, and deletion. |
| [Integration contracts](integration-contracts.md) | Account authority, stable names, durable completion, client ownership, and fallback. |
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

The installable t2touch product implements first and additional enrollment,
matching, named deletion through an empty inventory, and automatic startup
reconciliation through fprintd. It exposes five stable neutral slots and keeps
password fallback available. Multi-user operation, batch deletion, deep-sleep
recovery, cross-macOS persistence, and broader hardware coverage are not
established by the reference-machine result.

## Reuse

This directory is available under the [MIT license](LICENSE) in both t2touch and
t2touch-mini. The notes are original explanations of the research findings.
Each reference names the tested or analyzed build where that affects the result.
Protocol identifiers belong to their stated interface: an AKS operation number, a BiometricKit command, and an
internal SEP service handle can have the same value without naming the same thing.
