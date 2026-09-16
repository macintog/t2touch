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
| [Integration contracts](integration-contracts.md) | Account authority, stable names, interrupted-operation recovery, and client ownership. |
| [Artifacts and method](artifacts-and-method.md) | Firmware identities, analysis tools, and ways to reproduce the findings. |
| [Findings index](findings.json) | Machine-readable entry points into the same explanations. |

## Scope

The reference platform is MacBookPro16,1 / J152fAP with bridgeOS 10.6 build
`23P6068`. The protocol supports Linux-owned account creation, activation,
fingerprint enrollment, matching, deletion, and persistent Catacomb storage.
The full t2touch integration supplies the transport, authorization, fprintd,
PAM, and desktop behavior around these operations.

MacBookPro16,2 / J214K with bridgeOS `23P2048` uses an explicitly selected
version-4 identity-create body. Its contributor-reported creation, enrollment,
verification, sudo, and restart results do not establish full lifecycle or
graphical coverage on that model. Each protocol reference identifies the
firmware build to which its layouts and findings apply.

The Mac continues to run Apple's bridgeOS and SEP firmware. Broader hardware,
multiple users, suspend recovery, and persistence across a macOS boot require
separate qualification. These references do not make t2touch-mini an end-user
driver or guarantee compatibility with untested firmware.

## Reuse

This directory is available under the [MIT license](LICENSE) in both t2touch and
t2touch-mini. The notes are original explanations of the research findings.
Each reference names the tested or analyzed build where that affects the result.
Protocol identifiers belong to their stated interface: an AKS operation number, a BiometricKit command, and an
internal SEP service handle can have the same value without naming the same thing.
