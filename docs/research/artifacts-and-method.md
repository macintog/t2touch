# Artifacts and method

The research combined Intel host implementation recovery, matching SEP firmware
analysis, and controlled hardware observations. The host caller explains how
a request is built; the SEP decoder establishes how its fields are consumed;
hardware results distinguish reachable behavior from a mistaken static reading.

## Firmware identities

The target firmware is bridgeOS 10.6 build `23P6068`, J152fAP. The analyzed
RecoveryOS host binaries come from RecoveryOS 26.6.2 build `25G83`. A further
host biometric reference comes from macOS 15.7.9 build `24G830`. These are
different artifacts, not three names for the installed T2 firmware.

| Artifact | SHA-256 |
| --- | --- |
| bridgeOS IPSW | `da1ce0198ee23d38a6d065e296fed3f302ff79b196c14107ab59ea191028206a` |
| BuildManifest | `8c9b5d0a2440dd6794bde7bd65303ec9a53093dd44a809684e1a90162f3f64e3` |
| `sep-firmware.j152f.RELEASE.im4p` | `bc21098b1c4fa98d20974e55ebeebdf219294caf07db3ab3af3db7882b60be92` |
| Decrypted SEP payload | `1b29e87948c08ddd49a35137e8857892f7c5101fbe1de988dac357a9fa7cf66f` |
| Reconstructed `sks` Mach-O | `57178e6692f2599110eee5a01da24629cd2d5eacf474df09c53a0ae704f7bacd` |
| RecoveryOS `BaseSystem.dmg` | `edddd0d5869caaa12e29e6996a04f11590280580976a119dbd42c24fa62fe18e` |
| Intel AppleKeyStore kext | `c20c4b3302b75536ecea5c0d62bd2a33766d03db6a5239a4b1ff979e046b72ed` |
| Intel AppleSEPManager | `d43b5bf75d7b01000ef9e8b07d56b85de518293f8a95ce1a78dcd3a2a673516f` |

The reconstructed `sks` is an ARMv7 Mach-O with UUID
`D14EC38B-9DE3-32B0-867C-07C86AE9C97C` and source version
`AppleKeyStore_SEP 2155.160.13.0.1`. The recovered Intel AppleKeyStore version
matches it. Both decoders establish the create-v5 record described in
[Identity and authorization](identity-and-authorization.md).

## Recovering a mechanism

Start at both ends of a transaction: the host serializer and the corresponding
SEP dispatcher. Track field widths, padding, operation versions, service handles,
and response ownership through the whole call. Name the address space with each
address, particularly when a call crosses into the shared runtime.

For internal IPC, follow the handle value through lookup, storage, indirection,
and the final send. The xART work needed this chain to distinguish two queues
that shared the same import implementation. For durable state, follow the
returned object into its save and reload callers; the creation KEK output and
the separately exported keybag initially looked like competing persistence paths.

Useful hardware observations include exact request/reply headers, signed status,
transport generation, selected identity, and whether a later boot reproduced the
state. A positive match alone cannot reveal whether a new identity was saved;
inventory and a distinct-finger check resolved that question in the second
enrollment experiment.

Three corrected interpretations are especially useful when adapting the work:

| Initial interpretation | Discriminator | Result |
| --- | --- | --- |
| Create-v5 never returns KEK material | Successful hardware response | A 162-byte output existed; a separate export still supplied the reloadable keybag. |
| Endpoint-16 `0x2d` came from gigalocker I/O | MMIO bytes plus service-handle and dispatcher tracing | The request reached AMDM's unsupported-command branch. |
| The original password could activate the exported identity | Creation-side KDF input compared with verification-side extraction | Creation flags 6 used the raw 16-byte ACM reference; retaining it enabled activation. |

## Research credits

[jmurth1234/t2-touchid-linux](https://github.com/jmurth1234/t2-touchid-linux)
provided the transport and biometric foundation used by the working PoC.
[T1Bridge](https://github.com/standardagents/t1bridge/tree/7003b8d9f791)
informed the retained-secret lifecycle and enrollment transaction design.
The notes in this directory describe the subsequent T2 native-adoption research
in original prose.

Artifact acquisition and analysis used these open-source tools:

| Tool | Role | Recorded revision |
| --- | --- | --- |
| [OpenCorePkg macrecovery](https://github.com/acidanthera/OpenCorePkg) | Recovery asset acquisition | `2a9ce04683ab1d9ca7619bbb4ea4ab869c000ee1` |
| [ipsw](https://github.com/blacktop/ipsw) | Apple image inspection and extraction | `cdbc3a57114b5b240d23b00aa29cfad4d1f1d3fd` |
| [DyldExtractor](https://github.com/arandomdev/DyldExtractor) | Shared-cache image recovery | `0e1b35a5f60e7041c51b57a54cc36d815fe7adf2` |
| [sepsplit-rs](https://github.com/justtryingthingsout/sepsplit-rs) | SEP application reconstruction with split-data support | `ff45f9d1013cfd54413ec6c57b616b4e89187b7f` |

The older [sepsplit](https://github.com/matteyeux/sepsplit) at
`721c5bb3d7730af0bf39b9083b7ddeab3f718ee1` was a comparison tool. Its output did
not resolve this firmware's split-data layout and was not used for the final
application analysis. The hashes above identify analyzed artifacts; this
documentation bundle contains neither those binaries nor tool source.
