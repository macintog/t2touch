# External protocol comparisons

The source observations below were recorded on 2026-09-14. They describe
external research at that date; the [project README](../README.md) and
[validation record](RELEASE.md) describe t2touch's installed capabilities.
Native account creation, enrollment, named deletion, fprintd/PAM integration,
and the Omarchy installer are implemented.

The optional `python3 tools/check-external-research.py` command compares sources
listed in [the manifest](external-research-sources.json) and keeps its local
cache outside Git. It detects source changes; it does not validate hardware or
establish wire compatibility. Review exact source and licenses before adapting
another implementation.

## Current external evidence

| Source | What is established | Classification for the native goal |
| --- | --- | --- |
| [T1Bridge `02885e4`](https://github.com/standardagents/t1bridge/tree/02885e4b3c51bc7ae609681495b5b22dd0f529ae) | T1-native AKS/ACM activation and enrollment retain a separate secret, use the literal `TouchIdEnrollment` policy, verify returned identity, and durably reconcile a paired Catacomb export. | **Adapt** lifecycle and transaction invariants; **reject** T1 payloads, exact secret, transport, and ordering as T2 authority. |
| [KAIT2EN T2 implementation](https://github.com/kaiT2en/KaiT2en-Fedora/commit/1e9c57195377209295731e89b0321d7def4770a4) | Working T2 verification of macOS-enrolled fingers through BridgeXPC/BiometricKit and stock fprintd. Match uses flags `0` and an unbound `0xffffffff` credential-set sentinel. Linux enrollment is explicitly absent. | **Adapt later** as a read-only match discriminator and product-integration reference. It does not replace activation or native enrollment. |
| [KAIT2EN AKS notes](https://github.com/kaiT2en/KaiT2en-Fedora/blob/a34cf7c6446d830ae6d36e98f07d9140146b6f8d/apps/t2-aks/README.md#L19-L36) | Direct-password unlock is operation `0x04`; make-system `0x0d` deleted enrollment; a special-bag unlock caused CATERR/reset; attempts are rate-limited. | **Adopt** the safety warning. Never generalize an experiment on a special/system bag to the disposable native generation. |
| [BrettKulp `7935117`](https://github.com/BrettKulp/t2-touchid-linux/commit/7935117) | Exact-one recovery binding for an unbound `05ac:8233` control interface plus a five-second BridgeXPC quiet period produced a complete reboot/service chain. | **Reference** for boot reliability; not evidence that live PCI rebind is safe for this transport. |
| [Hoolock older-SEP support](https://github.com/HoolockLinux/m1n1/commit/0ec4a6afc73fd25a57c27691bd3134e5c51d09f1) and [Asahi PR 523](https://github.com/AsahiLinux/m1n1/pull/523) | Apple KingFisher mailbox support and mailbox-independent RTKit cover older SEP generations including T2. | **Monitor/adapt later** below our current service-layer boundary. |
| [Asahi issue 594](https://github.com/AsahiLinux/linux/issues/594), [issue 598](https://github.com/AsahiLinux/linux/issues/598), and [PR 599](https://github.com/AsahiLinux/linux/pull/599) | A bound driver can precede terminal SEP readiness; boot-once rebind can leave a dead bound device; timeout cleanup needs single ownership. | **Retain** readiness and cleanup invariants: bound is not ready, no live rebind, one cleanup owner. |
| [Aurora Silicon Touch ID](https://aurorasilicon.org/research/security/touch-id/) and [open-touchid-linux](https://github.com/ELI3GANT/open-touchid-linux) | Apple Silicon research has mapped SEP/SBIO/SIO structure but has not exposed a working sensor, match, or enrollment path. | **Monitor** for architecture evidence. It is not a T2 BridgeOS shortcut. |
| [BiometricKittie protocol inventory](https://github.com/AgentiLoop/BiometricKittie-RnD/blob/main/biometrickittie2/biometrickittie/BiometricKitXpcProtocol-Protocol.h) | Apple's client surface separates completion, identity inventory, database UUID/hash, store-token registration, provisioning, and later match. | **Adapt** as a post-enrollment evidence checklist, not code or current behavior proof. |
| [libfprint shared-storage work](https://github.com/Lannamokia/libfprint/commit/423f4587a88c) | An existing device identity and its local account link can have separate lifetimes. | **Adapt later** for metadata semantics. Adoption is not native enrollment. |
| [Anya](https://github.com/NyanSatan/Anya) | Prototype/JTAG tooling has expanded T1/T2-family firmware extraction. | **Monitor only**; it does not apply to production SEPOS or supply activation semantics. |

Official [libfprint support](https://fprint.freedesktop.org/supported-devices.html)
and the [t2linux feature matrix](https://wiki.t2linux.org/state/) still report no
upstream Apple Touch ID solution. They are lagging status indicators, not
evidence against the working project-specific implementations above.

## Activation semantic crosswalk

The external review closes two apparent contradictions and leaves one explicit
evidence boundary:

| Term or operation | T2 meaning in this repository | External comparison | Decision |
| --- | --- | --- | --- |
| `policy 1007` | Host-side label for ACM command `0x03` carrying literal `TouchIdEnrollment`; the wire never carries integer 1007. | T1Bridge sends the same literal and empty parameter array. | **Adopt** the shared policy spelling; do not claim a numeric wire-policy equivalence. |
| type `5` | ACM command `0x28` installs the identity-verifier input in one live context. | T1Bridge also retains its secret-bearing ACM context across verification and authorization, but uses a different 32-byte secret lifecycle. | **Adapt** context lifetime; retain the recovered T2 16-byte creation-secret mechanism. |
| AKS `0x04` | Direct plaintext-password unlock of a special alias; already implemented as `unlock_alias`. | KAIT2EN exposes this exact research path and warns it can reset SEP on the system bag. | **Reject** as a substitute for the selected ACM path. The warning strengthens our disposable-state and no-retry gates. |
| AKS `0x18` | Selector-`0x9a` credential-bearing transition: transition zero, flag `0x100`, and the original identity-input ACM external form while its separate authorized target remains live. | KAIT2EN does not implement it. T1Bridge's superficially similar number occurs in a T1-specific lifecycle. Exact macOS LocalAuthenticationCore confirms input/output separation and reuses `LACUserCredential.password.contextRef` for login. | Keep the J152f-recovered T2 codec and exact macOS caller contract authoritative. `0x04` and `0x18` are separate contracts, not competing names for one request. |
| AKS `0x21` | Verify the retained-secret input against the exact positive loaded handle and authorize a distinct policy target. | T1Bridge confirms the high-level verify/authorize split, but its fresh-create and persisted-restore order differs. | Preserve the T2 order selected from matching J152f code and prior T2 observations. Never infer ordering from T1. |

D178-D179 subsequently proved the T2 activation sequence that the earlier
D174 comparison left pending: load the exact saved keybag, verify UUID and
alias binding, rebuild the retained creation input in a fresh type-5 context,
authorize the distinct `TouchIdEnrollment` target through `0x21`, perform the
fixed original-input `0x18` transition, and independently read readiness back.
D200 then proved E4 and D218 proved continuous additional enrollment. External
work can challenge those results only with exact T2 service/firmware evidence,
not a shared opcode.

## Enrollment boundary after activation

T1Bridge closes several transaction-design gaps that do not need rediscovery.
Once T2 activation has independently passed, the native enrollment owner must:

- carry the authorized 16-byte ACM external form in the T2 protocol-v2 start
  request `0x03`;
- issue at most one continue `0x0e` for each qualifying progress transition;
- treat a completion callback as provisional until the returned identity is
  present in a fresh, structurally validated `0x42`/global inventory;
- export and sync the user then master Catacomb as one recoverable generation,
  retaining the previous pair until promotion;
- require the final physical identity set to equal the old set plus exactly
  the returned identity; and
- preserve database UUID/hash, store-token/provisioning state, mapping
  generation, and a later usable match as distinct evidence when exposed.

The existing T2 owner remains stricter for protocol-v2 records, global/group
inventory, E3/E4, BioLockout, account-generation binding, outcome-unknown
reconciliation, and sensor-driven capture. Those constraints must
not be weakened to match a T1 implementation.

## Product scope

The installed t2touch service implements native activation, enrollment,
matching, named deletion, neutral slots, PAM fallback, and Omarchy packaging.
External implementations remain comparison evidence for portability and future
integration; they are not missing prerequisites for that completed lifecycle.
