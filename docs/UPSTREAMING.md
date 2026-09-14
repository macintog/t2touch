# Upstream handoff plan

The objective is a reviewable Linux Touch ID stack for Intel T2 Macs that keeps
biometric matching in SEP and fails closed. “Upstream” spans several projects;
the experimental repository should not be submitted as one indivisible patch.

## Submission boundaries

| Component | Present home | Likely review boundary | Required before RFC |
| --- | --- | --- | --- |
| PCI mailbox, DMA, reset, and power management | `src/t2_sep_transport.c` | Linux kernel and T2 BCE maintainers | Multiple machines, lifecycle contract, no unload hazard, reviewed UAPI |
| Narrow AKS/ACM protocol access | Kernel transport plus root tools | Kernel security/UAPI review or retained userspace policy | Stable operation semantics, strict allowlist, fuzzed codecs |
| BridgeXPC and biometric state machine | Python userspace | Standalone daemon/library first | Version negotiation, reconnect behavior, multi-build evidence |
| Desktop authentication | fprintd-compatible facade and PAM templates | libfprint/fprintd and distro maintainers | Agreed representation for SEP-owned templates; no service conflict |
| Packaging and recovery | installer, systemd, PAM | Individual distributions | Idempotence, rollback, upgrade, and failure-injection evidence |

Subsystem destinations are intentionally provisional. Ask maintainers where a
driver belongs before restructuring it around a guessed kernel directory.

## Handoff gates

1. **Reproducible baseline:** CI is green, public-tree scans pass, userspace
   builds with warnings as errors, and the test procedure names exact commits.
2. **Reference-machine verification:** the recorded MacBookPro16,1 completes
   native positive and negative verification controls, first enrollment/E4,
   deletion, and continuous additional enrollment. These are complete through
   D218. Generality beyond this machine remains explicitly unproven and is left
   for later upstream testing.
3. **Lifecycle reliability:** cold boot, cancellation, bridgeOS port change,
   kernel upgrade, and a documented suspend policy fail closed and recover
   without unloading registered SEP DMA.
4. **Security review:** kernel memory/DMA lifetime, ioctl boundaries, parser
   fuzzing, replay, multi-user isolation, PAM fallback, and secret handling are
   independently reviewed.
5. **Maintainer RFC:** send architecture and UAPI questions before a large
   patch series. Include protocol provenance, reference-platform log, threat model,
   and deliberately unsupported operations.

## First kernel patch series shape

The first RFC should demonstrate transport mechanics without desktop policy:

1. PCI identification and mailbox discovery.
2. Bounded DMA allocation, registration, and teardown/reset contract.
3. Transaction matching, timeout handling, and buffer scrubbing.
4. A minimal documented interface for one read-only capability operation.
5. KUnit or equivalent hardware-free tests for framing and malformed replies.

Biometric verification, keybag mutation, PAM, and distro installation should
not be hidden inside that series. A generic raw command channel is explicitly
out of scope.

## Evidence attached to every RFC revision

- Exact kernel, t2bce, bridgeOS, and project revisions.
- Exact observations from [`REFERENCE_PLATFORM.md`](REFERENCE_PLATFORM.md).
- Automated test and privacy-scan results.
- Fault-injection results for timeout, malformed response, device loss, and
  interrupted caller.
- Remaining invariants that are inferred rather than observed.

## Separate follow-on projects

Non-exportable signing keys, a PKCS#11/OpenSSL provider, SEP-wrapped LUKS
keyslots, and a trusted Linux boot chain share some transport work but have
different security properties. They should receive separate threat models and
must not delay a verification-only Touch ID submission.
