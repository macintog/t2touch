# t2touch

Research handoff in preparation for Linux-native Touch ID adoption on clean-state
Intel T2 Macs. The intended contribution is a reproducible path to create Linux-owned
SEP authority, enroll fingerprints, persist their state, and verify a match without
importing macOS user or biometric state.

**The native proof of concept has not been imported into this checkout.** The source
currently implements the upstream, macOS-assisted path. No native hardware result has
been accepted for this tree, and dependency-license compatibility remains unresolved.

## Read the handoff

- [Handoff brief](HANDOFF.md): scope, intended demonstration, and what another engineer
  needs to reproduce and integrate the work.
- [Provenance inventory](docs/handoff-provenance.md): inherited source, dependencies,
  reference projects, and the open licensing finding.
- [Release gates](docs/handoff-release-gates.md): work that can proceed now and the
  evidence required from finished engineering.
- [Support boundary](SUPPORT.md): a finite research contribution with no ongoing
  maintenance commitment.

## Upstream foundation

This repository derives from
[jmurth1234/t2-touchid-linux at ea46d8a](https://github.com/jmurth1234/t2-touchid-linux/tree/ea46d8a0aef3e73b0e2f747aa18721dbcd265bce).
Its history and [GPL-2.0-only license](LICENSE) are preserved.

The [upstream installation guide](https://github.com/jmurth1234/t2-touchid-linux/blob/ea46d8a0aef3e73b0e2f747aa18721dbcd265bce/README.md)
describes the original macOS-assisted workflow. It is not a reproduction guide for
the native contribution. Other inherited documents retain their upstream context
until reviewed for the native handoff.
