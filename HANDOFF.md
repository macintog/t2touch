# Research handoff

## Purpose

t2touch will publish a reproducible proof of concept for Linux-native T2 Touch ID
adoption. The audience is engineers who can evaluate the implementation, reproduce
the result on appropriate hardware, and carry it into a maintained project.

The delivery ends with usable source, a protocol explanation, reproduction evidence,
and a precise account of the remaining integration work. It does not include ongoing
product maintenance, distribution packaging, or support for additional hardware.

## What is being prepared

This checkout starts from upstream commit
[`ea46d8a0aef3e73b0e2f747aa18721dbcd265bce`](https://github.com/jmurth1234/t2-touchid-linux/commit/ea46d8a0aef3e73b0e2f747aa18721dbcd265bce).
The new native implementation remains under engineering. No native release candidate
or hardware result has been accepted for this checkout.

The [provenance inventory](docs/handoff-provenance.md) distinguishes inherited code,
dependencies, adaptations, and research references. Its unresolved license finding
must be resolved before the runnable handoff can be approved for publication.

## Meaning of Linux-native adoption

The target is a Linux installation that creates its own SEP-backed account authority
and enrolls fingerprints without importing a macOS keybag, Catacomb, OpenDirectory
record, or APFS cryptographic-user record. The hardware still runs Apple's bridgeOS
and SEP firmware. Firmware prerequisites and any earlier provisioning needed by the
machine must be stated explicitly in the final reproduction guide.

Research that consulted Apple software must be described separately from installation
and runtime requirements. A clean-state claim requires a recorded starting state;
a successful match alone does not establish how that state was created.

## The package another engineer needs

The final handoff must provide:

- Source and build/install inputs for the complete native path, pinned to a release
  commit. Every required dependency must be publicly obtainable and license-reviewed.
- A reproduction guide with the starting state, exact hardware and firmware, commands,
  expected observations, stop conditions, and recovery instructions.
- An explanation of account authority creation, activation, enrollment, persistence,
  restore, and identity-specific matching, with links to the implementing code.
- A compact evidence table separating observed behavior, recovered outcomes, and
  untested cases. Evidence must identify the source revision and environment.
- An integration map showing which parts another project can reuse and which parts
  remain specific to the tested T2 protocol and hardware.

Protocol notes should retain the discoveries that explain the implementation. Raw
transcripts, private machine state, failed-probe collections, and internal execution
instructions are not part of the public handoff.

## Acceptance boundary

The intended demonstration is clean-state adoption, enrollment, durable persistence,
restore after a documented restart, positive matching, and an unenrolled-finger
negative control. Each claim needs evidence from the final candidate. Additional-finger
enrollment, deletion, cancellation, and interruption recovery should be described only
to the extent supported by that candidate's evidence.

Linux reboot, cold power cycle, and bridgeOS restart are distinct observations. The
release must name the transition actually tested. Recovered enrollment must not be
presented as an uninterrupted ceremony.

Production fprintd/PAM integration, broad hardware coverage, and upstream acceptance
are not completion requirements for this handoff. Any such capability that is included
must carry its own validation and limitation statement.

## Publication and adoption

Preserve upstream ancestry and add curated changes on top of an identified base.
Record any later base change and review the resulting behavior. Do not merge the raw
research history solely to obtain the final files.

The private preparation repository and public fork use ordinary Git commits. The
public candidate is the exact reviewed tree, not the output of an export generator.

After release, the work can be offered to the original T2 project and other relevant
projects for independent adoption. No recipient has agreed to integrate or maintain
it. A recipient's acceptance is not required to complete the handoff. Outreach needs
separate approval of the message and recipients.

The [support boundary](SUPPORT.md) defines the author's involvement after delivery.
