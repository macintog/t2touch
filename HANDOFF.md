# About the work

t2touch explores how Linux can set up Touch ID on a T2 Mac without an existing
macOS user account or imported biometric data. The work is intended to help other
engineers reproduce the result and integrate it into their projects.

The native path creates account authority in the Secure Enclave, enrolls
fingerprints, saves their state, and uses them for matching. It is still under
development and has not yet been added to this repository.

The Mac continues to use Apple's bridgeOS and Secure Enclave firmware. The
contribution concerns creating and managing the user and fingerprint state from
Linux.

See [sources and credits](docs/handoff-provenance.md) for the project's foundation
and research references.
