# Fingerprint integration contracts

Protocol codecs alone do not provide a usable fingerprint service. An
integrator must also own account activation, persistent state, authorization,
client lifetime, and recovery. t2touch implements those layers; t2touch-mini
contains only the identity request codecs and activation-bundle storage.

## Account authority and the current identity set

Account authority and fingerprint inventory have different lifetimes. The
original account proof does not require the first enrolled fingerprint to
remain present. Additions and deletions change the fingerprint set without
creating a new account authority.

Before a mutation, bind the current user/master Catacomb generation, live
identity inventory, and completed mutation journals to the same account UUID,
keybag UUID, and mapping generation. An unfinished or inconsistent mutation
blocks a new mutation.

An addition must extend the complete baseline by exactly one identity and
verify that new identity specifically. A match against an older enrolled
fingerprint does not prove that the addition persisted. Named deletion must
remove exactly its target and preserve every survivor, including the valid
empty set after final-fingerprint deletion.

## Stable names

Names such as `Finger 1` are neutral handles for enrollment records. A private
UUID identifies the template; the label does not establish physical anatomy.

Expose five independent slots, Finger 1 through Finger 5. Deleting one never
renumbers survivors. The next successful enrollment takes the lowest vacancy;
an empty inventory starts at Finger 1. Failed or cancelled capture does not
consume a slot. Allocate the name under the same operation lock that protects
the reconciled inventory.

## Durable completion and interrupted deletion

Capture reaching 100 percent precedes identity validation and persistence.
A client error can occur after SEP has created the fingerprint. Reconcile the
journal, fresh inventory, and saved components before deciding whether another
capture is appropriate.

Deletion has the same boundary. Record intent before biometric command `0x0d`.
If the target is already absent after an interruption, complete the existing
operation's persistence and exact-survivor checks without sending the deletion
again. Preserve the committed master Catacomb as well as the user component so
forward recovery can reconstruct the paired generation.

First enrollment requires fresh-owner verification and publication of account
authority. An addition to an already verified account has its own
identity-specific completion check. Neither a successful local file write nor
a new mapping schema proves that the hardware transaction completed.

## Client and service ownership

A D-Bus client must handle loss of its service owner or bus connection, accept
only status for its own operation, and preserve a terminal result against late
signals. Bound cleanup waits. A timeout ends the client's wait; it does not
certify hardware cleanup. A replacement daemon must not inherit cleanup
authority from an operation owned by the old daemon.

A cached Bridge endpoint is only a routing hint. Every connection still needs
a fresh RemoteXPC handshake and an advertised biometric service record. The
cache supplies neither account authority nor a previous authentication verdict.

## Authentication fallback

Readiness and fingerprint services must converge on startup, and their failure
must leave a usable password path. Verify these independently: a successful
fingerprint transaction does not test password fallback when fprintd is absent.
Keep recoverable PAM configuration when installing authentication changes.

The [T1 research reference](artifacts-and-method.md#research-credits) informed
these lifecycle principles. T2 credential representations, request layouts,
and hardware evidence remain specific to the T2 implementation.
