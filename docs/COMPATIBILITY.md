# Compatibility architecture

The project aims for Linux-native Touch ID across Intel T2 Macs. The one
available MacBookPro16,1 is the reference implementation and the only hardware
on which new behavior may be called verified. It is not an implementation
allowlist. T1/iBridge1 is an exploratory extension: shared protocol pieces
should be reused when evidence supports them, while a different transport or
security lifecycle must remain a separate backend.

This is deliberately not an exhaustive model catalog. Compatibility grows by
recording protocol facts and verified exceptions, not by adding marketing
model conditionals.

## Compatibility tuple

Every result should identify the smallest relevant tuple:

```text
bridge generation       iBridge1, iBridge2, ...
coprocessor chip ID      from the restore identity or hardware evidence
board target             provenance and verified-quirk key only
bridgeOS build           runtime/static protocol version axis
AppleKeyStore version    codec/semantic version axis
host transport           BCE mailbox, USB, or another evidenced backend
BridgeXPC version        biometric service negotiation axis
biometric protocol       command/reply codec version axis
```

Board target and Mac model must not select protocol behavior merely because
they are available. A conditional needs a documented, reproducible difference
in wire format, transport, or lifecycle. Otherwise capability negotiation and
versioned codecs select behavior.

## Portable boundaries

1. **Identity discovery** reports the tuple without private device identifiers.
2. **Transport backends** expose bounded named operations. T2's PCI/BCE mailbox
   backend is one implementation, not the definition of AppleKeyStore.
3. **Protocol codecs** are hardware-free and keyed by explicit record/protocol
   versions, never a Mac model.
4. **Lifecycle policy** journals mutation and reconciliation independently of
   the transport backend. Inputs such as internal versus portable storage are
   explicit capabilities recovered from host policy, not model predicates.
5. **Desktop integration** consumes a verified identity result and has no SEP
   or model-specific logic.

This separation lets another contributor bring a different T2 board by
supplying evidence for its tuple and testing the same codecs. It also gives T1
a viable path without pretending its transport is T2 BCE.

## Display and desktop compatibility

GPU routing is independent of the SEP protocol tuple. T2 machines may expose
an integrated GPU, a discrete GPU, or both, and either may own a connected
panel. The installer must not impose the reference laptop's routing policy.

The UWSM selector enumerates DRM devices and connectors at each login. It
preserves an explicit `AQ_DRM_DEVICES` value, including empty. Only when both a
fallback framebuffer and a connected native display exist does it select the
native devices: connected internal panels first, other connected displays next,
then remaining native GPUs. It retains those other native GPUs and changes no
kernel GPU-routing or power controls. Without that condition, Hyprland keeps
its default selection. No GPU vendor, PCI address, card number, or Mac model
is hardcoded.

Physical display and reboot coverage is limited to the MacBookPro16,1 reference
laptop. Regression fixtures do not qualify discrete-only, integrated-only, or
other multi-GPU machines.

The Omarchy UI helper checks all three QML files before writing any of them,
backs up originals, and skips unfamiliar integration points. Package updates
may replace the patch. A skipped UI patch does not disable the backend protocol
or DRM selector, but readiness messages then depend on the installed desktop.
See the [rollback instructions](TROUBLESHOOTING.md#undo-the-omarchy-desktop-integration).

## Evidence from the shared restore

Apple's bridgeOS 10.6 `23P6068` IPSW is a multi-device container. Its
BuildManifest has 16 unique iBridge2 hardware identities, all with chip ID
`0x8012`, and each identity selects a board-specific SEP image. This proves
that board selection belongs in artifact provenance. It does **not** prove
that all 16 images implement identical AppleKeyStore or BiometricKit behavior.

The J152f image is the only member currently analyzed and hardware-tested. Its
`AppleKeyStore_SEP` source version matches the separately recovered x86_64
AppleKeyStore framework. Other members are useful comparison inputs if a
specific portability question arises; analyzing all of them is not a gate.

Inspect one identity without introducing an allowlist:

```sh
python src/t2_bridgeos_manifest.py BuildManifest.plist \
  --product-type iBridge2,14 --target-type j152f --board-id 0x3A
```

Use `--all` only when a packaging-level comparison is actually needed. The
tool reports public restore metadata and SEP paths; it does not extract or
redistribute Apple firmware.

## Adding hardware evidence

For a new T2 Mac, contributors should:

1. record the public compatibility tuple and keep serials, addresses, UUIDs,
   keybags, Catacombs, and biometric data private;
2. prove transport and read-only negotiation before enabling authentication;
3. compare versioned codec behavior, adding a quirk only for a demonstrated
   difference;
4. run positive and negative controls on that hardware before changing its
   status from candidate to verified; and
5. report unsupported or unknown layers independently rather than marking the
   whole model supported.

For T1/iBridge1, begin at identity discovery and transport enumeration. Parser
support for an iBridge1-shaped manifest is only format portability; it is not
evidence that T1 exposes the T2 mailbox, endpoint numbers, keybag lifecycle, or
BridgeXPC services.

Relevant upstream transport projects are
[`t2linux/apple-bce-drv`](https://github.com/t2linux/apple-bce-drv) and the
upstream-oriented [`deqrocks/t2bce`](https://github.com/deqrocks/t2bce).
Their transport scope should remain separate from this project's
AppleKeyStore and biometric policy layers.
