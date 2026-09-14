# Fingerprint lifecycle

The first fingerprint creates host biometric state as well as a SEP identity.
Linux can build that state from the enrollment results without importing a
macOS Catacomb archive. Account activation, capture, persistence, and restore
form one lifecycle, even though they cross different transports.

## From an activated account to a fingerprint

The transaction begins with the selected account's verified keybag and live ACM
authorization, plus an explicitly empty biometric inventory. BridgeXPC carries
the biometric service messages. Enrollment uses start command `0x03`, continue
`0x0e`, and cancel `0x0c`; matching uses `0x04`, and removal uses `0x0d`.
These are biometric commands, separate from the AKS operation numbers.

Service messages have a 24-byte little-endian `<QIIQ>` header. Relevant event
types include:

| Event | Meaning |
| --- | --- |
| `0xe3ff8000` | Bridge status |
| `0xe3ff8001` | Enrollment status |
| `0xe3ff8003` | Enrollment result |
| `0xe3ff8004` | Enrollment statistics |
| `0xe3ff8009` | Sensor recovery |
| `0xe3ff800a` | SKS lock |
| `0xe3ff800e` | Accessory authentication |

Enrollment follows the returned events; repeatedly starting the sensor on a timer
does not replace that sequence. Progress reaching 100 percent is followed by a
terminal result and identity reconciliation. The successful second-finger session
used an extended version-1 terminal witness through a fresh Bridge connection
while retaining AKS/ACM authority. A parser that assumes only a short terminal
record can lose the result after capture has already succeeded.

## Constructing the first Catacomb

Catacomb is the host's persisted biometric archive. Its user, master, and
BioLockout components hold different state. The first user component is produced
after the first enrollment; an invented empty archive is unnecessary.

The terminal enrollment result supplies the numeric user ID, identity UUID, and
accessory descriptor. The first identity metadata uses type 1, attribute 0,
entity 0, the creation time, flags 0, and zeroed match/update counters.
The built-in accessory and group use zero UUIDs, name `Builtin`, type 1, and
accessory flags 6.

| Persistent field | Source |
| --- | --- |
| Secure user `LTFC` | Biometric command `0x3e` result for the selected user |
| Account UUID | AKS creation identity reconciled with primary inventory |
| Keybag UUID | Saved keybag identity, verified again after loading |
| Fingerprint UUID | Terminal result reconciled with fresh biometric inventory |
| Secure BioLockout `HRLB` | Biometric command `0x4a` result |

The persistence sequence reads command `0x3c` twice to establish stable state,
marks the selected user dirty, and stages the master last. Prepare `0x3d` and
complete `0x3e` supply the secure results used to encode user and master archives.
Confirmation and host commit have their own ordering; an interrupted outcome
needs reconciliation before another enrollment. The final batch includes the
`HRLB` from `0x4a`. Reading back the live identity set and all local components
checks that the committed generation describes the same enrollment.

`CatacombEnrollmentCount` was 1 for the first retained generation and 2 after
the next enrollment. Its reset and wrap behavior was not established. The
counter cannot substitute for the actual identity inventory.

## Restoring on another boot

Restore loads the master through biometric command `0x40`, then the selected
user, then the latest rolling BioLockout state. A cold connection may initially
show only master state 1. Loaded state `0x03` permits the subsequent user path;
the recognized component bits are `0x07`.

Biometric command `0x42` reads identities for a user; `0x51` reads the global
identity set; `0x50` reads group states. Identity entries are 20 bytes: a
four-byte user ID and a 16-byte identity UUID. The reference parser bounds the
set at 64 entries. The T2 component format uses version 2 and 24-byte descriptors,
unlike the referenced T1 version-1 format.

A loaded-user bit without its expected live identities is inconsistent state.
Restoring an old BioLockout archive can also disagree with more recent secure
state, so the rolling copy is persisted as it changes. The account mapping
selects the actual user ID; the empty results observed for several numeric IDs
do not make those IDs interchangeable after enrollment.

## Matching, adding, and deleting

The research checked a matching finger and a nonmatching finger after restoring
the native generation on a different boot. It also deleted one exact identity,
recovered the paired user/master state, and verified a surviving fingerprint
after another boot.

For a second enrollment, a duplicate check preceded capture. The completed
transaction saved all components, reconciled two identities, and matched the
new addition. These checks distinguish a working newly enrolled identity from
an old fingerprint that still matches while the new one was never persisted.

An integrating project can use this sequence beneath its own transport and
authentication service. These initial protocol experiments did not test
fprintd/PAM or password fallback. The completed installed work later exercised
standard fprintd enrollment, matching and selected deletion across reboot, as
well as real sudo/PAM fingerprint success and an independent unavailable-service
password fallback; see the [integration follow-up](integration-followup.md).
