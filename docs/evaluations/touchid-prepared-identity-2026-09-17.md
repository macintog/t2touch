# Touch ID readiness and repeated touches

Retaining prepared AKS and ACM state reduced median reader readiness from
**1.689 s to 0.314 s**, saving **1.375 s (81.4%)**, on the MacBookPro16,1
reference machine. Each request still obtains fresh caller authorization and
checks hardware state before matching.

These measurements end when the reader is ready for a finger. They do not
measure physical-contact-to-result time or a complete graphical login.

## Measurement conditions

The comparison used Linux `7.2.6-arch2-Watanare-T2-2-t2`, Python 3.14.7, and
unchanged hardware and installed dependencies. bridgeOS 23P6068 had been
identified earlier that day and was not queried again for this comparison.
The baseline already overlapped replacement-worker imports with verification.

Four blocks alternated baseline, candidate, baseline, candidate. Each restarted
fprintd, allowed three seconds for startup, measured the first request
separately, waited two seconds, then ran six immediate requests and three
requests separated by three seconds. Each request claimed, armed, stopped,
and released the reader without a touch. Profiling was off. No readiness
request failed, and both pairs reproduced the gain.

| Claim through ready cue, median | Baseline | Prepared identity | Saved | Samples per arm |
| --- | ---: | ---: | ---: | ---: |
| Immediate requests | 1.688980 s | 0.313866 s | 1.375115 s (81.4%) | 12 |
| Three-second gaps | 1.689648 s | 0.312006 s | 1.377642 s (81.5%) | 6 |
| First after startup window | 1.589941 s | 0.252324 s | 1.337618 s (84.1%) | 2 |

Immediate-request ranges were 1.570887–1.720068 s for the baseline and
0.230688–0.322872 s with prepared identity. The first-request measurement
starts after the three-second startup window. Preparation moves work into
service startup; it does not eliminate that cost or establish cold-start time.
Long-idle behavior was not qualified by this comparison.

## Historical comparison

An earlier direct-verification baseline measured 5.057296 s through reader
readiness, from two samples of 5.149571 s and 4.965022 s. Compared with the
current 0.3138655 s median, this is 4.7434305 s less waiting, or 93.8%.
The changelog rounds these values to 5.06 s, 0.31 s, 4.74 s, and 94%.

The historical baseline predates the inventory cache and prewarmed matcher.
It was recorded in a different session on kernel 7.2.4, versus 7.2.6 for the
current result. Use the controlled comparison above to assess the prepared
identity change alone.

## Worker memory

The maximum sampled sum of worker RSS fell from 131,844 KiB for two workers
to 67,212 KiB for one worker: 64,632 KiB (63.1 MiB, 49.0%) less. Sampling every
50 ms can miss brief peaks. RSS sums count shared pages more than once and
exclude the daemon. CPU, energy, system memory headroom, and capacity were
not measured.

## Authorization and ownership

The resident worker retains a prepared keybag and ACM capability while idle.
Each request reloads account and activation data, checks configuration and
transport generations, obtains fresh operation authorization, and checks SEP
policy. A changed binding releases the old preparation. An expired policy
permits one complete reauthorization before matching; other failures retire
the worker. A match is never replayed.

Each match opens a fresh Bridge connection and checks the fingerprint list
and result. Idle workers hold no operation lock or sleep inhibitor. Authorized
root AKS/ACM callers can request release of idle preparation; active requests
retain exclusive ownership. The kernel remains the final owner check.
Cancellation requires a separate cleanup acknowledgement and cannot produce
a match verdict.

## Repeated-touch behavior

Two successful results for the same finger previously caused verification to
fail. The worker now retains callbacks received during export and cleanup,
acknowledges each once, and saves the BioLockout state for every accepted
result before completing. Repeated matches must identify the same attested
finger. Conflicting, invalid, unbound, or unsaved results fail.

Physical checks covered an enrolled finger touched twice, an unenrolled
finger, and an enrolled finger touched once. All returned the expected result.
These were three checks, not a latency distribution. Host-observed intervals
from result receipt to public status were 1,576.709 ms, 1,963.347 ms, and
907.778 ms respectively. Physical-contact timing was not measured, and
callback batching can underestimate sensor work.

The timing comparison preceded final callback handling and C-helper ownership
corrections. Those changes received separate software and ownership-handoff
checks, but the timing comparison was not repeated for the final source.
The physical checks also preceded stricter integer validation and a stale
socket cleanup fix. No speedup after physical touch is claimed.

The 500 ms callback drain remains because callbacks can arrive after the
terminal result and during cleanup. These checks did not exercise graphical
login, suspend/resume, reboot, enrollment, or deletion, or establish support
for another Mac or firmware version. Separate recovery results appear in
[Fingerprint recovery findings](../RECOVERY_RELEASE_GATE.md).
