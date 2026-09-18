# Touch ID readiness with overlapping worker imports

September 17, 2026. On the test MacBookPro16,1, preparing an import-only spare
while verification runs reduced the median direct-verify readiness time of
immediate retries from **2.066 s to 1.670 s**, a **396.608 ms (19.2%)** reduction.
Spaced requests and cancellation cleanup were essentially unchanged. This is
a reader-readiness result, not physical-contact or full-login latency.

## Evidence and method

The comparison used Linux `7.2.6-arch2-Watanare-T2-2-t2` and Python 3.14.7.
bridgeOS 23P6068 had been identified earlier that day and was not queried
again. Both arms used the same hardware, dependencies, configuration and
preparation probe.

Four blocks alternated baseline, candidate, baseline, candidate. Each restarted
fprintd, ran one separately retained warmup, waited two seconds, ran six
direct-verify requests with no inter-request idle, then three requests with
three-second gaps. Each request claimed, armed, stopped, and released the
reader without a touch. Profiling was disabled during these comparisons.

The first baseline block overlapped ancillary ShellCheck/privacy commands.
That first pair is retained as exploratory evidence, not used for the primary
numbers below. The clean second pair independently reproduces the gain.
There were no failed readiness requests. The first sample in each tight series
starts with an already prepared worker and remains included in both arms.

| Clean repeat, median | Baseline | Candidate | Change |
| --- | ---: | ---: | ---: |
| Direct verify to armed, no idle (6 each) | 2.066140 s | 1.669532 s | -396.608 ms (-19.2%) |
| Direct verify to armed, 3 s idle (3 each) | 1.685424 s | 1.668321 s | -17.103 ms (-1.0%) |
| Stop and release, no idle (6 each) | 0.689424 s | 0.688987 s | -0.438 ms |

The tight-series ranges were 1.578448–2.077410 s baseline and
1.596131–1.672741 s candidate. The exploratory first pair's median improvement
was 390.076 ms. Small spaced-request differences are not a separate gain claim.
This is a small, single-session comparison, not a cross-platform qualification.

The largest sampled sum of worker RSS was 66,612 KiB baseline versus 131,644
KiB candidate, an additional 65,032 KiB (63.5 MiB) during active verification.
The observer sampled `/proc` every 50 ms and may miss brief peaks; these sums
do not deduplicate shared pages or include daemon memory. Idle operation has
one worker in both arms. Import work is moved earlier, not eliminated; CPU and
energy changes were not quantified. No capacity or memory-efficiency gain is
claimed. The bounded transient cost buys the measured repeated-request gain.

## Why the seven fixes did not improve readiness

The preceding evaluation had already shown approximately 31 ms for endpoint
discovery and 122 ms for Bridge preparation. Removing TCP batching could not
reliably remove the much larger delays elsewhere. BioLockout publication is
outside the ordinary no-touch readiness path.

The current intervention overlaps replacement imports with the active request
while preserving one hardware transaction per process. Previously those imports
began after the preceding worker was discarded. A prompt retry waited for that
replacement; after a few idle seconds the imports had already completed.
The measured improvement in tight requests, with little change in spaced
requests, agrees with this causal prediction.

Two additional candidate requests enabled opcode-only syscall profiling:

| Exchange | Median duration | Observations |
| --- | ---: | ---: |
| AKS `0x21`, identity authentication | 480.020 ms | 2 |
| AKS `0x18`, credential unlock | 497.163 ms | 2 |
| AKS `0x03`, keybag load | 85.773 ms | 2 |
| AKS `0x0d`, alias bind | 91.916 ms | 2 |
| ACM operations, grouped by opcode | 0.570–1.558 ms | 18 total |

The phase formerly labeled ACM authorization spends most of its time in the
AKS identity-authentication call inside that phase. These measurements locate
cost inside the ioctl boundary; they do not establish whether firmware,
cryptography, kernel scheduling, or other kernel work dominates it. No
authorization, keybag load, unlock, or independent readback was removed.

## Behavior and limits

The change overlaps worker imports while retaining fresh caller authorization,
AKS/ACM checks, fingerprint-list checks, result validation, BioLockout saves,
and the 500 ms callback quiet period. Cancellation stops the workers, and
service shutdown retains control-group process cleanup.

No physical touch, enrollment, deletion, or hardware suspend/resume was tested
in this comparison. Sleep handling had fixture coverage only. The result does
not establish authentication or readiness after resume.

The later [prepared-identity implementation](touchid-prepared-identity-2026-09-17.md)
reuses more of the preparation work and supersedes the import-only spare in
the native verification path. The figures here describe the earlier change.
