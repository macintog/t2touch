# Touch ID readiness after resume

Keeping native presentation metadata across system sleep moved the lock
screen's fingerprint prompt from **4.34–4.52 s to 2.42 s** after resume on the
MacBookPro16,1 reference machine. The hardware inventory no longer runs on the
resume path; verifier preparation now starts as soon as logind reports resume.
Each match still repeats live SEP inventory reconciliation and attestation.

These measurements end when the lock screen relays the placement prompt. They
do not measure physical-contact-to-result time or a complete graphical login.

## What changed

Before this change, `system_sleep_changed()` discarded the cached native
projection on both sleep edges. The resume warmup therefore repeated the full
inventory collection, which performs its own AKS and ACM authorization, Bridge
inventory, and Catacomb restore, before it could start the verifier. Both
operations take the machine-wide operation lock without blocking and both open
AKS/ACM, so they cannot overlap.

The sleep edge now advances the inventory generation, so a read that straddles
it cannot publish, but it keeps a completed native projection. The next use
still compares the account-authority token and the committed Catacomb and
mutation-journal state token. Verifier preparation is still released on sleep
and rebuilt after resume; no AKS keybag or ACM context crosses a suspend.

## Measurement conditions

Linux `7.2.11-arch1-Watanare-T2-1-t2-amdoff`, Python 3.14.8, deep sleep
initiated by closing the lid. The machine carried local, out-of-tree resume
repairs for unrelated platform devices; they are not part of T2Touch and
suspend/resume remains unqualified as described in the
[sleep policy](../SLEEP_POLICY.md). Times are from the systemd journal,
measured from `user.slice` thaw. Profiling was off.

| Resume | Code | PAM start | Prompt | Inventory | Verifier preparation |
| --- | --- | ---: | ---: | --- | ---: |
| 1 | before | +0.273 s | +3.897 s | collected, 1,952 ms | 1,764 ms |
| 2 | before | +0.292 s | +3.918 s | collected, 1,948 ms | 1,785 ms |
| 3 | before | +0.262 s | +3.874 s | collected, 1,909 ms | 1,775 ms |
| 4 | before | +0.316 s | +4.522 s | collected, 2,250 ms | 1,960 ms |
| 5 | before | +0.253 s | +4.441 s | collected, 2,152 ms | 2,021 ms |
| 6 | before | +0.255 s | +4.341 s | collected, 2,102 ms | 1,974 ms |
| 7 | after | +0.283 s | +2.422 s | cached, 0.0 ms | 2,076 ms |

Resume 1 ran on the machine's non-`amdoff` kernel build; resumes 2–3 and 4–6
ran in two later boots of the candidate's kernel. Resumes 4–6 come from the
boot immediately before the candidate and are its closest baseline; why they
are slower than 2–3 was not investigated. Before the change, verifier preparation
began 1.92–2.30 s after thaw; after it, at +0.044 s. Its internal AKS phases
were unchanged: about 0.27–0.29 s keybag retention, 0.55 s ACM context
authorization, and 0.56–0.58 s identity unlock. This is one candidate resume,
not a latency distribution.

The candidate's lock-screen match completed with post-match attestation, PAM
reported success, and the session unlocked. No negative control, enrollment,
deletion, or password-fallback path was exercised in this comparison.
