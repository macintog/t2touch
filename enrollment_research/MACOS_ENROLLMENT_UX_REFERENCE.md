# macOS Touch ID enrollment UX reference

This repository preserves an operator-provided screen recording of the existing
macOS Touch ID enrollment flow:

- [macos-touch-id-enrollment-reference.mov](reference_media/macos-touch-id-enrollment-reference.mov)
- SHA-256: `fcd6bf72839edb0efcaeb7043deff09ee62360b17f39d86976662495d9033219`

The recording is a product-behavior reference for a future Linux enrollment
frontend. It is not protocol evidence and must not override the recovered,
tested enrollment state machine or the persistence and reconciliation gates.

## Provenance and media details

- Retained in the repository on 2026-09-02 without transcoding or other content
  changes.
- The QuickTime metadata identifies ReplayKit as the recorder and records a
  creation time of `2026-09-01T01:47:38Z`.
- Duration: approximately 27.515 seconds.
- Video: H.264, 1458 x 1246, nominal 120 frames per second.
- Audio: AAC track with effectively silent samples; no spoken guidance is
  present.
- Size: 6,766,306 bytes.

The on-screen fingerprint is a stylized progress illustration, not a captured
fingerprint image or raw sensor output. No account name, stable identifier,
credential, Catacomb content, or biometric payload is visible in the recording.

## Observed interaction

Times are approximate and describe this one recording, not required enrollment
durations or protocol deadlines.

| Time | Visible behavior |
| --- | --- |
| 0-1 s | The enrollment sheet opens over **Touch ID & Password** settings. |
| 1-17 s | **Place Your Finger** remains visible with “Lift and rest your finger on Touch ID repeatedly.” The fingerprint illustration fills incrementally as touches are accepted. |
| 17-26 s | The heading remains **Place Your Finger**, while the instruction changes to “Keep going to capture the edges of your fingerprint.” Incremental visual feedback continues. |
| 26-27.5 s | A distinct terminal screen says **Touch ID is Ready** and offers **Done**. |

**Cancel** remains available throughout the active capture phases. Progress is
shown continuously without exposing a numeric percentage, and completion is a
separate state rather than merely a full-looking progress illustration.

## Cadence and closed-loop feedback

The recording's cadence is user- and result-driven rather than metronomic.
Progress arrives across repeated place/lift cycles during the central-coverage
phase, then continues across deliberate edge placements. There is no visible
countdown, target touch rate, or automatic time-based advance. A user can pause
between contacts without changing the meaning of the current phase.

The operator who made the recording recalls deliberately adjusting each touch
and experiencing the flow as a quality-feedback loop: macOS judged the input,
updated the illustration or guidance, and that response informed the next
placement. The visible stepwise progress and later edge instruction are
consistent with that recollection, but the recording alone does not reveal the
firmware's quality criteria. Treat the quality judgment as operator evidence
until exact service events and capture-error mappings establish it.

The Linux flow must therefore advance from accepted backend events, not from a
raw contact count, elapsed time, or animation schedule. Presence/lift events
should acknowledge cadence immediately; accepted-capture events should advance
coverage; and rejected, low-quality, partial, or dirty-sensor events should
leave accepted progress intact while giving a concrete correction for the next
touch. The UI must remain responsive whether the user moves quickly or pauses.

## Guidance for the Linux implementation

The user-facing flow should preserve these semantics while remaining driven by
the recovered service events:

1. Treat enrollment as a repeated place/lift interaction, with immediate
   feedback for accepted touches and actionable retry text for rejected,
   partial-coverage, or dirty-sensor events.
2. Present ordinary coverage and edge-coverage as distinguishable phases when
   the service events provide enough information. Do not infer a backend phase
   solely from elapsed time or animation fill.
3. Keep cancellation available until the operation reaches a terminal state,
   and route it through the journaled cancellation path.
4. Use text in addition to color or illustration changes so progress and retry
   states remain accessible.
5. Never report “ready” from progress alone. The Linux operation is complete
   only after its existing terminal result, identity observation, Catacomb
   persistence, and E3 reconciliation requirements succeed.

The roughly 27-second duration, number of touches, exact wording, colors, and
fingerprint animation are examples from one macOS run. They are useful design
references, not constants to encode in the protocol or tests.
