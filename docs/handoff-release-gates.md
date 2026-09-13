# Native PoC release gates

This checklist controls the native handoff release. Creating an upstream-only fork
does not satisfy these gates. Do not publish native code, tag a native release, or
announce a completed result until the relevant proof is recorded and the operator
approves the exact candidate.

## Work that can proceed now

- [x] Preserve an identified upstream baseline and its history.
- [x] Define a finite research handoff and the absence of ongoing maintenance.
- [x] Record the initial source relationships and unresolved license finding.
- [x] Confirm the operator can license their own contributions.
- [ ] Complete the file-level inventory when the import set is available.
- [ ] Resolve dependency compatibility before blessing a runnable release.

The preparation documents can be reviewed privately while principal engineering
continues. They do not require changing the reference machine or its active task.

## Blocked on the engineering handoff

| Gate | Required evidence | Current state |
| --- | --- | --- |
| Select the source | Finished engineering commit, scoped import list, and handoff identifying remaining limitations | Blocked: final engineering revision not selected |
| Curate the implementation | Reviewable changes against the recorded upstream base; necessary source, build inputs, tests, and recovery tools | Blocked: depends on selected source |
| Reproduce the native path | Results from the exact candidate and a recorded starting state, with prerequisites, commands, hardware, firmware, and outcomes | Blocked: candidate does not exist |
| Prove persistence and matching | Named restart transition, restored authority and fingerprints, positive and negative matching controls | Blocked: candidate evidence required |
| Describe recovery accurately | Candidate-specific cancellation and interruption evidence; distinction between uninterrupted success and recovered outcomes | Blocked: final behavior and evidence required |
| Finish reader documentation | Runnable reproduction guide, architecture/protocol explanation, evidence table, and integration map | Blocked: exact commands and claims depend on engineering |

Existing research observations are leads for the final evidence record. Do not copy
a prior PASS to a different tree or imply that documentation checks validate hardware.
Use existing evidence only when its revision and tested behavior apply to the candidate.

## Blocked on publication review

- [ ] Complete the provenance inventory and required notices, including resolution of
  the pymobiledevice3 finding. Record the decision and its evidence.
- [ ] Review the complete proposed public history and artifacts for private state,
  credentials, machine identifiers, private paths, and unredistributable material.
- [ ] Check public prerequisites and dependencies from the candidate itself. An
  internal installation or source checkout is not the public reproduction environment.
- [ ] Review inherited README, SECURITY, roadmap, CI, and installation claims so they
  cannot be mistaken for guarantees about the native handoff or ongoing support.
- [ ] Record candidate commit, tree hash, validation results, limitations, and reviewed
  artifact hashes. Complete relevant upstream checks at the release gate.
- [ ] Obtain approval to publish that candidate and its release text. Confirm that the
  pushed public commit and any release artifacts match the approved identities.

This preparation pass changes documents only. It does not select a license remedy,
run hardware tests, enable authentication, send announcements, or publish native code.

## After delivery

Prepare a concise handoff message for relevant projects. Send it only after approval
of the recipients and text. Do not promise review, integration, or support on behalf
of another maintainer.

Clarification may remain available after publication, without a response commitment.
The channel, duration, and eventual archive decision remain open. No reminder,
monitor, or automatic archive action is authorized by this checklist.

Delivery is complete when another engineer can reproduce, understand, and legally
reuse the published work. A merged PR, recruited successor, supported package, and
future maintenance are outside that completion boundary.
