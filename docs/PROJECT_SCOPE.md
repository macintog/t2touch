# Project scope requirements

These requirements apply to contributors, maintainers, and coding agents.
They are release requirements, not suggestions.

## Scope follows responsibility

T2Touch implements Apple T2 Touch ID support: the necessary transport and
biometric protocol, account-authorized fingerprint operations, fprintd/PAM
integration, and installation, diagnosis, recovery, and removal of that support.
A distribution adapter may configure the narrow authentication interfaces
needed by T2Touch. It is not permission to manage the distribution generally.

A problem discovered while installing, using, or testing T2Touch is not thereby
a T2Touch defect or feature requirement. General graphics selection, compositor
behavior, display-manager configuration, boot autologin policy, networking,
and unrelated desktop behavior belong to their respective components unless
a specific, necessary T2Touch dependency is established.

**MUST NOT bundle an unrelated repair into T2Touch, its default installer, or
its uninstaller merely because it helped one test machine or unblocked a test.**
Making such a repair optional or putting it in a separate T2Touch PR does not
by itself bring it into scope. A successful local workaround is evidence about
that machine, not authorization for a product feature or a compatibility claim.

## Required disposition of unrelated findings

**MUST NOT ignore an out-of-scope finding.** Give it a separate disposition:

1. Record the symptom, reproduction, evidence, affected component, and the
   distinction between confirmed cause and hypothesis. Exclude private data.
2. Place the repair or report with the appropriate upstream project,
   distribution, machine configuration, or standalone support artifact. State
   where it lives and whether it is local-only, reported, resolved, or pending.
   Do not claim an upstream report was filed unless it actually was.
3. Document any local workaround's files, ownership, verification, and rollback.
   Keep it separate from T2Touch installation and removal. A user's permission
   to repair their machine does not authorize distributing that repair.
4. Record any remaining T2Touch test or release limitation caused by the external
   problem. Refer to the separate disposition rather than importing its fix.

Do not silently change unrelated user policy to make testing easier. Preserve
expected behavior such as boot autologin. If a recovery action will trigger
that behavior, explain the effect before acting.

## Existing scope debt and lifecycle responsibility

Existing out-of-scope code is not automatically grandfathered. Identify it and
plan its separation. T2Touch remains responsible for ownership records and safe
cleanup or migration of changes its own installer previously made. That cleanup
must not adopt unrelated local repairs or delete subsequent user changes.

Moving an existing workaround out of T2Touch must account for machines relying
on it: document a standalone disposition and migration before removing support.
Do not turn a cleanup PR into a new distribution-management feature.

## Review and release gate

Every behavior-changing PR must explain:

- Which T2Touch requirement it serves and why each affected component is needed.
- Which files/settings T2Touch will own, and how upgrade, failure, and removal
  handle them without overwriting unrelated changes.
- Which observed problems remain external, with their separate dispositions.
- What was actually tested, and which release claims remain unverified.

Reviewers must reject unrelated implementation bundled into a T2Touch change.
A proposed scope expansion requires a deliberate, documented project-owner
scope decision before implementation; a general instruction to fix, finish,
test, or ship T2Touch is not that decision. This does not require repeated
approval for routine work already inside the agreed scope.
