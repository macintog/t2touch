# t2touch documentation

Start with the [project README](../README.md) for installation and everyday
fingerprint management.

| Document | Purpose |
| --- | --- |
| [Troubleshooting](TROUBLESHOOTING.md) | Installer stops, deletion recovery, graphical prompts, and rollback. |
| [First-run recovery](FIRST_RUN_RECOVERY.md) | What to do after an installer stop that requires reboot or relogin. |
| [Delete recovery](DELETE_RECOVERY.md) | Resume or recover an interrupted fingerprint deletion. |
| [Security](../SECURITY.md) | Authentication authority, credential storage, fallback, and private reporting. |
| [Architecture](ARCHITECTURE.md) | Runtime ownership, persistent state, and security boundaries. |
| [fprintd integration](FPRINT_INTEGRATION.md) | D-Bus clients, caller authorization, enrollment, matching, and deletion. |
| [Administration](ADMINISTRATION.md) | Product command scope and the macOS `bioutil` comparison. |
| [Compatibility](COMPATIBILITY.md) | Hardware and protocol portability, tested scope, and evidence for new models. |
| [Prepared-identity measurements](evaluations/touchid-prepared-identity-2026-09-17.md) | Current reader-readiness gains, repeated-touch correctness, hardware controls, and validation limits. |
| [Worker-overlap measurements](evaluations/touchid-responsiveness-worker-overlap-2026-09-17.md) | Measured retry-readiness improvement, memory cost, and remaining authorization latency. |
| [Sleep policy](SLEEP_POLICY.md) | Retiring the legacy sleep override, ownership, and suspend qualification limits. |
| [Tool retirement](TOOL_RETIREMENT.md) | Ownership-checked cleanup of obsolete installed commands and archival rollback. |
| [Disposition: T2 transport after deep sleep](dispositions/t2bce-stateful-resume-bulk-out.md) | Reported driver failure, external fix proposals, recovery guidance, and qualification limits. |
| [Terminal clients](TUI_CONTROL.md) | Contributor tools for exercising the installed service and native backends. |
| [T1Bridge reference](T1BRIDGE_REFERENCE.md) | Relevant external designs and the differences that matter on T2. |
| [Protocol research](https://github.com/macintog/t2-platform-research/blob/423d2b056b69764876097818b3efc74319a7f944/docs/sep/README.md) | SEP, AKS/ACM, storage, and fingerprint lifecycle. |
| [Sources and credits](PROVENANCE.md) | Implementation provenance, dependencies, and licenses. |

See [Contributing](../CONTRIBUTING.md) for development checks and hardware
reports, and the [roadmap](../ROADMAP.md) for support gaps.

Project governance: [mandatory scope requirements](PROJECT_SCOPE.md).
