# t2touch documentation

Start with the [project README](../README.md) for installation and everyday
fingerprint management.

| Document | Purpose |
| --- | --- |
| [Troubleshooting](TROUBLESHOOTING.md) | Installer stops, deletion recovery, graphical prompts, and rollback. |
| [Graphical validation](GRAPHICAL_AUTH_VALIDATION.md) | Readiness timing, actual lock/Polkit results, portable GPU selection, and test limits. |
| [Security](../SECURITY.md) | Authentication authority, credential storage, fallback, and private reporting. |
| [Architecture](ARCHITECTURE.md) | Runtime ownership, persistent state, and security boundaries. |
| [fprintd integration](FPRINT_INTEGRATION.md) | D-Bus clients, caller authorization, enrollment, matching, and deletion. |
| [Administration](ADMINISTRATION.md) | Product command scope and the macOS `bioutil` comparison. |
| [Compatibility](COMPATIBILITY.md) | Hardware and protocol portability, tested scope, and evidence for new models. |
| [Terminal clients](TUI_CONTROL.md) | Contributor tools for exercising the installed service and native backends. |
| [T1Bridge reference](T1BRIDGE_REFERENCE.md) | Relevant external designs and the differences that matter on T2. |
| [Protocol research](research/README.md) | SEP, AKS/ACM, storage, and fingerprint lifecycle. |
| [Sources and credits](PROVENANCE.md) | Implementation provenance, dependencies, and licenses. |

See [Contributing](../CONTRIBUTING.md) for development checks and hardware
reports, and the [roadmap](../ROADMAP.md) for support gaps.
