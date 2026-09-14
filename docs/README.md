# t2touch documentation

For installation and everyday fingerprint management, start with the
[project README](../README.md). t2touch is an experimental Omarchy integration
validated on one MacBookPro16,1. Named deletion includes the final fingerprint;
password authentication remains available.

## Product and contributor reference

| Document | Purpose |
| --- | --- |
| [Architecture](ARCHITECTURE.md) | Runtime ownership, persistent state, and security boundaries. |
| [fprintd integration](FPRINT_INTEGRATION.md) | Caller authorization, enrollment, matching, and deletion contracts. |
| [Service interfaces](SERVICE_INTERFACE_AUDIT.md) | Installed service responsibilities and reconciliation. |
| [Compatibility](COMPATIBILITY.md) | Existing Apple authority and additional hardware evidence. |
| [Internal components](DEVELOPMENT_STATUS.md) | Mapping, broker, activation, and research-only interfaces. |
| [Terminal clients](TUI_CONTROL.md) | Installed TUI and contributor test launchers. |
| [Validation record](RELEASE.md) | Recorded acceptance and limits of the tested installation paths. |
| [Roadmap](../ROADMAP.md) | Product capabilities and remaining support gaps. |
| [Contributing](../CONTRIBUTING.md) | Development checks and evidence requirements. |
| [Upstream boundaries](UPSTREAMING.md) | Component boundaries for future maintainer review. |

## Research and provenance

The [research reference](research/README.md) explains the recovered protocols
and is shared with the MIT-licensed t2touch-mini. The
[reference-platform log](REFERENCE_PLATFORM.md) and
[upstream comparison](UPSTREAM_STATUS_RECONCILIATION.md) retain dated evidence;
they do not replace the current installation instructions.

[External protocol comparisons](EXTERNAL_RESEARCH_WATCH.md),
[T1Bridge analysis](T1BRIDGE_REFERENCE.md), and
[sources and credits](handoff-provenance.md) record provenance and licensing.
[Bring-up troubleshooting](LINUX_BRINGUP_TROUBLESHOOTING.md),
[suspend observations](SUSPEND_REPORT.md), and the
[historical PAM issue](OMARCHY_PAM_PRIVILEGE_MISMATCH.md) describe specific
failure modes, not extra steps in normal installation.
