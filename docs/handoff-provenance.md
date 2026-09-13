# Handoff provenance inventory

Status: preliminary inventory, reviewed on 2026-09-13. This is not a completed
license audit or a substitute for required copyright and license notices.

The starting tree is upstream commit
[`ea46d8a0aef3e73b0e2f747aa18721dbcd265bce`](https://github.com/jmurth1234/t2-touchid-linux/commit/ea46d8a0aef3e73b0e2f747aa18721dbcd265bce).
Its Git tree is `82afdb2969afb1578f3f58801c6dd9df3aa22bcc`.
The native engineering revision for import is not yet selected.

## Known sources

| Source | Relationship | Evidence and remaining work |
| --- | --- | --- |
| [jmurth1234/t2-touchid-linux](https://github.com/jmurth1234/t2-touchid-linux) | Inherited source and history | The repository declares GPL-2.0-only. Preserve its license, authorship, source notices, and the syscall-note exception on the userspace transport header. Map retained and modified files in the final import. |
| [T1Bridge at 7003b8d9f791](https://github.com/standardagents/t1bridge/tree/7003b8d9f791) | Recorded reference for later native engineering | Its [top-level license at this revision](https://github.com/standardagents/t1bridge/blob/7003b8d9f791/LICENSE) is MIT. Earlier research notes calling the entire project GPL-2.0-only are incorrect. Inspect each adapted file and its notices at the revision actually used. No native adaptation has been imported here. |
| [pymobiledevice3 at 4fcfdd82ffcf30b6a11460b505fadb5579e7b2bb](https://github.com/doronz88/pymobiledevice3/tree/4fcfdd82ffcf30b6a11460b505fadb5579e7b2bb) | Pinned upstream dependency | Its [license file](https://github.com/doronz88/pymobiledevice3/blob/4fcfdd82ffcf30b6a11460b505fadb5579e7b2bb/LICENSE) contains GPLv3. The GPL-2.0-only discovery helper imports its RemoteXPCConnection class. Compatibility is unresolved; see below. |
| [python-dbus-next v0.2.3](https://github.com/altdesktop/python-dbus-next/tree/v0.2.3) | Pinned upstream dependency | Its [license](https://github.com/altdesktop/python-dbus-next/blob/v0.2.3/LICENSE) is MIT. Review any bundled copy and preserve required notices. |

The pins above identify inspected material. They are not recommendations to update
dependencies or statements that every file in a project has the same license.

## Open compatibility finding

[`requirements.txt`](../requirements.txt) pins pymobiledevice3. The GPL-2.0-only
[`discover-biometric-port.py`](../src/discover-biometric-port.py) directly imports
`pymobiledevice3.remote.remotexpc.RemoteXPCConnection` in `main_async`.
This is a concrete dependency relationship, not merely a bibliography entry.

GPLv2-only and GPLv3 are not generally compatible for a combined program. The
[GNU licensing FAQ](https://www.gnu.org/licenses/gpl-faq.html#v2v3Compatibility)
explains the distinction from GPLv2-or-later. This inventory does not decide the legal
classification of the complete distribution or establish an exception.

Before release, determine the license of the exact imported modules, check for any
applicable permission or exception, and map their use in the final native path.
Resolve the relationship through a supported licensing or implementation decision.
Separate installation, credit, or an existing public upstream release is not sufficient
evidence to close this finding. Do not relabel inherited code or replace dependencies
as a documentation cleanup.

## Inventory required at import

For each copied or adapted component, record the source URL, full revision, original
path, destination path, applicable license and exceptions, copyright notices, and
nature of the modifications. Distinguish runtime dependencies from vendored code and
research-only references. Trace generated code to its inputs.

Review the kernel/transport ancestry, local dependency patches, fixtures, diagrams,
documentation excerpts, and any proposed binaries. Apple binaries and private user,
keybag, or biometric state are excluded from this handoff.

The broader research crosswalk includes KAIT2EN, BrettKulp's T2 work, Asahi/Hoolock,
and other protocol references. Their appearance in research notes does not establish
that their code is shipped. Add final entries only with a specific relationship and
source. Keep intellectual acknowledgments distinct from redistribution notices.

The operator confirms that their contributions are personal work and require no
employer or client permission to publish under GPL-2.0-only. That confirmation does
not grant permission to relicense anyone else's code.

Retain the existing [LICENSE](../LICENSE). Add required third-party notice text when
the included material is known; do not invent a blanket authorship declaration.
