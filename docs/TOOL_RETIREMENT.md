# Retiring obsolete installed tools

Upgrades and uninstall archive recognized obsolete research executables before
removing their copies from `/usr/local/sbin`. Locally modified or unknown files
are preserved and reported. This prevents stale implementations from remaining
on PATH without treating a familiar filename as proof of ownership.

## Installed locations

Maintained research launchers live under `/opt/t2-touchid/bin` and execute
canonical source under `/opt/t2-touchid/src`. This includes native enrollment,
matching, provisioning, replacement, and the second-finger ceremony. Product
fprintd workers continue to use the canonical source directly.

The fixed-purpose `t2-native-enroll-verify` test-credential helper and the
`t2-xart-mmio-discriminator` and `t2-xart-post-repair` forensic tools have no
replacement PATH installation. Historical research source remains available;
these tools are not ordinary authentication or recovery interfaces.

Active administrative tools and fprintd workers are outside this retirement
list. Desktop commands are documented in [command migration](COMMAND_RECONCILIATION.md).

## Recognition and provenance

[`tools/retired-tools.json`](../tools/retired-tools.json) lists 29 recognized
tool names and their exact source-executable SHA-256 values. Entries retain
source paths and historical Git blob identifiers for provenance; these are
executable hashes, not biometric identifiers. One explicitly inspected deployed
matcher variant is also recognized. No other local edit is accepted by name
or similarity. A provenance blob need not be present in a public snapshot;
recognition uses the recorded content hash and filesystem ownership checks.

## Migration and failure behavior

`python3 tools/retire-path-tools.py` is an audit only. It reports only manifest
paths that exist and classifies recognized bytes or ownership/content conflicts.
`sudo python3 tools/retire-path-tools.py --apply` performs retirement:

1. Validate the PATH directory and ancestors, rejecting symlinks or writable
   untrusted locations. Accept only root-owned, singly linked regular files
   without group/other write permission and with a recognized content hash.
2. Copy exact bytes to
   `/var/lib/t2-touchid/retired-tools/SHA256/ORIGINAL-NAME`, preserving a
   non-executable, root-private copy. Never overwrite an existing archive.
3. Flush the archive and directory entries, recheck the source inode and
   content, then unlink only the recognized original PATH copy.
4. Report the archival destination. Repeated runs are safe: absent paths are
   skipped; a complete existing archive can finish interrupted retirement;
   conflicting/partial archived bytes stop removal and preserve both copies.

Unknown edits, ownership changes, symlinks and hard links are preserved and
reported. They do not block upgrading the active stack. There is deliberately
no force-delete option. Review conflicts individually; do not whitelist a file
merely because it has an expected name. For a partial archive, retain it under
a separate evidence name after inspection before retrying; never discard it
silently.

Upgrade stages off-PATH replacements before retirement. Those launchers use
isolated project Python and execute the canonical `/opt/t2-touchid/src` file,
so sibling imports and runtime dependencies resolve as they do for the worker;
they do not create another copy of research Python code in `bin`. Uninstall invokes the
same manifest-driven helper and removes the recognized retired names from its
old unconditional unlink loop. Archives survive uninstall alongside the
existing retained product state. The code never opens credentials, Catacombs,
mutation journals, or hardware devices and does not restart services.

Rollback, if a specific research interface is still needed, should normally
use the maintained off-PATH replacement. An administrator can restore archived
bytes explicitly to their former path with root ownership and mode 0755 after
checking that no newer file occupies it. Restoration recreates the old research
behavior and is not a recommendation to execute it. Do not restore obsolete
forensic tools as automatic recovery fallbacks.
