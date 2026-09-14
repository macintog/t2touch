# t2touch publication handoff

The product path is intentionally small:

```bash
./install-omarchy.sh
t2touch enroll
```

Installation prepares and starts the complete Touch ID stack in the running
Omarchy session. Enrollment returns success only when the fingerprint has been
persisted and published for immediate standard fprintd authentication. No reboot,
manual research phase, or acknowledgement flag belongs in the normal workflow.

Users manage one origin-neutral inventory through `t2touch status`,
`t2touch enroll`, `t2touch verify`, and `t2touch delete`. Password
authentication remains available. The installer owns reversible PAM changes,
and uninstall restores them.

The native lifecycle was hardware-proven from blank state on the MacBookPro16,1.
Current release work is packaging, automated validation, privacy review, and
publication—not additional hardware bringup.
