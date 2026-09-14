# Re-enrollment after an interrupted deletion

A deletion can reach SEP before its response is accepted or local persistence
finishes. In that state the deletion reports failure, the local archive still
lists the finger, and further enrollment must wait for reconciliation.

Update to the corrected source and run the ordinary installer:

```bash
git pull --ff-only
./install-omarchy.sh
```

Startup selects one interrupted deletion only when no other mutation is pending.
The existing recovery owner reads the exact recorded identity and a fresh SEP
inventory, then finishes persistence or proves no change. It never resends the
delete command. No recovery reboot is imposed. Do not remove private journals,
credentials, or the identity mapping to make enrollment proceed.

The deletion adapter also accepts well-formed asynchronous service notifications
instead of discarding their command reply. Stable target-absence and survivor
checks still determine deletion success. Worker failures retain an identifier-
free exception type chain for diagnosing any later transport failure.
