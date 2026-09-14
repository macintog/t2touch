# Installed service interfaces

The installed Linux-native service chain was demonstrated on MacBookPro16,1.
The [validation record](RELEASE.md) separates those results from untested
installation and hardware combinations. Detailed caller and transaction
contracts are in [fprintd integration](FPRINT_INTEGRATION.md).

| Boundary | Contract |
| --- | --- |
| Installer to kernel prerequisites | Compare the resident transport with the build before installed-state changes. Require the live applesmc boot-state publisher; stage the packaged prerequisite and stop if absent. |
| First-run to native authority | Create only on blank authority, preserve the activation bundle and account mapping, and independently activate through a fresh owner before enabling the mapping. Existing authority is never silently replaced. |
| Service to AKS/ACM | The native transport loader owns endpoint registration and derives provisioning/replacement gates from typed mapping and journal state. Device descriptors and ACM contexts have exclusive, bounded lifetimes. SEP-pinned DMA is never hot-unbound. |
| Readiness to fprintd | First-run, biometric readiness, and post-reboot reconciliation precede fprintd. Interrupted operations block exposure until reconciled. |
| Empty inventory to enrollment | One enabled native account may enroll its first fingerprint without an existing fingerprint authority. Persistence, fresh-owner verification, and authority publication precede successful completion. |
| fprintd to inventory and match | List, verify, enroll, and delete share one reconciled neutral inventory. Any enrolled fingerprint can satisfy verification; a requested name is not an anatomical constraint. |
| fprintd to mutation workers | D-Bus sender, active local session, PolicyKit grant, pidfd, account and mapping generation remain bound across the transient worker handoff. The lock-held allocator uses the lowest vacant slot and never renumbers survivors. |
| Named deletion to persistence | Resolve one name against fresh inventory, journal before dispatch, then reconcile the exact survivor set or a clean empty inventory. Recovery never repeats an ambiguous SEP deletion. Batch deletion is not exposed. |
| Restart to reconciliation | Reactivate the selected authority and reconcile eligible journals before fprintd starts. A completed hardware proof whose host publication was interrupted is recovered without replaying the hardware operation. |
| PAM to fprintd | Require current native authority and an unblocked inventory. Fingerprint success and independent password fallback were tested separately. |

## Compatibility authority

Compatibility and Linux-native authority select how a whole user's identity is
activated; they do not distinguish individual fingerprints by origin.
Compatibility startup uses the imported keybag and optional encrypted credential
services. Native startup uses its Linux-owned activation bundle.

The compatibility keybag loader retains one AKS descriptor across load and alias
binding. Credential unlock retains one descriptor and one locked secret buffer
across the required positive-handle and alias operations, then wipes the buffer.
Native services do not inherit compatibility-only keybag prerequisites.

Compatibility code remains available, but there is no supported end-user
migration command for existing macOS Touch ID state. Multi-user operation,
deep-sleep recovery, and cross-macOS persistence remain outside the proven
product scope.
