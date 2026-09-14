# Service-interface audit

The current audit target is greenfield Linux-native installation and operation.
The completed scope and hardware boundary are summarized in the
[integration follow-up](research/integration-followup.md); current source is
authoritative for the implemented interfaces.
The D228 matrix below primarily records compatibility work; its passing checks
do not establish native end-to-end completion. This document does not authorize
a hardware command by itself.

## Native interface audit

This table records the completed source-to-service review. "Integrated" means
the source and installed callers are connected and their focused offline gates
pass. The reference-machine greenfield hardware demonstration has also passed;
remaining limitations are stated explicitly below.

| Boundary | Implemented owner and contract | Status and remaining evidence |
| --- | --- | --- |
| Fresh install -> first-run setup | `install.sh` selects native on a fresh config, requires one protected encrypted credential only for truly blank state, and installs `t2-native-first-run.service`. `t2-native-first-run.py` owns blank create, different-boot legacy verification, schema-2 activation-bundle publication, independent activation, and steady-state authority validation. The unit is ordered before biometric readiness so their shared operation lock cannot race at boot. | Blank create through independent activation and stock-client empty inventory passed live. Prior state remained preserved and unused. The enrollment-persistence reboot proved first-run then readiness then post-reboot then fprintd without manual retry. |
| Setup -> native identity/activation owner | First-run dispatches the exact acknowledged provision, provision-verify, absence/replacement, and replacement-activation owners. It validates redacted typed results and deliberately fails each creation boot so consumers cannot cross either same-boot boundary. Exact schema-2 `mapping-committed` state routes to credential-free fresh-boot recovery. Child failures expose only a bounded printable final error detail. | Identity create, different-boot provision verification, durable schema-2 bundle/mapping commit, fresh-boot handle-absence reconciliation, and independent activation passed live. Mapping is enabled and first-run reports `mapping-ready`. |
| Service/worker -> AKS/ACM lifetime | `t2-sep-transport-load.sh` gives normal native service loads endpoint-7 OOL, capability probing, ACM, exact platform metadata, and typed state-derived one-shot provisioning/replacement gates. `t2-native-transport-gates.py` validates mapping and journal phases instead of grepping schema text. First-run, post-reboot, and deletion services receive `/dev/t2-aks`, `/dev/t2-acm`, `CAP_SYS_ADMIN`, and `CAP_IPC_LOCK`. | Live bundle creation had both gates. A recovery boot exposed and repaired the schema-2 gate drop; the installed resolver returned exact recovery gates `0 1`, completed, and released both devices. The later complete-state boot derived `0 0` and independently reactivated for E4. |
| Empty native state -> first enrollment | `T2Backend.enrollment_projection()` permits only the exact empty, mapping-enabled pre-E4 state. It and the detached worker share `native_enrollment_context()`; verify remains E4-only. | Circular prerequisite, empty inventory, and first stock `fprintd-enroll` are live-proven. Seven monotonic progress transitions reached completion without replacing prior state. |
| fprintd -> native inventory/match | The empty pre-E4 projection returns `NoEnrolledPrints`; after E4, list, numbered/`any` verify, enroll, and delete all use the same neutral runtime projection. Every verify request accepts the complete enrolled set and reports the identity that actually matched. | Stock listing and positive/negative verification passed with the reconciled multi-fingerprint set after E4 and rolling-BioLockout synchronization. |
| Reboot -> native reactivation | `t2-touchid-post-reboot.py` dispatches native journals to `t2_native_post_reboot_reconciler`, which pins the journal caller UID and invokes the proven activation-aware enrollment or management verifier. `fprintd.service` hard-requires successful first-run, readiness, and post-reboot units. Interrupted post-E4 host publication is a separate lock-protected recovery that never reruns hardware proof, and failure diagnostics expose only bounded allowlisted stage metadata. | Unattended startup, native activation, E3-to-E4 append, protected authority publication/readback, and subsequent fprintd start passed live. The interruption recovery and diagnostics pass focused offline contracts and await later deployment, not another reboot. |
| fprintd -> add/delete workers | The caller-bound workers retain one set/origin-neutral projection. Native and compatibility enrollment use the same lock-held five-slot allocator: retained handles never move and the next completed enrollment takes the lowest vacancy. Final-identity and bulk deletion remain refused. | Installed standard first/add enrollment, named deletion, survivor verification, durable label persistence, and later-boot closure passed live. |
| PAM/sudo -> native fprintd | `t2-pam-fingerprint-ready.sh` dispatches native mode to `t2_native_pam_ready.py`, which requires exact E4 authority, verify capability, same user, and no blocking mutation. Compatibility markers are not consulted. | Installed readiness passed; real `sudo -v` accepted an enrolled fingerprint. With fprintd runtime-masked, the same stack timed out biometric verification and accepted the normal Linux password, then fprintd was restored. |

Do not rerun the unchanged passing compatibility suite to fill these gaps.
Use the smallest check tied to the actual native implementation change, under
the repository's test-worker rules. Verify installed parity separately from
source correctness and hardware results.

## Historical D228 compatibility authority rule

The selected Linux user has one Catacomb and one fingerprint inventory.
Compatibility authority describes how that whole-user state is activated; it
does not tag individual fingerprints by origin. Preserved fingerprints and
fingerprints enrolled from Linux are projected, matched, renamed, and deleted
through the same canonical identity list.

## Historical D228 interface matrix

| Boundary | Contract audited | Lifetime and cleanup | Status |
| --- | --- | --- | --- |
| systemd -> keybag loader -> `/dev/t2-aks` | Operation `0x03` loads the canonical user keybag in session 1; operation `0x0d` binds its positive handle to the derived negative Apple-user alias. Requests and replies have exact kernel-enforced sizes. | Both calls share one tool descriptor. The kernel retains only the validated runtime handle and alias after close. | Static contract complete; load/bind hardware-proven. Alias-bind reply capacity tightened to the exact four-byte status. |
| credential unit -> AKS unlock | One encrypted credential read unlocks the positive handle and negative alias with two operation-`0x04` calls. | Both calls now share one descriptor and one locked secret buffer; the buffer is explicitly wiped before exit. Readiness is published only if the keybag snapshot remains byte-identical. | Defect found and repaired in this audit. Previous service code used two helper processes and two credential reads. |
| transient fprint worker -> password/ACM binder | Compatibility enrollment first verifies password fallback against the positive handle, then binds the same credential and exact 16-byte ACM context to the special alias. | Credential exists only in the root transient worker and child tool, is absent from argv/output, and is wiped. ACM contexts are closed in reverse order with ambiguous cleanup reconciled after device close. | Static contract complete; component operations hardware-proven. |
| worker -> `/dev/t2-acm` | Create, policy, externalize, identity-secret, and delete exchanges use command-specific exact capacities and generation-bound context state. | One ACM descriptor owns the full context lifecycle. Kernel and user space poison ambiguous generations and refuse reuse. | Static contract complete; lifecycle hardware-proven. |
| fprintd projection -> Bridge/Mesa -> Catacomb | The mutable canonical Catacomb is restored only from a cold loadable state, then live and local identity sets must match exactly. An already-matching live set is left untouched. | One Bridge generation owns preparation and inventory. Any rejected or malformed command stops without retry. | Static contract complete. Command-`0x40` failures now report operation, stage, reply shape, status, and output length without payload disclosure. Current retained SEP generation is exhausted and must not be retried. |
| fprintd -> enrollment worker | D-Bus caller, account/session, PolicyKit grants, runtime and protected mapping generations, boot UUID, and Bridge generation are reconstructed and revalidated before the first mutation. Client anatomy tokens are request syntax only; the authorized worker allocates the next durable neutral handle. | A root-private seqpacket and pidfd bind the transient worker; cancellation waits for a journaled terminal outcome. | Standard first and additional enrollment passed live, including cancellation/no-change recovery and same-boot validation of the added identity. |
| fprintd -> deletion worker | A numbered handle resolves against the same fresh inventory regardless of fingerprint origin. A final named identity may produce an empty inventory; batch delete-all remains unexposed. | The same worker, authorization, authority-generation, journal, and recovery rules apply as enrollment. | Stock named deletion, final-identity forward recovery to clean empty state, survivor verification, and later-boot closure passed live. |
| reboot -> post-reboot reconciler | Compatibility journals are selected against the derived in-memory compatibility authority; native journals dispatch to their activation-aware verifier. Both paths revalidate account, mapping, local/live state, and the exact eligible journal before appending only typed terminal proof. | Read-only operation lock and one Bridge generation; no credential or mutation entry point. | Automatic native enrollment, deletion, and rename closure passed live before fprintd startup. |
| PAM/sudo -> fprintd | PAM checks the exact boot readiness snapshot, prompts for touch before password input, accepts fprintd success as sufficient, and retains the normal password stack as fallback. | No password is passed through fprintd. Failure or timeout falls through to ordinary sudo authentication. | Installed sudo fingerprint success and forced-biometric-unavailable password fallback both passed live. |

## Historical D228 deployment and recovery boundary

The recovery plan in this section is superseded. It records the state at D228
and does not direct another compatibility load or reset. Reconcile live state
before planning native work; the unresolved compatibility rejection is not a
prerequisite to completing the native source/service audit.

No source-to-installed drift was found in the active unit and helper set before
these repairs. The repaired sources must be compiled, tested, installed, and
rechecked for byte parity before another device attempt. The next device work
must begin in a fresh SEP component generation; the current generation already
returned command-`0x40` status 257 after the T2 SMC reset and is not reusable.
No shutdown is authorized by this audit.

The base oneshot requires only common biometric readiness; compatibility's
fprintd authority drop-in starts the keybag-load and credential units, and the
oneshot is ordered after them without pulling them into native mode.

The explicit native verifier still owns E4 activation and ACM authorization;
the generic oneshot now dispatches to it instead of widening the compatibility
implementation. Its systemd sandbox supplies the audited AKS/ACM devices and
capabilities. The remaining boundary is installed parity and greenfield live
evidence, not another compatibility repair.
