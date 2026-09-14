# Reference platform log

This project is being brought up on one physical machine. Results describe
this exact configuration only; they are not a compatibility claim for other T2
Macs or bridgeOS versions.

## Current observed state — installed acceptance, 2026-09-14

The reference machine has two reconciled Linux-native fingerprints under D200
E4 authority. D204/D205 prove native positive and negative matching. D217
proves exact one-identity deletion and different-boot survivor verification.
D218 proves one continuous same-boot existing-finger check, explicit
Add/Finish choice, candidate no-match, second-finger capture and persistence,
fresh-generation exactly-one addition, E3 reconciliation, and immediate
new-identity-only match. The final enrollment journal is
`addition-verified`; all four activation leases ended ready and both hardware
nodes were unheld. The immutable artifact/read-only snapshot is
`D218-continuous-second-finger-ceremony-20260913`, manifest
`52f960e06e35e462326c89109597c586b6bd5d3376fa91011d2a93660eb6dd25`.

The installed fprintd/libfprint/PAM path is enabled. Unattended startup,
standard first and additional enrollment, origin-neutral list/match/rename/
single deletion, later-boot reconciliation, sudo fingerprint authentication,
and independent password fallback have passed. Current inventory is
`finger-1`, `finger-2`, and `finger-4` under the historical allocator; all mutation journals
are closed, and both hardware devices are unheld. No further enrollment is
needed for acceptance.

## Machine

| Field | Value |
| --- | --- |
| Mac model | MacBookPro16,1 |
| Board | Mac-E1008331FDC96864 |
| T2 product | iBridge2,14 |
| T2 board configuration | J152fAP (`j152f`) |
| T2 board code | `0x3A` |
| bridgeOS | 10.6 build `23P6068` |
| Distribution | Omarchy 4.0.2-1 |
| Kernel | 7.1.8-arch1-Watanare-T2-3-t2 |
| BCE stack | `t2bce_core`, `t2bce_dma`, `t2bce_vhci`, `t2bce_audio` |
| SEP PCI function | 106b:1802 present and initially unbound |
| T2 controller | 05ac:8233 exposed through `t2bce_vhci` and `cdc_ncm` |
| Host storage | LUKS2/Btrfs plus a 64 GiB-class APFS macOS coexistence partition |
| Private macOS input | None at baseline; one clean macOS user and one Touch ID identity now exist only as a comparison oracle |

Do not add network addresses, MAC addresses, account names, device serials,
identity UUIDs, keybag handles, or raw protocol replies to this file.

The machine was genuinely macOS-free for the baseline observations below.
After D038, macOS was installed into the bounded APFS partition and Touch ID
was enrolled once. Preserve the clean-wipe results as historical evidence, but
describe the current hardware as macOS-provisioned; it is no longer a clean
wipe and must not be used to claim an out-of-box Linux provisioning result.

The Mac host, T2 hardware identity, bridgeOS, and an inspected macOS RecoveryOS
are separate version axes. A RecoveryOS binary is static host-side protocol
evidence; it is not the T2 machine, its bridgeOS image, or proof that the same
ABI is active on the installed firmware.

## Evidence levels

- **E0 — hardware-free:** unit tests, userspace build, shell syntax, and privacy
  checks.
- **E1 — transport:** module build/load, bounded read-only capability query,
  and diagnostic health.
- **E2 — bridge:** T2 network reachability, RemoteXPC discovery, and stable
  read-only inventory.
- **E3 — verification:** enrolled-finger and unenrolled-finger controls at raw,
  fprintd, and PAM layers, with password fallback retained.
- **E4 — lifecycle:** cold boot, cancellation, lockout, kernel update, and
  suspend/resume.
- **E5 — mutation:** explicitly acknowledged enrollment, rename, or deletion
  with journal recovery and post-reboot reconciliation.

## Observations

### 2026-08-31 — Baseline

- E0 passed at upstream commit `55d6e70`: 512 Python tests, userspace AKS build
  with warnings as errors, Bash syntax, and both privacy scans.
- The T2 BCE, audio, keyboard/trackpad, Touch Bar, and CDC-NCM devices enumerate.
- The T2 CDC-NCM interface has no carrier or IPv6 address, so E2 is not yet
  established.
- No macOS-derived keybag or enrolled-user export exists. E3 and above are
  blocked until Linux-native user/keybag provisioning is implemented and
  validated. Importing Apple state is not the target for this machine.
- The SEP transport and userspace AKS tool build successfully against the
  running Watanare T2 kernel. The module metadata matches PCI function
  106b:1802 and kernel `7.1.8-arch1-Watanare-T2-3-t2`.

### 2026-08-31 — Endpoint-7 transport bring-up

- An observation-only load bound PCI function 106b:1802 and reported healthy
  mailbox inbox/outbox state without registering DMA buffers. It unloaded
  cleanly before the active test.
- Loading with `register_ool=1 probe_capabilities=1` registered the two 16 KiB
  endpoint-7 out-of-line buffers and created `/dev/t2-aks` with mode `0600`.
- Both the load-time read-only capability probe and an explicit
  `t2-aks-tool capabilities` request timed out with `-ETIMEDOUT` (`-110`). No
  IOMMU/DMA fault or network watchdog event was observed.
- The registered module is deliberately left loaded until reboot because its
  DMA lifetime makes runtime unload unsafe. E1 is therefore partial: PCI,
  mailbox discovery, endpoint registration, and the UAPI device work, but an
  endpoint-7 request/reply has not completed.

### 2026-08-31 — v1-first replacement boot

- A later reboot loaded the corrected installed DKMS image; its live build ID
  matches the module under the kernel's DKMS updates directory and its source
  version is `4BC16341140F7FD6189ED91`.
- Endpoint-7 and endpoint-10 OOL registration completed and both root-only
  device nodes appeared. Automatic capability probing was explicitly off, so
  this boot produced no endpoint-7 application request.
- The four authentication/provisioning services stayed disabled and inactive,
  and PAM remained untouched. No identity result is claimed from this boot.

### 2026-08-31 — Local installation

- The first install found that Arch/Omarchy does not create
  `/etc/dbus-1/system.d` by default. The installer now creates it before writing
  the fprintd policy, with a hardware-free regression test.
- A second install completed, and DKMS built and installed the transport for
  the running kernel. The live manually loaded module predates that DKMS build,
  so its build ID will differ until reboot.
- The health report now rejects example placeholder addresses and distinguishes
  absent provisioning artifacts from permission failures.
- At install time, all five runtime services remained disabled and the T2
  network had no carrier. The private keybag, encrypted credential, runtime
  handles, and biometric port cache were absent.

### 2026-08-31 — Bridge network and read-only inventory

- Assigning the documented link-local address did not overcome the initial
  `NO-CARRIER` state. Unbinding and rebinding only the T2 controller's
  `cdc_ncm` interface immediately restored carrier without disturbing the
  other BCE devices.
- The link-local address is now held by a dedicated NetworkManager connection.
  ICMP reachability and dynamic RemoteXPC service discovery both pass.
- BridgeXPC negotiation reports bridgeOS `23P6068`, BridgeXPC 39, a bridge API
  maximum of 3, and successful client negotiation at version 2.
- Two complete read-only inventory passes were byte-stable. Capacity and lock
  state calls returned structurally valid replies, but identity lists were nil,
  the standalone biometric protocol query was rejected, and no complete
  private inventory could be attested without the user's keybag/Catacomb.

E2 is partial: network, service discovery, BridgeXPC negotiation, and stable
read-only commands work, while user-scoped identity reconciliation does not.

### 2026-08-31 — Installed-build reboot validation

- The DKMS transport loaded automatically and its GNU build ID matched the
  installed image. Endpoint-7 registration succeeded and `/dev/t2-aks` was
  recreated.
- One explicit read-only capabilities request reached the host mailbox but SEP
  sent no reply. The diagnostic state was: no unrelated messages, inbox empty,
  and outbox not full. This narrows the failure to SEP acceptance/readiness or
  request framing rather than host mailbox backpressure.
- The initial CDC-NCM `NO-CARRIER` state reproduced. The same isolated driver
  rebind restored carrier, after which NetworkManager reapplied the link-local
  profile and Bridge discovery passed.
- An optional guarded CDC-NCM recovery helper and systemd template are now
  installed and enabled only for this reference interface. The installer does
  not enable the workaround globally.
- The transport and network-recovery units are enabled. Keybag, credential,
  biometric-ready, fprintd, and PAM integration remain disabled.
- A root-only search of the encrypted Linux filesystem and EFI volume found no
  keybag, Catacomb, or prior provisioning archive. The system is confirmed to
  be a clean installation on a wiped Mac.

### 2026-08-31 — Transient identity-secret producer

- The installed transport rebooted with root-only, generation-pinned endpoint
  10 enabled alongside the endpoint-7 OOL transport.
- The fixed-purpose hardware test completed ACM context create, type-5 secret
  set, externalization, and deletion. Cleanup reconciled successfully; the
  output was redacted and reported no keybag or fingerprint mutation.
- A post-test preflight passed and the kernel log contained no late protocol or
  transport error. Keybag-load, credential-unlock, biometric-ready, and
  fprintd units remain disabled; PAM remains untouched.
- Static host recovery classifies the reference Mac's internal NVMe storage as
  non-portable. The corresponding request-10 candidate is original flags `6`,
  transformed by the kext to internal flags `0x4100`.

## Historical next-observation sequence

Matching firmware now identifies the Intel host as the xART slave and the
BridgeOS side as owner of an asynchronous master/backing-store rendezvous. The
current boot autoloaded the transport before T2 CDC-NCM enumeration, while a
later dynamic RemoteXPC discovery and BridgeXPC HELO-only exchange succeeded.

D015's next observation is one reboot with modalias autoload suppressed and
one explicit transport load after that capability gate. A zero opcode-8 status
supports a startup race; another `0x2d` falsifies HELO as sufficient. Do not
retry, start PAM integration, or issue an identity mutation.

That observation is complete. Boot `b00e4d1d-ce8a-46ba-bce8-0077edee7e40`
logged HELO readiness before the sole explicit load and still returned
`0x2d`. No endpoint-7 request occurred. The next observation must exercise a
recovered clean-install gigalocker provisioning or attachment boundary, not a
longer delay.

Matching-image recovery now constrains that boundary: normal bridgeOS invokes
an attach-only `init_data_protection` path, while restore/Ramrod alone invokes
the creator form that makes the 6 MiB backing before migration and attachment.
Live service inventory provides no targeted creator; the advertised multiboot
service only writes a version whitelist, and restoreserviced exposes no safe
gigalocker-init command. This supports missing restore-created state as the
next causal hypothesis, but it does not yet prove that the backing file is
absent on the physical reference Mac.

### 2026-08-31 — First paired identity probe

This experiment predates D025. Static matching-SEP recovery later proved that
operation 3 is a loader, not an existence query; the probe and its interface
were removed. The timeout below remains valid transport evidence only.

- After booting the generation-pinned paired-probe build, one fresh random
  UUID was submitted to the fixed-purpose operation-3/operation-5 kernel
  transaction. Identifiers remained redacted.
- Operation 3 received no reply and timed out after zero unrelated messages;
  the inbox was empty and the outbox was not full. No operation status or
  identity-absence result was obtained.
- The ambiguous result poisoned endpoint 7. A second tool invocation was
  rejected as transport-unavailable without transmitting, proving the
  no-blind-retry boundary. No live handle was returned to userspace.
- This reproduces the no-reply shape previously seen with capability operation
  `0x4d`, so the next falsifiable target is shared framing or endpoint
  initialization, not the recovered operation-3 request body.

### 2026-09-01 — xART OS-identity publication

- The installed source version `8B50EEA9B1BE9C5ECC27B5F` completed the fixed
  endpoint-0 version selection and endpoint-16 OOL setup.
- A correlated xART opcode-8 reply returned status `0x2d`. This is a definite
  application rejection rather than the earlier no-reply endpoint-7 failure.
- The driver failed closed before endpoint-7 registration. Both root-only
  device nodes were absent, and no endpoint-7 request was issued.
- Keybag-load, credential-unlock, biometric-ready, and fprintd remained
  disabled and inactive; PAM remained unchanged.

### 2026-09-01 — xART UUID provenance

- Matching bridgeOS `multiboot` prefers an APFS volume-group UUID and falls
  back to the boot partition UUID for selector `0x28`.
- The reference Linux installation has no APFS volume group. `BootCurrent`,
  EFI loader metadata, and `/boot` identify the same Limine GPT partition.
- Matching `seputil` uses the machine host UUID only to name the separate
  bridgeOS gigalocker backing file; it is not selector `0x28`'s active OS UUID.
- D014's reboot used the boot partition identity and returned the same status
  `0x2d`. Authentication and provisioning services remain disabled.

### 2026-09-01 — Correct boot identity remains insufficient

- Boot `d3de2696-782a-4652-b0fc-ef3e5d3d0798` loaded source version
  `8B50EEA9B1BE9C5ECC27B5F`, completed command `0x22`, and registered the
  endpoint-16 OOL buffers.
- xART opcode `8` received the current EFI loader partition's GPT PARTUUID and
  returned status `0x2d`, the same status observed with the btrfs UUID.
- The driver failed closed before endpoint-7 registration. `/dev/t2-aks` and
  `/dev/t2-acm` were absent, and no endpoint-7 request was issued.
- The transport unit failed. Keybag-load, credential-unlock, biometric-ready,
  and fprintd remained disabled and inactive; PAM remained unchanged.

### 2026-09-02 — macOS APFS volume-group identity also returns `0x2d`

- Boot `648962a4-8940-479f-90e1-75b90f14147c` supplied the protected APFS
  volume-group UUID shared by the macOS System and Data volumes.
- Versioned app selection completed and one correlated xART opcode-8 reply
  returned status `0x2d`. The driver failed closed before endpoint-7 setup;
  `/dev/t2-aks` is absent and the module remains pinned.
- This matches the prior filesystem-UUID and Linux boot-PARTUUID results.
  UUID identity class is not sufficient even though separate bridgeOS logs
  prove the embedded xART volume now mounts and supplies SEP/USER state.
- Authentication/biometric services, mapping, ACM, identity provisioning,
  PAM, and EFI remain unchanged. No retry or reload is allowed this boot.

### 2026-09-01 — BridgeOS readiness discriminator

- Matching AppleSEPManager assigns the host's endpoint 16 to the xART slave;
  `xarm` owns the gigalocker master role and joins independent master-check-in
  and backing-path prerequisites.
- On the current boot, module autoload began at monotonic `10.923s` and xART
  returned `0x2d` near `10.955s`. T2 CDC-NCM enumerated only at `11.059s`,
  after the one-shot xART attempt had already failed.
- Later in the same boot, the persistent link-local configuration was usable,
  dynamic RemoteXPC service discovery succeeded, and a BridgeXPC HELO-only
  probe reported readiness. No biometric command was sent.
- The next boot will replace modalias autoload with a capability-gated explicit
  load. The gate is portable across discovered interface address and service
  port and does not encode the reference model.

### 2026-09-01 — Readiness discriminator result

- Boot `b00e4d1d-ce8a-46ba-bce8-0077edee7e40` had no early transport load.
  CDC-NCM enumerated at `11.458s`, BridgeXPC HELO readiness was logged at
  `39.176s`, and explicit module load followed at `39.181s`.
- Command `0x22` completed; opcode 8 returned `0x2d` at `39.184s`.
- `/dev/t2-aks` and `/dev/t2-acm` remained absent. Endpoint 7 was not
  registered and no biometric transaction occurred.
- HELO is not sufficient to establish gigalocker readiness. The next target is
  clean-install creation or attachment of the BridgeOS master backing store.

### Reconstructed xART storage prerequisite

- The clean wipe had removed the Apple APFS xART partition entirely.
- The Linux root was safely shortened only at its tail after Btrfs and
  dm-crypt were reduced in that order; its partition start is unchanged.
- The disk now has one 128 MiB partition with Apple APFS content type
  `69646961-6700-11AA-AA11-00306543ECAC`.
- Its volume is named `xART`, has role `0x100`, and contains one root-owned
  mode-`0600`, physically preallocated 6 MiB `.gl` file named from the
  uppercase Apple/DMI platform UUID.
- The image passed `apfsck` and its complete raw readback matched the source
  SHA-256. Exact machine and disk UUIDs are intentionally private.
- Boot `16b6bad4-194e-4e6a-bda4-1595347a4bf7` completed D016's sole startup
  transaction. xART again returned `0x2d`, endpoint 7 stayed absent, and the
  complete APFS partition hash remained unchanged.
- Authentication/provisioning units remain absent and inactive and PAM has no
  T2 hook. Do not retry or unload the pinned module in this boot.

### 2026-09-01 — Apple-control oracle capture

- A macOS control boot produced one structurally valid keybag archive and one
  structurally valid three-component Catacomb archive for the existing Apple
  UID 501 enrollment.
- Linux independently validated safe archive paths, exact map-to-payload
  correspondence, one unique saved `user.kb` payload, and exactly one enrolled
  user Catacomb record. Private bytes, paths, and identifiers remain excluded
  from this log.
- The capture is interoperability evidence only. It does not establish
  Linux-native provisioning and must never become an installation prerequisite.

### 2026-09-01 — APFS volume-group identity recovered read-only

- Linux opened the temporary macOS APFS container read-only and parsed volume
  superblocks without mounting or decrypting them.
- Exactly six roles are present: Data, Preboot, Recovery, System, Update, and
  VM. System and Data share one nonzero volume-group UUID; the other four group
  identifiers are zero.
- The shared UUID is retained only in a root-private oracle file. It is the
  identity class selected by matching Apple xART boot policy, not a portable
  constant or a Linux-native installation dependency.

### 2026-09-01 — embedded xART becomes live after macOS provisioning

- A constrained bridgeOS OS-log archive collected from Linux proves the T2
  embedded APFS container now has an `xART` volume at `disk1s3`.
- One retained boot mounts the volume, enables bypass mode on its backing
  inode, fetches SEP-xART and USER-xART, and later saves USER-xART lockers.
- The pre-macOS post-Revive archive proved the same embedded container lacked
  xART. The transition is therefore real even though the creator instant aged
  out of retained logs.
- All raw logs, identifiers, CRCs, and paths remain root-private. Collection
  did not open SEP, mount storage from Linux, change services/PAM/EFI, or reboot.
