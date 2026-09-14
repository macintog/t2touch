# Static artifact provenance

This file records reproducible, public provenance only. Apple binaries and
extracted caches live under ignored `linux_native/artifacts/` and must not be
committed or redistributed.

## 2026-09-02 — Reacquired macOS 15.7.9 (24G830) host corpus

- Apple full-installer URL:
  `https://swcdn.apple.com/content/downloads/16/08/140-85388-A_3LX3Q36I6P/zxod6nr7zkovvsml6s628z44gdbc4exa5p/InstallAssistant.pkg`
- `InstallAssistant.pkg` size: 15,655,958,320 bytes.
- `InstallAssistant.pkg` SHA-1:
  `94295f31d12db20110e7036cfc09edc8d9900b38`.
- `InstallAssistant.pkg` SHA-256:
  `3a0d0ce4422a51b826699508a50e3f6b559cff7014daaa5b3600bbef935ecc9e`.
- `bsdtar` extracted the package's 15,640,665,291-byte
  `SharedSupport.dmg`. 7-Zip 26.02 read its HFS+ volume and extracted the exact
  full OTA named by the earlier research record:
  `9d95c64142a9a426f56d3265d4f8a6fa31585333.zip`.
- OTA size: 15,630,394,567 bytes.
- OTA SHA-256:
  `1c76ee0ffbc8bcb4ec74e94d2b68fe31032f90a9a52f39847ae7fa946fa36d45`.
  This independently matches the hash already recorded in
  `enrollment_research/FINDINGS.md`.

The ignored working files are retained under
`linux_native/artifacts/macos-15.7.9-24G830/`. Both the installer and exact OTA
also reside in the root-owned Btrfs subvolume
`/var/lib/t2-touchid/research-artifacts/macos-15.7.9-24G830/`. The OTA archive
copy compared byte-identically with the working copy. Immutable snapshots now
include:

- `/var/lib/t2-touchid/research-artifact-snapshots/24G830-primary-20260902T1744`
  (installer acquisition checkpoint); and
- `/var/lib/t2-touchid/research-artifact-snapshots/24G830-ota-20260902T1758`
  (installer plus exact OTA, `ro=true`).

Btrfs reports zero exclusive bytes for both archived large files: these are
reflink protections, not duplicate 30 GB allocations. The OTA's x86_64 cache
is carried inside `cryptex-system-x86_64` as a full-image RIDIFF. Linux
AppleArchive parsing found no loose cache duplicate; `ipsw` 3.1.713 correctly
refused that Darwin-only RawImagePatch step.

### Linux RIDIFF recovery and exact host cache

The RIDIFF was recovered directly from the OTA at
`AssetData/payloadv2/image_patches/cryptex-system-x86_64`:

- encoded size: 1,353,927,934 bytes;
- encoded SHA-256:
  `b9ffd2eeca8b7810130046ed6dbf76266e66777f290e43ea44ef8734d3f3d4cd`;
- one control record, declaring 5,264,658,091 output bytes; and
- PBZX-decoded output SHA-256:
  `ca93365dfde27e0babb25ada2e9848dd98e3f5923de35935f72e7a11648de71c`.

The decoded output contains complete cache files consecutively. Its System
cache begins at byte 108,124,407. Each file length was taken from its dyld
code-signature end and independently agreed with the next declared cache
header. The reconstructed family is:

| File | Payload offset | Size | SHA-256 |
| --- | ---: | ---: | --- |
| main | 108,124,407 | 870,400,000 | `b30ed9191df8900e345105f4a3d43dc138bdec0a5204913cd96cd4a2684e7552` |
| `.01` | 978,524,407 | 804,896,768 | `4a24ed9ac34040442e2b96dcf0cf8b75007ac6733adeaf809c46c56a22350bc8` |
| `.02` | 1,783,421,175 | 789,905,408 | `4f997f2caf92bbed117e3d5b65ad0231593245badd0dec666e2f5faed7998a60` |
| `.03` | 2,573,326,583 | 753,500,160 | `5362ea7bb87e68aa433d807471f72f24a1f5381fd3265a3ee5a5338ce6c2c4b0` |
| `.04` | 3,326,826,743 | 765,100,032 | `980e150c88b513da782519edf9b427d437bd6400f8e20a88c9bfc2c70220109b` |
| `.05` | 4,091,926,775 | 779,157,504 | `ec830d71f94230e3543dbd3b8b4548709b0ea90062f9f36489400f6f2ab83596` |
| `.06` | 4,871,084,279 | 216,907,776 | `4dbf395d8f8479a0d9eecaacf24101d48a9536acd9bf69c9d06a1bc20fc125fe` |

`ipsw dyld info` validated this as macOS 15.7, cache UUID
`FDD97301-9818-3865-A1D2-FEC1D3914796`, 3,258 images, and six subcaches. The
six UUIDs in the main header match the six recovered companions. A retained
1,030,555,686-byte symbol cache has SHA-256
`6199a9bd384783d3e38f682bf1cdc51925b5610ca905604542cf9c921b565a50`.

`ipsw dyld extract --objc --stubs` produced the exact 24G830 host images:

- BiometricKit 511.100.15.0.0, SHA-256
  `6075d4b2bba604614dc7e7de79cf20694746f420ae437677b21c833db06d5749`;
- BiometricSupport 511.100.15.0.0, SHA-256
  `f2a6137800b819c6b958eec6082cb4ff38aa8fb08e58e2cf054df889629c9a8b`;
- BiometricKitUI 646.4.2.0.0, SHA-256
  `b09ac44eac67879614ac0458ca3980e137bc06ea37269b0ee9ee08eab5a93e61`;
  and
- LocalAuthenticationCore 1656.140.4.700.1, SHA-256
  `5b6ea5d938211f84d3b1ee78df2b090f2bf429b8b2061e145cdc6c3a605afe0e`.

A selective Linux YAA pass over the same OTA's 47 ordinary payloads recovered
`usr/libexec/biometrickitd`. It is a 2,617,152-byte universal Mach-O containing
x86_64 and arm64e slices, with SHA-256
`161c88b861d32790da5d28b5be05de069051a84c5ef256baf0dff9502ee9d37c`.
The working and root-archive copies compared byte-identically. Immutable
checkpoint
`/var/lib/t2-touchid/research-artifact-snapshots/24G830-biometrickitd-20260902T1901`
is `ro=true`.

The encoded RIDIFF, decoded output, decoded metadata/control streams,
reconstructed cache family, symbol cache, extracted images, and temporary
Linux parser source at upstream `ipsw` commit
`3ad9df2367e73edb06fafb9e8ed5772878c508e6` are retained together. Working,
root-archive, and snapshot copies compared byte-identically. The immutable
checkpoint is
`/var/lib/t2-touchid/research-artifact-snapshots/24G830-complete-corpus-20260902T1844`
(`ro=true`).

### Match-quality static and live-control checkpoint

The 1,282,880-byte x86_64 slice of `biometrickitd` has SHA-256
`aa250221917fb64b345a317650371013aa5236e9d5d5228dd96a0256ea206b36`.
Generated exact-build disassemblies retain match initialization, command
serialization, sensor initialization, calibration, service-status dispatch,
and analytics-statistics handling. The two statistics dispatch artifacts have
SHA-256 values
`85ac98e888b1b9a8af584c212e8b5ab5dc0c22f7af8f80b676132c5779e69bef`
and
`0212bbdeb9eff152a19208f761a9d320fcd02cc86d3ecbbfa7e2a63e762f0ead`.

The public-safe exact-`0x4001` live control is 45,308 bytes with SHA-256
`84f631daccd502ea6b1c5cda1d13cb9362dd370e556e31155f381f2b5d012104`.
It contains summaries only; identity bytes and raw event payloads are absent.
The slice, all current static-analysis outputs, and that control were verified
byte-identical after reflink archival below the root-owned research subvolume.
The named immutable checkpoint is
`/var/lib/t2-touchid/research-artifact-snapshots/24G830-match-quality-20260902T231551Z`
(`ro=true`).

The subsequent continuous-contact control and its exact root-only event stream
are retained with both pre-hardware launch diagnostics. Two exact BiometricKit
match-status disassemblies have SHA-256 values
`b63fbd6ba7aa3d86eb718e0c7063f803746d0133091a57b6d485c7d7d96572e9`
and
`e46ef0cb91d17070823f1d59b40976e83780ea4c04eeee16b4d6244d4949b9ea`.
Working and archive copies compared byte-identically. The added immutable
checkpoint is
`/var/lib/t2-touchid/research-artifact-snapshots/24G830-match-cadence-20260902T232827Z`
(`ro=true`).

## 2026-08-31 — MacBookPro16,1 latest RecoveryOS

### Target identity used for selection

- Mac host model: MacBookPro16,1 (16-inch, 2019; Intel)
- Mac board ID: `Mac-E1008331FDC96864`
- T2 product: `iBridge2,14`
- T2 board configuration: `J152fAP` (`j152f`)
- T2 board code: `0x3A`
- T2 firmware observed over BridgeXPC: bridgeOS 10.6 build `23P6068`

The first two values selected the Apple recovery asset. The T2 values identify
the hardware/firmware being researched; they do not claim that the recovery
image contains the identical bridgeOS payload.

### Acquisition tool

- Source: `https://github.com/acidanthera/OpenCorePkg`
- OpenCorePkg commit: `2a9ce04683ab1d9ca7619bbb4ea4ab869c000ee1`
- Tool: `Utilities/macrecovery/macrecovery.py`
- Tool SHA-256:
  `3023a9b4ca79a5255d93c00f25ab5df37e6f938b729b797d9ecea56184b17aff`
- Selection arguments: board ID above, zero/generic MLB, `os-type=latest`

### Apple response and downloaded files

- Apple recovery product: `140-93589`
- RecoveryOS: macOS 26.6.2 build `25G83`
- `BaseSystem.dmg` size: 960,530,321 bytes
- `BaseSystem.dmg` SHA-256:
  `edddd0d5869caaa12e29e6996a04f11590280580976a119dbd42c24fa62fe18e`
- `BaseSystem.chunklist` SHA-256:
  `06f7c498f856341f467ba1faedf2717fb2c172ae0aff4658a1467cbf46b711f9`
- The complete image passed OpenCore macrecovery chunk-by-chunk verification.

This RecoveryOS version is not bridgeOS `23P6068`. Its x86_64 host binaries are
version-qualified evidence for the AppleKeyStore client/server ABI only.

### Public APFS creation tool

- Source: `https://github.com/linux-apfs/apfsprogs`
- Commit: `3721463ba7f539e532907bc1d10ed5b9a97d0449` (`0.2.1`)
- The source checkout remains under ignored `.research-tools/`.
- The project-carried contribution adds a generic `mkapfs -r <role>` option;
  see [`patches/apfsprogs-mkapfs-volume-role.patch`](patches/apfsprogs-mkapfs-volume-role.patch).
- On 2026-09-01 that patch applied without offsets to a clean detached tree at
  the pinned commit. Both `mkapfs` and `apfsck` built; one role-`0x100` image
  passed `apfsck` and `git diff --check`. See
  [`patches/README.md`](patches/README.md) for the exact bounded reproduction.

### Extraction tools

- 7-Zip 26.02 extracted the HFS+ paths from the DMG.
- `ipsw` 3.1.713, build commit
  `cdbc3a57114b5b240d23b00aa29cfad4d1f1d3fd`, extracted the framework image
  from the dyld shared cache.
- `ipsw_3.1.713_linux_x86_64.tar.gz` was verified against the release's
  published SHA-256:
  `502dc308f2b1a0038031b47a2ba663630b16e43a18755733385f3a3342f0d273`.
- Current `DyldExtractor` source was inspected at commit
  `0e1b35a5f60e7041c51b57a54cc36d815fe7adf2`; the checkout and extracted
  products remain below ignored artifact directories.
- It extracted the matching bridgeOS `BiometricSupport` image with SHA-256
  `b0793287f1766dcc9b599746cd1f0842c98e8c9c25bff0fac164a3ebcfe00ed5`.
  The image has only `0xac` bytes of `__text` and message-data support exports
  such as `MCDMExtractMessageData`; it is not a host Catacomb constructor.

### Relevant extracted components

- `applekeystored`: x86_64, Mach-O UUID
  `4BCDF315-EB89-37EA-A9B6-73367E866E08`, SHA-256
  `8caa175067a2ed19aecaee7f69bb0eab330e9d2cabfecbf41d1738c3f2298d46`.
- AppleKeyStore framework: source version `2155.160.13.0.1`, x86_64, Mach-O
  UUID `80968FD4-9A54-38BF-8AFA-51B73165191C`, extracted-image SHA-256
  `4eda3cc5a3951295d3eeb7debdf3589a2fb22fc13987ed54928d7cc941c4ef39`.
- Main dyld cache UUID: `3200C045-CABD-3383-972F-D3AB676F6DA4`; one subcache,
  UUID `087A5BFE-5947-3426-A238-C921048163D2`.
- Boot kernel collection SHA-256:
  `c80161fa3065883753fc285339281361a8469cbb6fb27653c88e2a22eb4807a4`.
- BaseSystem kernel collection SHA-256:
  `60d3f43f1a23847aa8b60b7c57153fd93d20d0653c116d14da4875f09e5d2f04`.
- AppleKeyStore kernel extension: x86_64, Mach-O UUID
  `060C7A7E-28E1-3FED-BDB3-586E4210C064`, SHA-256
  `c20c4b3302b75536ecea5c0d62bd2a33766d03db6a5239a4b1ff979e046b72ed`.
- AppleSEPManager kernel extension: x86_64, Mach-O UUID
  `0D42925E-8B07-3064-80D1-328D43196288`, SHA-256
  `d43b5bf75d7b01000ef9e8b07d56b85de518293f8a95ce1a78dcd3a2a673516f`.
- IOSlaveProcessor kernel extension: x86_64, Mach-O UUID
  `70B0AED1-5344-3608-B342-45E9C11B79A5`, SHA-256
  `c5770c108c854399923cad7c6ea70fca622ce121f129ef7cc2335a199bf14c47`.

The latter two extensions were extracted from the same verified Boot kernel
collection with `ipsw kernel extract --imports`. They are retained only below
the ignored `linux_native/artifacts/kexts/` directory.

### Recovered common endpoint transport

- AppleKeyStore's generated v1/v2 headers are respectively `0x48`/`0x50`
  bytes, preceded by their four-byte size. Its integrity value is the first 16
  bytes of SHA-256 over header offset `0x10` through the body. These byte
  ranges match the Linux codec.
- Operation `0x4d` is sent with a v1 header and the 16-byte
  result/selector/empty-blob body already used by Linux.
- AppleSEPManager registers send and receive OOL memory with one 12-byte
  endpoint-0 message each: opcode `2` or `3`, target endpoint, page address,
  and byte size. The recovered Intel implementation matches the Linux control
  layout and direction; an older two-message account is not applicable here.
- The Intel manager performs no additional SEP-visible endpoint-enable or
  host-alive message before clients use endpoint 7. Endpoint enablement below
  IOSlaveProcessor is local event-source and power-accounting state.
- AppleKeyStore begins with header v1, sends the v1 capability request, and
  upgrades to `min(peer, 2)` only after a successful reply. If negotiation
  fails, it leaves normal requests on v1. Linux previously hard-coded v2 for
  normal traffic; that state machine is now explicit and fail-closed.

### Recovered identity-creation path

The 26.6.2 `applekeystored` still calls `IOConnectCallMethod` with user-client
selector `0x76` in its identity-creation routine. The call uses three scalar
inputs, one structured input, one scalar output, and one structured output.
The AppleKeyStore kext unpacks that input, calls its version-5 create-keybag
IPC routine, and dispatches the encoded body to endpoint 7 as operation
`0x01`. The recovered structures, symbols, addresses, evidence qualifiers, and
remaining unknowns are recorded in [`SELECTOR_76.md`](SELECTOR_76.md).

## 2026-08-31 — Matching iBridge2,14 bridgeOS restore

### Apple restore artifact

- Device query: `iBridge2,14`, build `23P6068`, iBridge restore catalog.
- Apple restore version: bridgeOS 10.6 build `23P6068`.
- Apple CDN object: `iBridge2,1,iBridge2,10,iBridge2,12,iBridge2,14,iBridge2,15,iBridge2,16,iBridge2,19,iBridge2,20,iBridge2,21,iBridge2,22,iBridge2,3,iBridge2,4,iBridge2,5,iBridge2,6,iBridge2,7,iBridge2,8_10.6_23P6068_Restore.ipsw`.
- Size: 742,609,165 bytes.
- SHA-256, advertised by Apple's CDN and verified locally:
  `da1ce0198ee23d38a6d065e296fed3f302ff79b196c14107ab59ea191028206a`.
- The long object name denotes Apple's shared multi-device restore container;
  it is not the selected hardware identity. Its manifest has a distinct
  identity with `Ap,ProductType=iBridge2,14`, `Ap,Target=J152fAP`,
  `Ap,TargetType=j152f`, `ApBoardID=0x3A`, and `ApChipID=0x8012`.
- Extracted `BuildManifest.plist` SHA-256:
  `8c9b5d0a2440dd6794bde7bd65303ec9a53093dd44a809684e1a90162f3f64e3`.
- That J152f identity selects the exact `j152f` DeviceTree, input-device,
  MacEFI, bootloader, and SEP-firmware variants used by MacBookPro16,1.
- The manifest contains 32 build identities collapsing to 16 unique iBridge2
  hardware profiles. All report chip ID `0x8012` and select board-specific SEP
  paths. This is packaging evidence, not a cross-board protocol claim.

The IPSW and every extracted binary remain below ignored
`linux_native/artifacts/bridgeos/`.

### Linux revive client

- RestoreKit source: `https://github.com/fcjr/restorekit.git`
- Pinned RestoreKit commit:
  `7745cadad6b660dfb070504c8505bbe07f817e70` (`0.5.10`)
- Pinned vendored idevicerestore commit:
  `45145e9fdc8458022c61a4b87bd029b866d5bcdc`
- Local checkout: ignored `.research-tools/restorekit/`
- Portable contribution:
  `patches/restorekit/0001-allow-revive-from-iboot-recovery.patch`
- Validation: `cargo build --release --locked -p restorekit-cli` succeeded on
  the reference Linux installation; resulting binary reports
  `restorekit 0.5.10` and is an x86-64 dynamically linked PIE.

The patch changes only client admission: iBoot recovery is accepted for
non-erasing Revive, while Erase and Obliterate retain the DFU-only requirement.
It does not change idevicerestore flags, manifests, or restore payloads.

Current public protocol corroboration was inspected from
`https://github.com/doronz88/pymobiledevice3.git` at commit
`ec4ac06a850a6a884ca778350621f354faf347c6`. Its
`pymobiledevice3/services/restore_service.py` uses the same restoreserviced
service name, lowercase `command` envelope, and `result == "success"` rule.
The ignored checkout is `.research-tools/pymobiledevice3/`.

### Matching J152f SEP component

- Encrypted `sep-firmware.j152f.RELEASE.im4p` SHA-256:
  `bc21098b1c4fa98d20974e55ebeebdf219294caf07db3ab3af3db7882b60be92`.
- Decrypted/extracted payload SHA-256:
  `1b29e87948c08ddd49a35137e8857892f7c5101fbe1de988dac357a9fa7cf66f`.
- Correctly reconstructed `sks` SEP app: ARMv7 Mach-O, UUID
  `D14EC38B-9DE3-32B0-867C-07C86AE9C97C`, SHA-256
  `57178e6692f2599110eee5a01da24629cd2d5eacf474df09c53a0ae704f7bacd`.
- The `sks` app identifies its source as `AppleKeyStore_SEP`, version
  `2155.160.13.0.1`, built July 11, 2026. That source version exactly matches
  the RecoveryOS AppleKeyStore framework used above.

The matching ARMv7 operation table and version-5 decoder independently confirm
the full request layout recovered from the x86_64 host side. Addresses and
field mapping are recorded in [`SELECTOR_76.md`](SELECTOR_76.md). Semantic
requirements inside the operation implementation remain under analysis.

### SEP splitting tools

- Legacy comparison tool: `https://github.com/matteyeux/sepsplit`, commit
  `721c5bb3d7730af0bf39b9083b7ddeab3f718ee1`. It did not understand the
  current split-data layout and its unlabeled output was not used as evidence.
- Current tool: `https://github.com/justtryingthingsout/sepsplit-rs`, commit
  `ff45f9d1013cfd54413ec6c57b616b4e89187b7f`. Its reconstructed binary
  SHA-256 was
  `0bb46b2f634ed86e91753a6c3db5a5166663747b2c5c4312a72eef34c4a91e1d`.
- Firmware decryption material was obtained through the tool's public lookup
  path and is deliberately not recorded in this repository.

## 2026-09-02 — Calibration-gate and interactive-cadence evidence

The next archive generation retains the two event-cued rejections, the failed
zero-contact first TUI, the exact read-only calibration-gate query, and the
39-rejection no-new-calibration run. SHA-256 values, in that order by artifact
group, are:

- cadenced public/private/stderr: `788526737379c6d80e6a09292a43058e319f3ffdbf2ad03402def7a58d4194ae`,
  `e98feaf66355a135c664bf8bb4fa779a17e746cc3341177bb5dc1b4739b2d72e`,
  `ac987c8bca5b636675c3cd002b057015a86fa9dfbaaed5944ca8b927453723a8`;
- first-TUI public/stderr/private: `828191ed2667ea39318e17693ceef7b8e87f47e2da42ba2599ae24d547c0ef1d`,
  `ae2f337e83ff246ae20d5c7b2232c645deed2a49f2983a7fa7739573470e8f76`,
  `ca935a8dba424b0f5308b8ae99961bd537cb67eab6383adf32e8d5d3eceadcbd`;
- calibration-gate JSON/stderr: `f0218f1e56ef72b959ab389fb259d15ef1c11c402056aa4546965afe83591bba`,
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`;
- no-new-calibration public/stderr/private: `43169293101cf87fb85f71bb3a6b9585c3375b2dc330472f2c9d7a06d0fcf869`,
  `091bb1e2c9a9a9077fe166fc5721c06bfaaa5403b5c40569b22b2dc3c851d392`,
  `05712283aa7f9bd4fbd940b5eb1f5190d80c6a633fd8c22f8ff8a7e4133f602c`.

The exact `loadCalibrationData` and sensor-prerequisite disassemblies have
SHA-256 values `cd9a7becc0ef6c76b13deaac55c994b31cb2a113576dd964cc4ce1cc25da3a2b`
and `0fe15ee8ae3349cd72cfb1b4de98c9c9f49e25d1af04c69117d08240b4ae96ac`.
Every working/archive pair compared byte-identically. The containing immutable
checkpoint is
`/var/lib/t2-touchid/research-artifact-snapshots/24G830-match-calibration-20260902T235145Z`
(`ro=true`).

The adjacent exact `setCalibrationData:source:` and
`getCalibrationDataState` methods are retained in
`biometrickitd-x86_64-calibration-write-state.txt`, SHA-256
`62c96f90c89cbf83ab280cd4e2ab12b87be9f05b5c51b46d2548186c88a6722c`.
The working and root-archive copies compare byte-identically. The extended
archive is frozen without modifying the prior checkpoint in read-only snapshot
`/var/lib/t2-touchid/research-artifact-snapshots/24G830-calibration-state-20260902T235913Z`
(`ro=true`).

## 2026-09-03 — Cold gate and exact initialization lifecycle

The first stale-port cold-gate public/stderr artifacts have SHA-256 values
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
and `6c460e0146adf98b5c3b7958fccc80ed7f4dc74fa63429cce5d65dc2c6906117`.
The successful cold-gate public/stderr pair has SHA-256 values
`d4d4e47691af310a772421ad23913a6ec58c216557cd555d6d25f5f008242be7`
and `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
All pairs are byte-identical in the archive and read-only snapshot
`/var/lib/t2-touchid/research-artifact-snapshots/24G830-cold-calibration-20260903T000605Z`.

The exact-init match public/stderr/private artifacts have SHA-256 values
`a7975a4929fc145fe8c2c948c6c3d8fed96f089e3f483de1f09ba55b15f2eda0`,
`d305394865570fa734eee01aca759e9e63a66ff92d9bcd4a8800cb1733b43590`,
and `758821f3b41c972827d2ca0903d9edc36e02e0cfbfe50867f32a9660962ebdb8`.
The corrected one-time TUI initialization public/stderr pair has SHA-256
values `7ac058cf2def8522734d1b23d82e75815db4cc8d7f072b5eb0aeea784376148f`
and `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
Every working/archive/snapshot copy compared byte-identically. The immutable
checkpoint is
`/var/lib/t2-touchid/research-artifact-snapshots/24G830-exact-init-lifecycle-20260903T002110Z`
(`ro=true`).

## 2026-09-03 — Service-match lifecycle and BioLockout recovery

The final no-reset match public/stderr/private artifacts have SHA-256 values
`c1f1fb02a1b00f50ebf9843c2ff7dedd9101ce6b70963c957ebe763a7ad563fd`,
`2e5ed78f59744ee2c5e89f01981a6332db1b96547c8b5964eef7e85a78a1471c`,
and `5bf3ca3932a79c5fea314a9b3a55811449e1d1584b41dd0929b9669df809a9ef`.
They are frozen in read-only snapshot
`/var/lib/t2-touchid/research-artifact-snapshots/24G830-long-lived-match-20260903T002453Z`.

The exact TemplateList/BioLockout static artifacts have SHA-256 values
`4c778c2d27d6e9466168419d214853f0abb761de2ab8123196dc5fd83ae79525`
and `17b34c823b19bd3a299f8248df7cd6bb446038a0e4f5e34650e22b3af2587952`.
The successful template-presence query JSON/stderr pair is
`352487755ae906e38f5722be11d7e768327cde13199d0d4acc462f7643303f09`
and `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`;
the retained preflight-failure pair is
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
and `f2fb609847629be8fb9cc2c11f2b8027a8d41e75db4d2b080d83a10755cc1f4a`.

The rejected stale-record TUI public/stderr pair is
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
and `a331547a9fc2a2cef702ce1a4f3fc78b928ff76fe37614e0ff6fdca6f28f96b0`.
The current-record export public/stderr pair is
`23bf5479ccc135a80744993ea77332af61b11502f5868b49aac006d9a1051a99`
and `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`;
the root-private HRLB is 105 bytes with SHA-256
`bdf1bea51515c6f9d579a8e812552b37df3bc090b1d62d86ec4df3b2a106fbcc`.
The no-finger lifecycle-prefix JSON/stderr pair is
`96852140c4b53db2a3447402bd8fb12fed329f43f6ccb60632c1c217411b3bf0`
and `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

All 21 working/archive files compared byte-identically. The new root-owned
bundle is frozen without changing earlier generations in read-only snapshot
`/var/lib/t2-touchid/research-artifact-snapshots/24G830-service-match-lifecycle-20260903T010543Z`
(`ro=true`).

## 2026-09-03 — First Linux BioLockout-store generation

The current 105-byte SEP record was copied into the production-shaped
append-only Linux store as generation 1. Its HRLB SHA-256 is
`bdf1bea51515c6f9d579a8e812552b37df3bc090b1d62d86ec4df3b2a106fbcc`;
the strict immutable manifest SHA-256 is
`6cf230f3621a4470686ede48513f9eebfb9a2a259c3c4b935a076cc05df51225`.
Both are root-owned mode `0600`, have one link, and passed byte-identical store
readback. Archive copies are under
`/var/lib/t2-touchid/research-artifacts/linux-biolockout-store-20260903T012317Z`.
The full archive is frozen without replacing earlier evidence in read-only
snapshot
`/var/lib/t2-touchid/research-artifact-snapshots/24G830-linux-biolockout-store-20260903T012317Z`
(`ro=true`).

## 2026-09-03 — Branch-correct Catacomb service preflight

The transient command-`0x1e` no-finger probe is retained root-only under
`/var/lib/t2-touchid/research-artifact-snapshots/24G830-templates-at-boot-preflight-20260903T023348Z`.
It proved only that the command is accepted; exact control-flow recovery then
showed it belongs to the Class-C-inaccessible branch and the source was
reverted byte-identically before further work.

The corrected state-`3` no-finger gate is frozen in
`/var/lib/t2-touchid/research-artifact-snapshots/24G830-state3-service-preflight-20260903T025333Z`
(`ro=true`). SHA-256 values for exit status, root-private events, public JSON,
the read-only marker, and stderr are respectively
`9a271f2a916b0b6ee6cecb2426f0b3206ef074578be55d9bc94f6f3fe3ab86aa`,
`affa745435b2dfc10e0dcf7c7fe8c5bea9e091eacd1a2bf31830873a8c593021`,
`bd4563dea58a91dd045f3b04a9055f617ab86f6b13ead85e6fb0a7e4b35b1e7e`,
`a17fcf0a2f50e2d495e4f90ce263410edc183add6c62699a2facbccf60410f74`,
and `2aa578dc58e83739c7fe5cafda2d8247444551f9b8aadc3c45211becd1ff9d14`.

The pre/post root configuration copies are retained under
`/var/lib/t2-touchid/research-artifacts/config-reconcile-20260903`; their
SHA-256 values are
`0e121e212d2a5dbfcee9bbf7d7f7a2a2012aab265910c3793620f60e13743444`
and `af35c62ab85d9840965c52662d9e7af41d562e02362bd9c7fd040a6ed15e5151`.
The latter adds only the immutable hash-addressed Catacomb archive path.

## 2026-09-03 — Premature-lift control and exact cadence lookahead

The complete 20260903T025834Z run and the deployed source that produced its UI
are frozen read-only in
`/var/lib/t2-touchid/research-artifact-snapshots/24G830-premature-lift-control-20260903T025834Z`.
Public JSON, private events, stderr, the probe, and the TUI have SHA-256 values
`1ffc4df373e456c909fd8e0ef5bea75e5adda6673534bfef020c7e62606b769a`,
`5f5346635be43f2017398a759be0f704c8cd95017454deb5970a847d4c801560`,
`e0d742e55b2bf32304c09e3dd7ca593e4933a70736b46fcd8d67a16c0b40e881`,
`2200840ed788d4d3ce92c5bf5af0139a7f56afe0eba1e55f4ff9946e09430783`,
and `9101ad4d2e2241b8c23524ee9ceae864f2f1a36ddaf7a612b47c970147dbf639`
respectively. The run contains 50 presence/rejection/release cycles, no match
result, valid cancel/cleanup, and released Bridge transaction state. Exact
static recovery proved its UI requested lift prematurely at status 63/91; the
run remains valuable evidence but is not an Apple-cadence acquisition control.
Focused public analysis is retained in
`match-cadence-and-finale-lookahead-20260903.txt`.

## 2026-09-03 — Status-63 TUI renderer crash

The application-level 030751 failure is frozen read-only in
`/var/lib/t2-touchid/research-artifact-snapshots/24G830-tui-present-mode-crash-20260903T030751Z`.
Its public JSON, private events, child stderr, crashing TUI, and probe SHA-256
values are respectively
`58681d699d5009b5c41a416d2d47d4fa86c4e61ce44f3455fca0d4bf3b734e56`,
`c2e14c26f71e867719b209007ba0d369ece1af114ba66564b7517118ee787e31`,
`a2538f71833330cd642654ad87d51912dbb9a2fae26c522a7b96a3c5603a95a8`,
`5aa7e3a94df321af602cd6c716330c096cc7f2b060f6143ff4067879243e8be9`,
and `464425ea353f5815f0f86b8e26aff3ac461b09d3e42b5c577ec6dc7e094ce046`.
The stream ends exactly at valid finger-present status 63; static source proves
the ensuing full-layout lookup of absent mode `capturing`. Child cancellation,
match cleanup, and Bridge release all succeeded. Focused analysis is retained
in `tui-present-mode-crash-20260903.txt`.

The repaired no-finger arm/cancel gate is frozen read-only in
`/var/lib/t2-touchid/research-artifact-snapshots/24G830-post-crash-preflight-20260903T031436723742Z`.
Its public JSON, private events, child stderr, TUI, and probe SHA-256 values are
`bddfdcad0582d5d13bae3b730094ca258564fcccd25c845f4b00109496da304a`,
`8f90c2cb5c924101e8a6222a45073af105d8373e628cba49b07e22b7e51d9f3c`,
`66388a6aa29fa84c80ab55b53667ee1c4aaefb08bec88343f74eeb90904b72a8`,
`7dc09cc739c28a2114cf639a83117ab4021406d3fddec65f6f059baa3ab820ca`,
and `b08aa9426fb1c7e805f80c27072c2b1ba1a1f49b318a56887d14749f6254b493`.
It proves armed-event delivery, zero-status cancel, valid cleanup, Bridge
release, no orphan child, and persistent-TUI return to standby.

## 2026-09-03 — Corrected keep-steady control

The complete 20260903T131130470997Z control and exact deployed source are
frozen read-only in
`/var/lib/t2-touchid/research-artifact-snapshots/24G830-keep-steady-control-20260903T131130470997Z`.
Public JSON, private events, child stderr, TUI and probe SHA-256 values are
`494e90b9497c6b17030b3b3f2e64e6b4a8c37cb1c26d4d5e3112eceec1e10850`,
`c5c5317f8a79b0a35ec9a1828bd23080ddb5331cb84be9534bf8997890d042a7`,
`73a10271e285b4d94875f0ec4723640c48f2af021ca8d2235cfa2ef6abc65573`,
`7dc09cc739c28a2114cf639a83117ab4021406d3fddec65f6f059baa3ab820ca`,
and `b08aa9426fb1c7e805f80c27072c2b1ba1a1f49b318a56887d14749f6254b493`.
It records 13 longer-contact status-78 rejections, no match result, valid
cancel/cleanup/release, and a persistent healthy TUI. Focused timing and host-
parity analysis is retained in
`keep-steady-control-and-host-parity-20260903.txt`.

## 2026-09-03 — Native-length command-4 preflight

The 68-byte command-4 no-finger gate is frozen read-only in
`/var/lib/t2-touchid/research-artifact-snapshots/24G830-native68-preflight-20260903T134136378417Z`.
Public JSON, private events, stderr, TUI and probe SHA-256 values are
`81b96004b2edbb22d8d409681d6e70d72e095012c1d2c14eefbcf34fd2d155c5`,
`5456acc1feae1669191cbb68ac2dd7bbd88049e221a931375f9f34f4f2a97d98`,
`d6fb0d8ac5a8770083527c27a46e33f68998af6065ada2ea2b31acc9314bf580`,
`dc05c6c9859dca148d21b9620606ac09e5184b47942b7305cef8460dc63d347a`,
and `a90de8b87f7ac1c9aa542891c0b4010ff5af9b15947c1daf90eff1552ba12142`.
It records length 68, flags 1, zero selected identities, mandatory returned-
identity validation, zero-status command 4/cancel, valid cleanup and Bridge
release. Static/native evidence is retained in
`native-success-and-status78-firmware-boundary-20260903.txt`.

## 2026-09-03 — Native-length enrolled-finger control

The 68-byte enrolled-finger run is frozen read-only in
`/var/lib/t2-touchid/research-artifact-snapshots/24G830-native68-finger-control-20260903T134402342236Z`.
Public JSON, private events, stderr, TUI and probe SHA-256 values are
`16318ea7eb4d96d20f8573aefc49c89f02d616f42dba0e1a6f215cb7102db239`,
`3b8f5dd4f8486bed1bfb473131200cd1f5639beb029ca22a2381b9420fd9ae9e`,
`b91171b1dda11f6e7bca8978c601b9453469f24c504b38ecd8e204fefe82569b`,
`dc05c6c9859dca148d21b9620606ac09e5184b47942b7305cef8460dc63d347a`,
and `a90de8b87f7ac1c9aa542891c0b4010ff5af9b15947c1daf90eff1552ba12142`.
The post-session screen is also retained with SHA-256
`ff016a97b7b5f88e13ed30e4b46ba3d13f4e21e35ecdc70fdbbe79090bc69297`.
The run records ten status-81/status-78 cycles despite exact native request
length, valid zero-status cancel, valid cleanup and Bridge release.

## 2026-09-03 — Match-flags and capture-queue boundary

The full exact-build AppleMesaSEPDriver disassembly and focused extracts are
frozen read-only in
`/var/lib/t2-touchid/research-artifact-snapshots/24G830-driver-match-flags9-boundary-20260903T142000Z`.
The full disassembly, acquisition-path extract, commandStartMatch extract, and
native-success log window SHA-256 values are respectively
`8a8ea6383d7ec630bfecd1688fb1c9f609bb2508668315d7b0b3f040adc6ae92`,
`1b865e2f2b4404b4272f2e803779a085b943617a7ce4d74342a2a73ebcaa4405`,
`b865d33d80c756f530f4bcd49a8ba95860bbb071a9300a9d014a1b18536ee40d`,
and `37b2038b5ec80d0363db0e72bea9552e7b95b5beef09829035309c18b46f042e`.
The retained files prove command 4 word 0 becomes `_matchFlags`, native
success uses flags 9, and Linux flags 1 diverges before capture-data enqueue.
A sanitized tracked account is retained in
`match-flags9-capture-queue-boundary-20260903.txt`.

## 2026-09-03 — Flags-9 missing-authorization gate

The TUI-launched no-finger gate and exact source are frozen read-only in
`/var/lib/t2-touchid/research-artifact-snapshots/24G830-flags9-missing-auth-gate-20260903T141043709201Z`.
The public JSON, private event JSON, empty stderr, TUI and probe SHA-256 values
are respectively
`45a20112414c0766d58eea3a11fa5960632cd7a244bd8b5e3a7d42e1c0801857`,
`caf79ce64b0c8d2eec1c2a1c226a6c893fe4fb47f5de2f91f235f556c8f9b9de`,
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`,
`01d207a80cfe673632a9067f41c0e16f6014a34d4b3ab1b6c0a547dc6c28859e`,
and `b08ac3cac842d75d5248126f2f52cbc40ffe25c2292be6a3f02598c672ede512`.
It records a 68-byte flags-9 request, immediate status 22, no events and clean
Bridge release. Exact daemon/driver analysis attributes rejection to the
absent noBioLockout user-ID and 40-byte authorization fields.

## 2026-09-03 — Authenticated match-header boundary

Exact 24G830 host binaries, exact host/driver disassemblies, resolved selector
notes, and recovered Objective-C metadata are frozen in read-only snapshot
`/var/lib/t2-touchid/research-artifact-snapshots/24G830-auth-bypass-boundary-20260903T142840Z`.
The important SHA-256 values are:

- `BiometricSupport`: `f2a6137800b819c6b958eec6082cb4ff38aa8fb08e58e2cf054df889629c9a8b`
- `BiometricKit`: `6075d4b2bba604614dc7e7de79cf20694746f420ae437677b21c833db06d5749`
- `BiometricSupport-x86_64-initMatchOperation.txt`: `f5c36f78562f3d83a516e3a970627730f03b69df370240c62315cba32563c7b9`
- `biometrickitd-x86_64-performMatchCommand.txt`: `35ab7298af74a07af50fc392ab225b1f1a04cc72cba81add2d1437ad627a5ead`
- `commandStartMatch.txt`: `b865d33d80c756f530f4bcd49a8ba95860bbb071a9300a9d014a1b18536ee40d`
- `BKMatchOperation-optionsDictionary.txt`: `f7ee295bd6b7e86bf194402b155ad8d14e654e59b1214d4779bba560ccfc11ef`
- `parseAuthDict.txt`: `26a0b3b1f3afa4f55d4e52eacf71a6631b8de29c0dc7bb85ec5c21cad82f9330`
- `BiometricMatchOperation-class.json`: `c94ad53fb64030bddf8d204b8fcdf3625bc13e151218beba75fb092a7cd61721`
- `resolved-selectors.txt`: `4c68d879f7076d205b409280f8d6b2aca4600078136c04b3591adc02f5f8dacc`

Working, root-archive, and snapshot copies compared byte-identically. The
snapshot is `ro=true` and contains a read-only `ro` marker.

## 2026-09-03 — Normal-unlock credential-set producer

The exact 24G830 `MechTouchId`, `ModuleACM`, and `coreauthd` universal binaries,
their x86_64 slices, and focused producer/serializer disassemblies are frozen
in root-owned read-only snapshot
`/var/lib/t2-touchid/research-artifact-snapshots/24G830-match-credential-set-producer-20260903T151500Z`.
The snapshot is `ro=true`, its marker is read-only, and archive/snapshot hashes
match. Important hashes are recorded in
`static-analysis/match-credential-set-producer-20260903.txt`.

The binaries came from the already-retained full macOS 15.7.9 (24G830) OTA.
They prove the live ACM external form is the normal unlock credential-set
producer and close the offset-8 length/offset-12 payload interpretation. Apple
binaries and credential bytes remain excluded from Git.
