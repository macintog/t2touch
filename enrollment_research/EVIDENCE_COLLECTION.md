# Evidence collection reference

These collectors preserve optional macOS/oracle evidence and support future
portability or reverse-engineering work. They are no longer prerequisites for
the reference-machine native path: D196-D218 completed native enrollment,
different-boot persistence, matching, single-identity deletion/recovery, and
continuous second-finger enrollment. Collection output is private by default
and must not be committed to this repository.

## Recommended one-shot collection

For the currently available macOS evidence, use the standalone collector:

```bash
curl -fL -o ~/collect-t2-enrollment-evidence.sh \
  https://raw.githubusercontent.com/jmurth1234/t2-touchid-linux/main/enrollment_research/scripts/collect-all-macos-evidence.sh
chmod 700 ~/collect-t2-enrollment-evidence.sh
~/collect-t2-enrollment-evidence.sh
```

It creates one private archive in the current directory, briefly freezes and
always resumes `biometrickitd` while copying Catacomb state, and also captures
the console user's OpenDirectory record, host UUID, `persona.kb`, hashes, and
Catacomb filesystem metadata. It performs no biometric or keybag command.

After it prints `Created private archive`, move that archive through your
private dual-boot transfer location. Never publish or attach it to a public
issue. The individual collectors below remain useful when only one evidence
class needs refreshing.

### Current AppleKeyStore caller platform data

Operation `0x21` carries the caller's audit-session ID and process-unique ID,
not its Unix UID. To capture the current values for likely selector-42 callers
in one read-only run, boot macOS and run:

```bash
curl -fL -o ~/collect-aks-platform-identities-macos.sh \
  https://raw.githubusercontent.com/jmurth1234/t2-touchid-linux/main/enrollment_research/scripts/collect-aks-platform-identities-macos.sh
chmod 700 ~/collect-aks-platform-identities-macos.sh
~/collect-aks-platform-identities-macos.sh
```

The default destination is the mounted `OMARCHY_EFI` volume. The TSV contains
private, boot-scoped process identifiers: transfer it privately, do not commit
it, and do not assume its numeric values survive a process restart or reboot.
The relationships are research evidence; they are not reusable credentials.

If the EFI volume is already mounted at `/Volumes/EFI`, the collector can place
the archive there directly even when the directory requires administrator
permission:

```bash
~/collect-t2-enrollment-evidence.sh \
  /Volumes/EFI/t2-enrollment-evidence.tar.gz
```

Delete the EFI copy after transferring it into the Linux home directory; FAT
volumes do not provide meaningful Unix confidentiality permissions.

## 1. Exact Catacomb fixtures

Needed for independent keyed-archive reader/writer and crash-recovery tests:

- `master.cat`;
- `biolockout.cat`;
- `user_*.cat` with one and, if naturally available, multiple identities;
- before/delete/re-enroll generations; and
- ideally a genuine legacy user archive without `CatacombUserKeybagUUID`.

Boot macOS and run:

```bash
sudo ./scripts/collect-catacomb-fixtures-macos.sh /path/outside/the/repo
```

Use `--freeze-daemon` only when a consistent point-in-time copy is required.
It briefly stops `biometrickitd`, copies the files, and resumes it through a
trap. Review `manifest.sha256` and `metadata.txt`. Encrypt the directory before
moving it between operating systems. Do not publish the raw files.

## 2. Read-only account/persona inventory

Needed to join numeric UID, OpenDirectory UUID, UserPersona data, host UUID,
top-level AKS identity, bag UUID, and selector-`0x61` persona UUIDs without
assuming equal-looking UUIDs are interchangeable.

```bash
sudo ./scripts/collect-persona-inventory-macos.sh USERNAME /path/outside/the/repo
```

The script collects OS/account metadata and a private copy of `persona.kb` when
present. It cannot call private `AKSIdentityList` or selector `0x61` by itself;
those require a separately reviewed read-only helper. The output explicitly
records those missing columns rather than fabricating them.

## 3. Whole-biometric-user presence primitive

Command `0x48` is known, but zero identities does not distinguish an empty
biometric-user container from an absent one. Search exact extracted host
binaries offline:

```bash
./scripts/search-container-presence.sh /path/to/extracted/BiometricSupport \
  /path/to/biometrickitd /path/to/private/output
```

Promising symbols or strings still need disassembly and an exact request/reply
contract. Do not probe guessed commands on live hardware.

## 4. Encrypted J132 SEP artifact

The encrypted SEP image is useful for provenance and may become analyzable if a
legitimate plaintext key/image is obtained later:

```bash
./scripts/extract-encrypted-sep.sh /path/to/bridgeOS.ipsw \
  /path/outside/the/repo
```

The script extracts only Apple's encrypted IM4P and hashes it. If the `ipsw`
tool is installed, it also records metadata and wrapped KBAG data. A displayed
KBAG key is wrapped material, not a usable AES key. The script performs no
decryption and downloads nothing.

## 5. Controlled device validation (completed on the reference machine)

The once-deferred device experiment is complete on the MacBookPro16,1. D196-
D200 proved mode-0 consumption, native persistence, and different-boot E4;
D204-D205 proved positive and negative matching; D217 proved exact deletion,
recovery, and survivor verification; and D218 proved uninterrupted additional
enrollment with immediate new-identity-only matching. The D218 immutable
artifact/read-only snapshot is
`D218-continuous-second-finger-ceremony-20260913`, with private-manifest
SHA-256
`52f960e06e35e462326c89109597c586b6bd5d3376fa91011d2a93660eb6dd25`.

The historical non-mutating checklist generator remains useful when repeating
the experiment on a new machine:

```bash
./scripts/hardware-experiment-preflight.sh /path/to/private/output
```

It intentionally exits nonzero while any prerequisite is unacknowledged and
contains no enrollment or deletion command. Any repetition must remain a
separately reviewed change with an immutable target UID, verified backup,
password fallback, exact before/after inventory, and explicit operator consent.

## Publishing results safely

Share semantic, redacted findings rather than raw captures. Replace account
names, filesystem paths, host/account/bag/persona/identity UUIDs, session IDs,
network addresses, and hashes of private artifacts. Public hashes of unmodified
Apple binaries may be retained for reproducibility, but Apple binaries and
firmware themselves must not be committed.

Before committing documentation changes, run:

```bash
./scripts/check-public-tree.sh
../../tools/privacy-check.sh
```
