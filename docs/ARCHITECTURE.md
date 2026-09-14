# Product architecture

t2touch installs a Linux-native Touch ID stack for one desktop account on an
Intel T2 Mac. Its Python service owns the standard `net.reactivated.Fprint`
D-Bus name and implements the fprintd interface. Stock fprintd clients, sudo,
PolicyKit, and the Omarchy lock screen all use that service. t2touch is a
fprintd-compatible service, not a libfprint driver loaded into the stock daemon.

The [README](../README.md) covers installation and everyday commands.
[Fprintd integration](FPRINT_INTEGRATION.md) specifies the client and worker
contracts; the [protocol reference](research/README.md) explains AKS, ACM,
BridgeXPC, and Catacomb formats.

## Components and control flow

```text
  t2touch CLI / enrollment TUI       sudo / PolicyKit / lock screen
                   \                 /
                    fprintd D-Bus API
                            |
                 t2-fprintd.py service
              caller + account + inventory
                            |
          serialized enrollment / match / deletion
                 /                       \
    BridgeXPC / BiometricKit           AKS / ACM
       sensor and templates        account authorization
                 |                       |
         T2 CDC-NCM network        /dev/t2-aks, /dev/t2-acm
                 |                       |
             bridgeOS            t2_sep_transport kernel module
                 \                       /
                       Secure Enclave
```

- [`src/t2touch.py`](../src/t2touch.py) dispatches enrollment to the direct
  D-Bus TUI and uses stock fprintd clients for list, verify, and named deletion.
- [`src/t2-fprintd.py`](../src/t2-fprintd.py) owns claims, the reconciled user
  inventory, and the public operation lifecycle. Enrollment and deletion use
  separate caller-bound transient workers.
- Lifecycle modules in [`src/`](../src/) coordinate activation, sensor
  operations, persistent state, and recovery under the biometric operation lock.
- BridgeXPC carries BiometricKit requests and sensor events over the private
  T2 network. AKS manages keybag identity; ACM supplies authorization contexts.
- [`src/t2_sep_transport.c`](../src/t2_sep_transport.c) owns PCI/BCE mailbox
  DMA and exposes a narrow allowlist of AKS/ACM operations. It is not a general
  raw SEP command channel.

Apple's bridgeOS and Secure Enclave firmware continue to run on the T2.
Linux owns the host-side account mapping, activation material, biometric
archives, and service integration. Matching occurs in SEP.

## Installation and startup

[`install-omarchy.sh`](../install-omarchy.sh) installs dependencies and invokes
[`install.sh`](../install.sh) for the desktop account. The latter installs the
Python environment under `/opt/t2-touchid`, DKMS modules, systemd units,
D-Bus access policy, and reversible PAM integration.

Before changing installed state, it rejects a different or unidentified
resident T2 transport. It also requires the running applesmc driver to publish
typed SEP boot state. If that capability is absent, it stages the included
[`applesmc-t2touch`](../packaging/applesmc-t2touch/README.md) prerequisite and
stops for a normal kernel restart. An on-disk module is not proof of a live
capability.

The installed native startup chain is:

```text
Bridge network preparation -> BiometricKit port discovery -> SEP transport
  -> native account setup/activation -> biometric readiness
  -> mutation reconciliation -> fprintd service
```

The [systemd units](../systemd/system/) enforce these dependencies.
`t2-native-first-run.service` creates or verifies the selected account;
`t2-biometric-ready.service` establishes usable biometric state;
`t2-touchid-post-reboot.service` reconciles eligible journals before
`fprintd.service` starts. A failed prerequisite prevents service exposure.
The installer starts this chain and installs PAM only after native fprintd
readiness succeeds.

Fresh installations select `linux-native` authority. Compatibility mode retains
an existing Apple authority and adds the imported keybag and encrypted-credential
services; it does not turn an existing fingerprint into a different inventory
type. There is no supported end-user migration command for macOS Touch ID state.

## Account authority and fingerprints

On blank authority, first run creates a Linux-owned SEP identity, saves its
keybag and activation material, then verifies it through a fresh userspace
owner before enabling the Linux account mapping. It does not overwrite an
existing authority. A fresh owner means new descriptors and authorization
contexts, not replacing the resident kernel transport or rebooting the machine.

First enrollment begins with an enabled account and empty fingerprint inventory.
It captures a fingerprint, persists the user/master Catacomb and rolling
BioLockout state, reconciles local and SEP inventories through a fresh Bridge
connection, and publishes runtime authority before returning success. Normal
enrollment therefore completes in the current session.

Account authority survives changes to the fingerprint set. Later enrollments
extend the reconciled inventory rather than requiring the first fingerprint
to remain present. Finger 1 through Finger 5 are stable neutral slots backed by
private template identities. The lock-held allocator chooses the lowest vacant
slot, and deletion never renumbers survivors. Any enrolled fingerprint may
satisfy authentication, regardless of its origin or the client's requested name.

Named deletion supports the final fingerprint. It reconciles an empty,
enrollable inventory, so the next enrollment uses Finger 1. Stable external
removal of the sole fingerprint is also reconciled without restoring it or
sending another deletion. Batch delete-all and private-state purge are not
exposed.

## Persistence and recovery

| Location | Responsibility |
| --- | --- |
| `/etc/t2-touchid.conf` | Protected account, transport, and installation configuration. |
| `/etc/credstore.encrypted/t2-touchid-password` | Encrypted credential supplied to the systemd service that needs it. |
| `/var/lib/t2-touchid` | Account mapping, activation bundles, keybags, Catacomb generations, mutation journals, and PAM backups. |
| `/run/t2-touchid` | Volatile operation state, locks, worker sockets, and readiness data. |

An activation bundle preserves the saved keybag and the 16-byte creation input
needed by a fresh ACM context. The bundle is private credential material; its
checksums detect inconsistent generations but do not encrypt its contents.

Mutation intent is journaled before dispatch. Completion requires the expected
identity set and committed paired state, not just a successful command return
or 100-percent capture progress. A failed client can leave a hardware operation
completed but its persistence unfinished. Recovery reconciles that existing
operation; it never blindly repeats an ambiguous enrollment or deletion.
Incomplete state blocks further mutation or authentication as appropriate.

A cached biometric endpoint is a routing hint only. Every connection validates
its RemoteXPC handshake and advertised service. Neither a cache entry nor a
previous match grants authority for a new operation.

## Privilege and authentication

A D-Bus claim is bound to its unique sender, kernel process identity, Linux
account generation, and session. PolicyKit grants and mapping capabilities are
rechecked at the worker boundary. A username or Finger N label is not authority
to mutate another account. Multi-user service exposure is not supported.

Credentials, keybags, and private template identifiers stay inside protected
service state. The desktop receives neutral inventory names, progress, and
validated operation results. Finger presence or transport success never counts
as authentication. Password fallback remains independently usable when
biometrics fail or the service is unavailable.

This Linux stack does not establish Apple's Secure Boot trust chain or provide
FileVault-equivalent guarantees. See [Security](../SECURITY.md).

## Updates, uninstall, and support limits

A matching-transport reinstall restarts the product's userspace services in the
current session. SEP retains registered DMA addresses, so a transport change
requires a planned kernel restart. [`uninstall.sh`](../uninstall.sh) restores
managed PAM state, removes the installed software and future transport startup,
and leaves a pinned live transport resident until the next kernel start.
It preserves private account and biometric state for reinstall.

The installer selects s2idle through systemd sleep policy. Deep-sleep recovery,
cross-macOS persistence of Linux-only fingerprints, multiple Linux users, and
additional hardware models are outside the demonstrated product scope.
Validation covers MacBookPro16,1. Clean-volume first activation of the packaged
applesmc prerequisite is not established by a reinstall on an already-capable
kernel. See [Troubleshooting](TROUBLESHOOTING.md) and
[Compatibility](COMPATIBILITY.md).
