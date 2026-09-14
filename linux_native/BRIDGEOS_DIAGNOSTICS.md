# BridgeOS diagnostics from Linux

This note records the minimum read-only path used to correlate Linux SEP
traffic with matching bridgeOS `23P6068`. It is a continuity aid, not an
authentication component. Dynamic ports and device identifiers must never be
committed.

## Constrained sysdiagnose transport

Remote Service Discovery advertises `com.apple.sysdiagnose.remote` and
`com.apple.sysdiagnose.remote.trusted` over the T2 link-local interface. The
service accepts a numeric RemoteXPC dictionary:

- `MSG_TYPE = 1` means request;
- `REQUEST_TYPE = 1` means Sysdiagnose; and
- response dictionaries use `MSG_TYPE = 2`, with `RESPONSE_TYPE = 1` for
  success and `2` for failure.

The reference capture requested only the unified OS log archive. It set
`shouldRunOSLogArchive=true` and disabled log-copy, log-generation, and
time-sensitive task classes. Biometric, keybag, provisioning, and PAM paths
were not invoked.

The current `pymobiledevice3` RemoteXPC receiver needs two narrow framing
corrections for this service:

1. the unsolicited file announcement arrives on stream 1 while the duplicate
   requested reply arrives on stream 3; stream 3 is control traffic, not file
   payload; and
2. stream 2 begins with a 24-byte RemoteXPC wrapper. The announced `FILE_TX`
   size counts only the following archive, so those 24 bytes must be removed
   before validating the gzip payload.

The resulting ignored archive is
`linux_native/artifacts/bridgeos/live/sysdiagnose-oslog.tar.gz`, SHA-256
`a098226d91630c2b32cdc7869285935f640bfce55ed0697d1939cb515d6deb4c`.
It passed `gzip -t`. Mandiant's `macos-UnifiedLogs` at commit
`f250d5594da647e61bf563021eac4bc5255d325c` parsed 298,719 records without a
parser error. The archive and parsed JSONL remain ignored because they contain
private machine data.

## D016 time correlation

Linux boot `16b6bad4-194e-4e6a-bda4-1595347a4bf7` began at
`2026-09-01T15:21:25Z`. Its sole xART opcode-8 transaction returned `0x2d` at
`15:21:55Z`. The bridgeOS log archive retained the same bridge boot UUID that
was already active on 2026-08-31; rebooting Linux did not restart bridgeOS.

Within the verified D016 window, bridgeOS emitted no AppleSEPXART request,
gigalocker attach, xART-volume mount, or APFS probe corresponding to the new
host GPT entry. Across the retained APFS log history, the only device names are
bridgeOS `disk1`, `disk1s1`, and `disk1s5`; no host-disk partition appears. The
three USER-xART writes at `15:15Z` predate the Linux reboot and correlate with
separate MobileActivation diagnostic connections, so they are not D016
evidence.

An earlier boot window provides the decisive namespace observation. Ramrod
logged `Using device path /dev/disk0 for EmbeddedDeviceTypeRoot`, identified
`/dev/disk0s1` as the APFS container, and followed it to synthesized `disk1`.
Its subsequent volume inventory contains no xART. Ramrod's static traversal is
rooted at that I/O Registry object; it is not a generic scan of Linux-visible
block devices. D016's Linux `/dev/nvme0n1p3` is therefore outside the creator's
namespace.

This supersedes the proposed restart-only discriminator. A fresh bridgeOS boot
would rescan the same embedded container and cannot turn the host-side D016
partition into xART. Matching normal software updates explicitly suppress
filesystem-partition creation; the next meaningful transition must run the
creator through a non-erasing full-IPSW restore/revive path. See
[`BRIDGEOS_UPDATE_XART_RECOVERY.md`](BRIDGEOS_UPDATE_XART_RECOVERY.md).

The advertised DVT process-control channel was also checked once as a possible
read-only mount-table source. This bridgeOS build canceled that channel with
code `-1` before launching a process. Do not retry it; the unified-log archive
is the supported evidence path recovered here.

## Post-DFU-Revive observation

Apple Finder DFU Revive completed at `2026-09-01 20:58:08 +0000`. A second
constrained OS-log archive was collected after the resulting bridgeOS boot and
parsed without an error. It remains ignored because it contains private
machine data; the archive SHA-256 is
`59863bf36c3acec1d021ad51196d87c89f8f2f5ce8d155e445129d42d8d5ffd3`.

The fresh boot probes `EmbeddedDeviceTypeRoot`, follows `/dev/disk0s1` to
synthesized `disk1`, and reports System, Preboot, the encrypted user volume,
and Hardware. It never reports an xART volume or xART slice. No xART mount,
gigalocker initialization, or gigalocker-online event occurs after the restore
time. This is direct negative evidence: non-erasing DFU Revive did not create
the missing xART/gigalocker backing on the reference Mac.

## Post-macOS-provisioning observation

A later OS-log-only archive was collected from Linux after the temporary macOS
control had provisioned its account. The root-private gzip contains 335,784
parsed records. Exactly 149 records match the bounded xART/gigalocker/APFS
filter; raw JSONL and private identifiers remain outside Git.

The retained bridge boots now mount an embedded APFS volume named `xART` as
`disk1s3`. At the detailed 2026-09-01 22:05 UTC boot, mount completed at
22:05:47.572, bypass mode was enabled on the xART inode at 22:05:48.217, and
SEP-xART plus USER-xART were fetched at 22:05:48.542–.543. Subsequent records
show USER-xART and USER-xART-locker saves. BiometricKit repeatedly queries
`IsXARTAvailable` with a one-byte output.

Launchd logged its `data-protection` boot task at 22:05:43.285, four seconds
before the xART mount. No `seputil`, gigalocker-init, or creator record appears
in that boot window. This directly correlates normal boot's data-protection
stage with mount, bypass attachment, and xART consumption while preserving the
static conclusion that creation happened earlier.

This is decisive before/after evidence. Finder DFU Revive left the same T2
embedded container without xART; macOS provisioning left it with a mounted,
live xART volume and locker backing. The archive does not retain the original
creator moment. Its sole `newfs_apfs Success` belongs to `usermanagerd` after
xART was already online and is not evidence of xART creation. Do not infer a
normal-mode creator from that line.
