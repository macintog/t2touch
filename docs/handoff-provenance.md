# Sources and credits

t2touch builds on
[jmurth1234/t2-touchid-linux](https://github.com/jmurth1234/t2-touchid-linux/tree/ea46d8a0aef3e73b0e2f747aa18721dbcd265bce).
The starting revision is `ea46d8a0aef3e73b0e2f747aa18721dbcd265bce`. Its source,
history, and author notices are preserved under [GPL-2.0-only](../LICENSE), with
the Linux syscall-note exception on the userspace transport header.

[T1Bridge](https://github.com/standardagents/t1bridge/tree/7003b8d9f791) is a
reference for the native adoption research. Its top-level
[license](https://github.com/standardagents/t1bridge/blob/7003b8d9f791/LICENSE)
is MIT. The native implementation has not yet been imported into this checkout.

## Dependencies in the upstream implementation

| Dependency | Pinned revision | License |
| --- | --- | --- |
| [pymobiledevice3](https://github.com/doronz88/pymobiledevice3) | `4fcfdd82ffcf30b6a11460b505fadb5579e7b2bb` | [GPLv3](https://github.com/doronz88/pymobiledevice3/blob/4fcfdd82ffcf30b6a11460b505fadb5579e7b2bb/LICENSE) |
| [python-dbus-next](https://github.com/altdesktop/python-dbus-next) | `v0.2.3` | [MIT](https://github.com/altdesktop/python-dbus-next/blob/v0.2.3/LICENSE) |

The upstream [discovery helper](../src/discover-biometric-port.py), licensed
GPL-2.0-only, imports `RemoteXPCConnection` from the pinned pymobiledevice3
dependency. License compatibility for that combination remains unresolved.
