# t2touch

A proof of concept for setting up Touch ID from Linux on Intel Macs with Apple T2
chips, without importing macOS user or fingerprint data.

The research implementation has demonstrated native enrollment, persistence across
reboot, matching, and deletion on the reference T2 Mac. Its source import is still
being prepared; this checkout contains source from the original, macOS-assisted
project and the native research documentation.

- [About the work](HANDOFF.md)
- [SEP architecture and native-adoption research](docs/research/README.md)
- [Sources and credits](docs/handoff-provenance.md)
- [Community use](SUPPORT.md)

## Upstream foundation

This project builds on
[jmurth1234/t2-touchid-linux](https://github.com/jmurth1234/t2-touchid-linux/tree/ea46d8a0aef3e73b0e2f747aa18721dbcd265bce),
with its history and [GPL-2.0-only license](LICENSE) preserved.

The original documentation in [docs/research](docs/research/README.md) is separately
[MIT licensed](docs/research/LICENSE) and is also included in t2touch-mini.

The [upstream installation guide](https://github.com/jmurth1234/t2-touchid-linux/blob/ea46d8a0aef3e73b0e2f747aa18721dbcd265bce/README.md)
describes the macOS-assisted workflow included in this checkout.
