# Sources and credits

t2touch builds on
[jmurth1234/t2-touchid-linux](https://github.com/jmurth1234/t2-touchid-linux/tree/ea46d8a0aef3e73b0e2f747aa18721dbcd265bce).
The starting revision is `ea46d8a0aef3e73b0e2f747aa18721dbcd265bce`. Its source,
history, and author notices are preserved under [GPL-2.0-only](../LICENSE), with
the Linux syscall-note exception on the userspace transport header.

[T1Bridge](https://github.com/standardagents/t1bridge/tree/7003b8d9f791) is a
reference for the native adoption research. Its top-level
[license](https://github.com/standardagents/t1bridge/blob/7003b8d9f791/LICENSE)
is MIT. It was used as comparison evidence where protocol-family behavior
agreed; T2-specific credential forms, request layouts, and hardware claims were
derived and validated separately. The completed native implementation imported
here is recorded by engineering revision
`d821b087658792b863fef35336c871d494709961` and remains GPL-2.0-only.

The original [research documentation](research/README.md) is available under its
own [MIT license](research/LICENSE), also in t2touch-mini. Its
[artifact and tool credits](research/artifacts-and-method.md) identify the analyzed
firmware and the open-source tools used. This documentation license does not
change the license of the inherited implementation.

## Dependencies in the upstream implementation

| Dependency | Pinned revision | License |
| --- | --- | --- |
| [pymobiledevice3](https://github.com/doronz88/pymobiledevice3) | `4fcfdd82ffcf30b6a11460b505fadb5579e7b2bb` | [GPLv3](https://github.com/doronz88/pymobiledevice3/blob/4fcfdd82ffcf30b6a11460b505fadb5579e7b2bb/LICENSE) |
| [python-dbus-next](https://github.com/altdesktop/python-dbus-next) | `v0.2.3` | [MIT](https://github.com/altdesktop/python-dbus-next/blob/v0.2.3/LICENSE) |

The upstream [discovery helper](../src/discover-biometric-port.py), licensed
GPL-2.0-only, imports `RemoteXPCConnection` from the pinned pymobiledevice3
dependency. License compatibility for that combination remains unresolved.

## Install-time Python provenance

`install.sh` installs the root daemon venv through the same helper as CI:

```sh
# The helper resolves the repository root for the file: wheel path.
tools/install-python-deps.sh /path/to/venv/bin/python
```

`requirements-hashed.txt` pins the runtime packages, including
`dbus-next==0.2.3`, `cryptography`, `construct`, and the rest of the
pymobiledevice3 dependency tree. PyPI artifacts are locked by SHA-256.
`pymobiledevice3` is accepted only as the vendored wheel
`vendor/python/pymobiledevice3-11.1.3-py3-none-any.whl`, referenced by a
`file:` URL in the lock so pip cannot substitute the PyPI 11.1.3 wheel
(digest `6d6da2f7…`). The vendored artifact was built with
`pip wheel --no-deps` from
`4fcfdd82ffcf30b6a11460b505fadb5579e7b2bb` with Python 3.14.7.
The GitHub sdist/archive cannot satisfy `setuptools_scm` without a `.git`
directory, so that commit is shipped as a wheel rather than cloned at
install time.

There is no second unhashed `pip install`. Transitive versions cannot
float: `--require-hashes` refuses any file whose digest is not listed.
The supported CI interpreters are Python 3.12 and 3.14 on Linux. The lock
includes `sslpsk-pmd3` for Python <3.13 and `backports.zstd` for Python
>=3.10,<3.14, matching the vendored wheel metadata. Validate resolution for
both CI interpreters when regenerating; a lock resolved only on 3.14 misses
these conditional dependencies. `test_provenance_lock` checks every direct
wheel dependency against the lock under both interpreter environments.

The helper first installs `setuptools==80.9.0` and `wheel==0.45.1` from
`requirements-build-hashed.txt`, requiring hashed wheels only. The runtime
installation then uses `--no-build-isolation`: pip must use that installed
backend and cannot silently fetch unpinned build dependencies. This matters
for source-only `hexdump` and the Python 3.14 builds of `lzfse` and `pylzss`.
Both locks and the helper participate in the installer freshness stamp.
Source compilation still uses the host compiler and headers; the lock does
not claim reproducible compiler output.

The vendored wheel redistributes the GPL-3.0-or-later pymobiledevice3 dependency. The
GPL-2.0-only/GPLv3 compatibility issue above remains unresolved; pinning and
hashing the artifact do not resolve licensing or redistribution obligations.
