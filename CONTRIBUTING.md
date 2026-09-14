# Contributing

This project handles authentication state and machine-specific Apple keybag
material. Contributions should be small, reviewable, fail closed, and usable
without access to another person's private captures.

## Pick a work lane

- **Hardware-free:** parsers, state machines, tests, documentation, packaging,
  fuzzing, and privacy tooling.
- **Read-only hardware:** capability discovery, inventory, diagnostics, and
  reproducibility across Mac and bridgeOS versions.
- **Authentication:** positive and negative verification controls. Keep a
  password fallback and an authenticated recovery terminal available.
- **Mutation research:** enrollment, rename, deletion, or keybag changes. Use
  only an explicitly designated research Mac with macOS recovery available.

Do not turn a read-only task into an authentication or mutation experiment in
the same change. Hardware-affecting commands must retain their explicit
acknowledgements and preflight checks.

## Development setup

```sh
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m py_compile src/*.py tests/*.py
.venv/bin/python -m unittest discover -s tests
make -C src t2-aks-tool
tools/privacy-check.sh
enrollment_research/scripts/check-public-tree.sh
```

Run ShellCheck when it is available:

```sh
shellcheck install.sh uninstall.sh src/*.sh tools/*.sh tools/macos/*.sh
```

Kernel-module builds additionally require headers for the running kernel. Unit
tests and the userspace build do not prove that a module is safe to load.

## Public evidence

Start with the [architecture](docs/ARCHITECTURE.md),
[fprintd contracts](docs/FPRINT_INTEGRATION.md), and
[protocol research](docs/research/README.md). Keep hardware
claims tied to a named platform, source revision, client boundary, and retained
redacted evidence.

For another Mac or bridge generation, follow
[`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md). Add protocol-version or
capability evidence before adding model conditionals; one untested manifest
entry is not a support claim.

A hardware report should identify the kernel, T2 transport revision, expected
result, observed result, and recovery behavior. Report positive and negative
controls together and distinguish source checks from hardware observations.

Never commit or publish keybags, Catacombs, credentials, packet captures,
Apple binaries, raw BridgeXPC replies, biometric payloads, device addresses,
identity UUIDs, or other stable identifiers. Use only the project's redacted
diagnostic output, and manually inspect it before sharing.

## Change shape

- Keep protocol codecs separate from transport and policy.
- Reject unknown fields, states, opcodes, response shapes, and ownership.
- Record mutation intent before dispatch; never infer success from a command
  return when independent read-back is possible.
- Add negative tests for malformed, stale, replayed, cross-user, timeout, and
  interrupted-operation cases.
- Do not add a generic raw SEP command interface to make experimentation
  easier. Extend a narrow allowlist with a documented operation instead.
- Keep upstream-facing kernel changes independent of PAM and distro policy.

Each pull request should state its hardware risk level, tests run, hardware and
firmware coverage, user-visible failure mode, and recovery path. Kernel
transport, biometric protocol, fprintd integration, and distribution packaging
have different review boundaries; keep changes scoped to the layer they affect.
