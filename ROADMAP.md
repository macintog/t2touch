# Product roadmap

t2touch is a working single-machine proof of concept. The next work is about
making the supported user experience broader and easier to distribute.

## v0.1

- [x] One-command Omarchy dependency and system installation
- [x] Automatic T2 interface detection and encrypted Linux-owned authority setup
- [x] Enrollment through the polished `t2touch enroll` terminal UI
- [x] Immediate use through fprintd, sudo, PolicyKit, and the Omarchy lock screen
- [x] Neutral `Finger N` slots with origin-independent verification and deletion
- [x] Password fallback and reversible PAM installation
- [x] Same-session upgrades and uninstall without a reboot
- [ ] Complete the release test, privacy, and documentation gates
- [ ] Publish experimental GitHub releases for t2touch and t2touch-mini

## Next

- Validate and document more Intel T2 Mac models.
- Package t2touch so users do not need a source checkout.
- Add a guided compatibility importer for machines retaining macOS Touch ID state.
- Preserve Linux-only additions across a later macOS boot.
- Support multiple Linux desktop users.
- Integrate enrollment into graphical desktop settings while retaining the TUI.
- Validate future `linux-t2` kernel upgrades through DKMS CI and real hardware.
