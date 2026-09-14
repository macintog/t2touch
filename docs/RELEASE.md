# Validation record

This record describes completed checks and their limits. It is not a release
queue or an instruction to repeat hardware operations.

## Product behavior

Enrollment, named deletion through an empty inventory, password fallback, and
matching-transport userspace reinstall were demonstrated on MacBookPro16,1.
The installed TUI allocates the lowest vacant slot among Finger 1 through
Finger 5 and never renumbers survivors. Enrolled fingerprints immediately work
through fprintd, sudo, graphical PolicyKit, and the Omarchy lock screen.

A kernel without the typed applesmc boot-state publisher needs the included
DKMS prerequisite and one restart before installation completes. A different
or unidentified resident T2 transport stops installation before installed-state
changes. The installer does not unload SEP-pinned DMA or reboot the machine.

Uninstall restores PAM, stops userspace, disables future transport startup,
and preserves private state. A pinned live transport remains resident until
the next ordinary kernel start.

## Recorded validation

The integrated lifecycle review recorded 130 focused deletion-path tests and
1,173 full Python tests with one intentional skip, ShellCheck for installed
scripts, warning-free userspace and DKMS builds, privacy checks, and a passing
installed doctor. These are results for that source generation, not an assertion
that every later revision reran those checks.

Clean-volume first activation of the packaged applesmc prerequisite has not
been demonstrated by the acceptance runs below. The reference machine already
had a capable live driver. Broader hardware coverage remains unproven.

## Updated reference-machine acceptance — 2026-09-14

After updating to Omarchy `4.0.3-1`, the exact documented
`./install-omarchy.sh` entry point completed with exit status 0 on the
`MacBookPro16,1` reference system. It required no reboot, module unload, PCI
unbind, manual service sequencing, password entry, or fingerprint operation.
The installed daemon and product CLI matched the candidate source byte for
byte; the doctor passed every check; fprintd reported an enrollable empty
inventory; and the mutation registry reported no pending operation.

The included applesmc source applies to the current public
`linux-t2 7.2.4.arch1-2` package source and builds against the reference
`7.1.8.arch1-3` headers. An isolated DKMS add/build/install produced the
expected `updates/dkms/applesmc.ko` with all three typed boot-state parameters,
and an isolated DKMS removal removed that module while preserving source. The
reference system already boots a capable applesmc, so this run did not replace
its live driver or claim clean-volume first activation.

## Uninstall and reinstall acceptance — 2026-09-14

With the reference system in a clean, empty-inventory state, `./uninstall.sh`
restored the original PAM files, removed the product commands, units, future
transport startup, on-disk transport module, and owned boot configuration. It
preserved the root-private configuration, encrypted credential, user keybag,
provisioning journal, and identity state for a later reinstall. As required by
the transport safety contract, the SEP-pinned live transport remained resident;
the uninstaller did not unload it or unbind PCI devices.

The exact documented `./install-omarchy.sh` entry point then completed with exit
status 0 in the same running session. It rebuilt and installed Omarchy's
`linux-t2` unified kernel image, and inspection of that image confirmed that
`t2-sep-boot-state.conf` and both transport configuration files are present.
All four product services returned active and enabled, DKMS reported the
transport installed for the running kernel, the doctor passed every check,
fprintd reported an enrollable empty inventory, and every mutation queue was
empty and unblocked. No reboot, password entry, manual service sequencing, or
fingerprint operation was used.
