#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Apply a reversible readiness-message fix to compatible Omarchy lock UI code."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

MARKER = '// t2touch PAM readiness integration v1'


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Omarchy lock source differs from the supported integration points')
    return text.replace(old, new, 1)


def transform(service, view):
    if MARKER in service and MARKER in view:
        return service, view
    if MARKER in service or MARKER in view:
        raise ValueError('partial Omarchy lock integration; restore its backup first')
    service = replace_once(service, '  property bool fingerprintConfigured: false',
        '  ' + MARKER + '\n  property string fingerprintMessage: ""\n  property bool fingerprintWakeUsed: false\n  property bool fingerprintConfigured: false')
    service = replace_once(service, '    lockRequested = true\n    armBlankTimer()',
        '    lockRequested = true\n    fingerprintWakeUsed = false\n    armBlankTimer()')
    service = replace_once(service, '    fingerprintAuthenticating = true\n',
        '    fingerprintMessage = ""\n    fingerprintAuthenticating = true\n')
    service = replace_once(service, '    id: fingerprintPam\n    config: "omarchy-lock-fingerprint"',
        '''    id: fingerprintPam
    onPamMessage: {
      root.fingerprintMessage = message
      // Wake once for the first placement prompt. Later retries must not
      // repeatedly wake an unattended laptop. No translated text matching.
      if (root.lockRequested && !root.fingerprintWakeUsed && !messageIsError
          && !responseRequired && message.length > 0) {
        root.fingerprintWakeUsed = true
        root.runWake()
      }
    }
    config: "omarchy-lock-fingerprint"''')
    needle = 'fingerprintConfigured: root.fingerprintConfigured'
    if service.count(needle) != 2:
        raise ValueError('Omarchy lock view bindings changed')
    service = service.replace(needle, needle + '\n        fingerprintMessage: root.fingerprintMessage')
    service = replace_once(service, 'grep -qi finger', "grep -Eq '^[[:space:]]*-[[:space:]]*#[0-9]+:'")
    view = replace_once(view, '  property bool fingerprintConfigured: false',
        '  ' + MARKER + '\n  property string fingerprintMessage: ""\n  property bool fingerprintConfigured: false')
    view = replace_once(view, '    BorderSurface {', '''    Text {
      anchors.horizontalCenter: parent.horizontalCenter
      anchors.top: parent.verticalCenter
      anchors.topMargin: root.fieldHeight / 2 + 16
      width: Math.min(parent.width - 32, root.fieldWidth + 100)
      visible: root.fingerprintConfigured
      text: root.fingerprintMessage || "Preparing fingerprint reader…"
      textFormat: Text.PlainText
      wrapMode: Text.WordWrap
      horizontalAlignment: Text.AlignHCenter
      color: Color.lock.text
      font.family: Style.font.family
      font.pixelSize: Math.round(root.fieldFontSize * 0.65)
    }

    BorderSurface {''')
    return service, view



def transform_polkit(text):
    if MARKER in text:
        return text
    text = replace_once(text, '  property string currentSupplementary: ""',
        '  ' + MARKER + '\n  property string currentSupplementary: ""')
    anchor = '    Rectangle {\n      width: Math.min(justificationText.implicitWidth'
    addition = """    Rectangle {
      visible: root.fingerprintMode
      width: Math.min(Style.space(360), panel.width - Style.gapsOut * 2)
      height: readinessText.implicitHeight + Style.space(16)
      anchors.horizontalCenter: card.horizontalCenter
      anchors.top: card.bottom
      anchors.topMargin: Style.space(10)
      radius: root.cornerRadius
      color: root.background
      Text {
        id: readinessText
        anchors.centerIn: parent
        width: parent.width - Style.space(24)
        text: root.currentSupplementary || "Preparing fingerprint reader…"
        textFormat: Text.PlainText
        wrapMode: Text.WordWrap
        horizontalAlignment: Text.AlignHCenter
        color: root.foreground
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
      }
    }

"""
    return replace_once(text, anchor, addition + anchor)


def atomic_write(path, data, mode, owner=None):
    fd, temporary = tempfile.mkstemp(prefix='.t2touch-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            os.fchmod(stream.fileno(), mode)
            if owner is not None:
                os.fchown(stream.fileno(), *owner)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run through the Omarchy installer (requires root).')
    root = Path(sys.argv[1] if len(sys.argv) > 1 else '/usr/share/omarchy')
    directory = root / 'shell/plugins/lock'
    paths = [directory / 'Service.qml', directory / 'LockView.qml',
             root / 'shell/plugins/polkit/PolkitAgent.qml']
    if not all(path.is_file() and not path.is_symlink() for path in paths):
        print('Omarchy lock UI integration skipped: supported QML files not present.')
        return
    originals = [path.read_bytes() for path in paths]
    try:
        lock = transform(*(data.decode() for data in originals[:2]))
        changed = [text.encode() for text in (*lock, transform_polkit(originals[2].decode()))]
    except (ValueError, UnicodeError) as error:
        print(f'Omarchy lock UI integration skipped: {error}. No files changed.')
        return
    if changed == originals:
        print('Omarchy authentication UI readiness integration is already installed.')
        return
    digest = hashlib.sha256(b'\0'.join(originals)).hexdigest()
    backup = Path('/var/lib/t2-touchid/omarchy-ui-backups') / digest
    backup.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = [path.stat() for path in paths]
    modes = [info.st_mode & 0o777 for info in metadata]
    owners = [(info.st_uid, info.st_gid) for info in metadata]
    for path, data in zip(paths, originals):
        saved = backup / path.name
        if saved.exists() and saved.read_bytes() != data:
            raise SystemExit('Omarchy UI backup conflict; no files changed.')
        atomic_write(saved, data, 0o600)
    record = {'paths': [str(path) for path in paths],
              'installed_sha256': [hashlib.sha256(data).hexdigest() for data in changed]}
    atomic_write(backup / 'receipt.json', (json.dumps(record) + '\n').encode(), 0o600)
    try:
        # Add the view property before its service binding.
        for index in (1, 0, 2):
            atomic_write(paths[index], changed[index], modes[index], owners[index])
    except BaseException:
        for path, data, mode, owner in zip(paths, originals, modes, owners):
            atomic_write(path, data, mode, owner)
        raise
    print(f'Omarchy authentication UI readiness installed; originals: {backup}')
    print('The UI change takes effect when the Omarchy shell next starts.')

if __name__ == '__main__':
    main()
