"""Temporary root via a one-shot boot image (no partition is written).

Why this path exists: on a release Xiaomi firmware the only deterministic way to
hold root for one boot session is to boot a patched kernel image through
`fastboot boot`. Nothing is flashed, the bootloader slot is untouched, and a
plain reboot returns the device to its stock kernel. That is exactly the
"temporary root" semantic this project needs.

Steps performed by `run`:
  1. verify the device is visible to adb and fastboot
  2. verify the bootloader is unlocked (ro.boot.verifiedbootstate == orange)
  3. identify the active slot and the boot partition node
  4. pull boot.img and hash it (evidence record)
  5. `fastboot boot <patched image>` - one boot session only
  6. verify uid 0 through adb shell

The patched image must be produced locally from *your own* pulled boot.img
(Magisk app: Install -> Select and Patch a File, or KernelSU's manager). This
script never uploads anything and never flashes.
"""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

DEFAULT_ADB = r'C:\Program Files (x86)\SDK_TOOL\platform-tools\adb.exe'
DEFAULT_FASTBOOT = r'C:\Program Files (x86)\SDK_TOOL\platform-tools\fastboot.exe'


def tool(explicit, default, name):
    if explicit:
        return explicit
    if shutil.which(name):
        return shutil.which(name)
    if Path(default).exists():
        return default
    raise SystemExit(f'{name} not found; pass --{name} <path>')


def run(cmd, timeout=120, check=True):
    result = subprocess.run([str(c) for c in cmd], capture_output=True, text=True,
                            encoding='utf-8', errors='replace', timeout=timeout)
    out = (result.stdout or '').strip()
    err = (result.stderr or '').strip()
    if check and result.returncode != 0:
        raise SystemExit(f'{Path(str(cmd[0])).name} failed ({result.returncode}): {err or out}')
    return out if out else err


def shell(adb, command):
    return run([adb, 'shell', command])


def cmd_check(args):
    adb = tool(args.adb, DEFAULT_ADB, 'adb')
    fastboot = tool(args.fastboot, DEFAULT_FASTBOOT, 'fastboot')
    info = {'adb': adb, 'fastboot': fastboot}

    devices = run([adb, 'devices'])
    info['adb_devices'] = devices.splitlines()[1:] if devices else []
    if not any(line.strip().endswith('device') for line in info['adb_devices']):
        info['state'] = 'NO_ADB_DEVICE'
        print(json.dumps(info, indent=2, ensure_ascii=False))
        return 1

    info['serial'] = run([adb, 'get-serialno'], check=False)
    info['product_device'] = shell(adb, 'getprop ro.product.device')
    info['build_fingerprint'] = shell(adb, 'getprop ro.build.fingerprint')
    info['kernel_release'] = shell(adb, 'uname -r')
    info['verified_boot_state'] = shell(adb, 'getprop ro.boot.verifiedbootstate')
    info['slot'] = shell(adb, 'getprop ro.boot.slot_suffix')
    info['adb_uid'] = shell(adb, 'id')
    info['boot_partition'] = shell(adb, 'ls -l /dev/block/by-name/boot' + info['slot'])

    unlocked = info['verified_boot_state'].strip() == 'orange'
    info['bootloader_unlocked'] = unlocked
    if not unlocked:
        info['state'] = 'LOCKED_BOOTLOADER'
        info['note_zh'] = ('引导程序已锁定（verifiedbootstate=%s）。此状态下 fastboot boot 会被拒绝，'
                           '也无法加载任何未签名镜像；内核漏洞路径又会被 KASAN 直接 panic。'
                           '结论：本机当前固件上不存在可用的临时 root 路径。' % info['verified_boot_state'])
    else:
        info['state'] = 'READY'
        info['note_zh'] = '引导程序已解锁，可以执行一次性的 fastboot boot（不写分区）。'
    print(json.dumps(info, indent=2, ensure_ascii=False))
    return 0 if unlocked else 2


def cmd_pull(args):
    adb = tool(args.adb, DEFAULT_ADB, 'adb')
    slot = shell(adb, 'getprop ro.boot.slot_suffix').strip() or '_a'
    node = f'/dev/block/by-name/boot{slot}'
    out = Path(args.out or f'boot{slot}.img')
    run([adb, 'pull', node, str(out)])
    data = out.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    record = {'node': node, 'file': str(out), 'bytes': len(data), 'sha256': digest,
              'kernel_release': shell(adb, 'uname -r')}
    Path(str(out) + '.sha256').write_text(f'{digest}  {out.name}\n', encoding='ascii')
    print(json.dumps(record, indent=2, ensure_ascii=False))
    return 0


def cmd_boot(args):
    adb = tool(args.adb, DEFAULT_ADB, 'adb')
    fastboot = tool(args.fastboot, DEFAULT_FASTBOOT, 'fastboot')
    image = Path(args.image)
    if not image.exists():
        raise SystemExit(f'image not found: {image}')
    state = shell(adb, 'getprop ro.boot.verifiedbootstate').strip()
    if state != 'orange':
        raise SystemExit(f'bootloader is not unlocked (verifiedbootstate={state}); refusing')
    if args.expected_sha256:
        actual = hashlib.sha256(image.read_bytes()).hexdigest()
        if actual != args.expected_sha256:
            raise SystemExit(f'sha256 mismatch: {actual}')
        print(f'sha256 verified: {actual}')

    print('rebooting into bootloader for a one-shot boot (no flash)')
    run([adb, 'reboot', 'bootloader'])
    run([fastboot, 'wait-for-device'.replace('-device', 'device')], timeout=180, check=False)
    out = run([fastboot, 'boot', str(image)], timeout=300, check=False)
    print(out)
    if 'error' in out.lower() or 'failed' in out.lower():
        raise SystemExit('fastboot boot failed; nothing was written, the device can simply be rebooted')
    run([adb, 'wait-for-device'], timeout=300, check=False)
    for _ in range(60):
        uid = shell(adb, 'id')
        if 'uid=0' in uid:
            print('root acquired for this boot session only:', uid)
            print(shell(adb, 'cat /proc/version'))
            return 0
        import time
        time.sleep(2)
    print('booted, but adb shell is not uid=0; check the patched image and its manager app')
    return 1


def cmd_verify(args):
    adb = tool(args.adb, DEFAULT_ADB, 'adb')
    out = {
        'id': shell(adb, 'id'),
        'kernel': shell(adb, 'uname -a'),
        'selinux': shell(adb, 'getenforce'),
        'manager': shell(adb, 'ls -d /data/adb/* 2>/dev/null'),
    }
    out['root'] = 'uid=0' in out['id']
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0 if out['root'] else 1


def main():
    parser = argparse.ArgumentParser(description='One-shot temporary root via fastboot boot')
    parser.add_argument('--adb', default=None)
    parser.add_argument('--fastboot', default=None)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('check', help='report device state, unlock state and slot')
    pull = sub.add_parser('pull', help='pull the active boot image as evidence')
    pull.add_argument('--out', default=None)
    boot = sub.add_parser('boot', help='boot a patched image for one session only')
    boot.add_argument('--image', required=True)
    boot.add_argument('--expected-sha256', default=None)
    sub.add_parser('verify', help='verify root on the running session')
    args = parser.parse_args()
    return {'check': cmd_check, 'pull': cmd_pull, 'boot': cmd_boot,
            'verify': cmd_verify}[args.command](args)


if __name__ == '__main__':
    sys.exit(main())
