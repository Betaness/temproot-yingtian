"""Static consistency checks between Java declarations and the native library.

Catches the failure mode that only shows up on the device as
UnsatisfiedLinkError: a native method without a matching exported symbol.
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NDK = ROOT.parent / 'android-kernel/.tools/ndk/android-ndk-r27c'


def find_readelf():
    for host in ('windows-x86_64', 'linux-x86_64'):
        for name in ('llvm-readelf.exe', 'llvm-readelf'):
            p = NDK / 'toolchains/llvm/prebuilt' / host / 'bin' / name
            if p.exists():
                return p
    raise FileNotFoundError('llvm-readelf not found in the NDK')


def exported_symbols(readelf, so):
    out = subprocess.run([str(readelf), '--dyn-syms', str(so)], capture_output=True,
                         text=True, encoding='utf-8', errors='replace').stdout
    names = set()
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[-1].startswith(('Java_', 'JNI_')):
            names.add(parts[-1])
    return names


def declared_natives(java_file):
    text = java_file.read_text(encoding='utf-8')
    return sorted(re.findall(r'native\s+[\w\[\]<>.]+\s+(\w+)\s*\(', text))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--abi', default='arm64-v8a')
    args = parser.parse_args()

    readelf = find_readelf()
    so = ROOT / 'dist/lib' / args.abi / 'libtemproot.so'
    if not so.exists():
        raise SystemExit(f'{so} missing')
    symbols = exported_symbols(readelf, so)
    bridge = ROOT / 'app/src/org/fujiang/temproot/NativeBridge.java'
    natives = declared_natives(bridge)

    package_path = 'Java_org_fujiang_temproot_NativeBridge_'
    missing = [n for n in natives if f'{package_path}{n}' not in symbols]
    extra = sorted(s for s in symbols
                   if s.startswith('Java_') and s.rsplit('_', 1)[-1] not in natives)

    print(f'ABI {args.abi}: {so.stat().st_size} bytes')
    print(f'native declarations: {len(natives)}')
    print(f'exported JNI symbols: {len([s for s in symbols if s.startswith("Java_")])}')
    print(f'JNI_OnLoad exported: {"JNI_OnLoad" in symbols}')
    if missing:
        print('MISSING SYMBOLS: ' + ', '.join(missing), file=sys.stderr)
    if extra:
        print('UNUSED EXPORTS: ' + ', '.join(extra))

    # Dependency whitelist: only bionic basics plus zlib.
    dyn = subprocess.run([str(readelf), '-d', str(so)], capture_output=True, text=True,
                         encoding='utf-8', errors='replace').stdout
    needed = re.findall(r'NEEDED.*?\[(.*?)\]', dyn)
    allowed = {'libc.so', 'libm.so', 'libdl.so', 'libz.so', 'liblog.so'}
    unexpected = [n for n in needed if n not in allowed]
    print('NEEDED: ' + ', '.join(needed))
    if unexpected:
        print('UNEXPECTED DEPENDENCIES: ' + ', '.join(unexpected), file=sys.stderr)

    # Text relocations break modern loaders.
    if 'TEXTREL' in dyn:
        print('TEXTREL present', file=sys.stderr)
        raise SystemExit(1)

    if missing or unexpected:
        raise SystemExit(1)
    print('OK: every declared native method is exported')


if __name__ == '__main__':
    main()
