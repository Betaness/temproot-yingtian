"""Build libtemproot.so for every configured Android ABI with the pinned NDK.

The NDK is resolved from --ndk, then TEMPROOT_NDK, then the research workspace
copy used by android-kernel/. Nothing is installed globally.

Outputs (all reproducible given the same NDK + sources):
  dist/lib/<abi>/libtemproot.so
  dist/native-build.json   (per-file sha256, compiler version, flags)
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = [
    'tr_common.c', 'tr_probe.c', 'tr_build_db.c', 'tr_guard.c', 'tr_btf.c',
    'tr_layout.c', 'tr_timer_exec.c', 'tr_verify.c', 'tr_rootd.c', 'tr_jni.c',
]
ABIS = {
    'arm64-v8a': 'aarch64-linux-android26',
    'x86_64': 'x86_64-linux-android26',
}
COMMON_FLAGS = [
    '-fPIC', '-O2', '-fvisibility=hidden', '-ffunction-sections',
    '-fdata-sections', '-Wall', '-Wextra', '-Wno-unused-parameter',
    '-Wno-sign-compare', '-std=c11', '-D_FILE_OFFSET_BITS=64',
]
LINK_FLAGS = [
    '-shared',
    # Android 16+ devices may use 16 KiB pages; keep the segment alignment valid
    # for both 4 KiB and 16 KiB page kernels.
    '-Wl,-z,max-page-size=16384',
    '-Wl,--hash-style=both',
    '-Wl,--gc-sections',
    '-lz',
]
# Symbols the JVM must be able to dlsym: keep them despite -fvisibility=hidden.
EXPORT_MAP = 'temproot.map'


def find_ndk(explicit):
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    if os.environ.get('TEMPROOT_NDK'):
        candidates.append(Path(os.environ['TEMPROOT_NDK']))
    candidates.append(ROOT.parent / 'android-kernel/.tools/ndk/android-ndk-r27c')
    candidates.append(Path(r'C:\Android\ndk'))
    for candidate in candidates:
        if (candidate / 'toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe').exists():
            return candidate
        if (candidate / 'toolchains/llvm/prebuilt/linux-x86_64/bin/clang').exists():
            return candidate
    raise FileNotFoundError('NDK not found; pass --ndk <path to android-ndk-r27c>')


def tool(ndk, name):
    for host in ('windows-x86_64', 'linux-x86_64', 'darwin-x86_64'):
        base = ndk / 'toolchains/llvm/prebuilt' / host / 'bin'
        for suffix in ('.exe', ''):
            candidate = base / (name + suffix)
            if candidate.exists():
                return candidate
    raise FileNotFoundError(name)


def write_export_map(path):
    # Version script equivalent for lld: only JNI entry points are exported.
    symbols = [
        'Java_org_fujiang_temproot_NativeBridge_nativeVersion',
        'Java_org_fujiang_temproot_NativeBridge_nativeInit',
        'Java_org_fujiang_temproot_NativeBridge_nativeProbe',
        'Java_org_fujiang_temproot_NativeBridge_nativeLayoutReport',
        'Java_org_fujiang_temproot_NativeBridge_nativeTimerProbe',
        'Java_org_fujiang_temproot_NativeBridge_nativeTrigger',
        'Java_org_fujiang_temproot_NativeBridge_nativeApplyEvidence',
        'Java_org_fujiang_temproot_NativeBridge_nativeVerify',
        'Java_org_fujiang_temproot_NativeBridge_nativeRootdStart',
        'Java_org_fujiang_temproot_NativeBridge_nativeRootdPing',
        'Java_org_fujiang_temproot_NativeBridge_nativeRootdStop',
        'Java_org_fujiang_temproot_NativeBridge_nativeSu',
        'Java_org_fujiang_temproot_NativeBridge_nativeLogDrain',
        # JNI_OnLoad must stay visible or System.loadLibrary fails.
        'JNI_OnLoad',
    ]
    path.write_text('{\n  global:\n' + ''.join(f'    {s};\n' for s in symbols) +
                    '  local:\n    *;\n};\n', encoding='ascii')


def run(cmd, **kwargs):
    result = subprocess.run([str(c) for c in cmd], capture_output=True, text=True,
                            encoding='utf-8', errors='replace', **kwargs)
    if result.stdout.strip():
        print(result.stdout.strip())
    if result.returncode != 0:
        if result.stderr.strip():
            print(result.stderr.strip(), file=sys.stderr)
        raise RuntimeError(f'{Path(str(cmd[0])).name} failed ({result.returncode})')
    return (result.stdout + result.stderr).strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ndk', default=None)
    parser.add_argument('--abis', nargs='*', default=list(ABIS))
    args = parser.parse_args()

    ndk = find_ndk(args.ndk)
    clang = tool(ndk, 'clang')
    strip = tool(ndk, 'llvm-strip')
    include = ndk / 'toolchains/llvm/prebuilt'
    sysroot_include = None
    for host in ('windows-x86_64', 'linux-x86_64', 'darwin-x86_64'):
        candidate = include / host / 'sysroot/usr/include'
        if candidate.exists():
            sysroot_include = candidate
            break
    if sysroot_include is None:
        raise FileNotFoundError('NDK sysroot include directory not found')

    out_root = ROOT / 'dist'
    build_dir = ROOT / 'build' / 'native'
    build_dir.mkdir(parents=True, exist_ok=True)
    export_map = build_dir / EXPORT_MAP
    write_export_map(export_map)

    compiler_version = run([clang, '--version']).splitlines()[0]
    results = {
        'ndk_version': (ndk / 'source.properties').read_text(encoding='utf-8').strip().splitlines()[-1],
        'compiler': compiler_version,
        'flags': COMMON_FLAGS + LINK_FLAGS,
        'abis': {},
    }

    for abi in args.abis:
        triple = ABIS[abi]
        dest = out_root / 'lib' / abi
        dest.mkdir(parents=True, exist_ok=True)
        obj_dir = build_dir / abi
        obj_dir.mkdir(parents=True, exist_ok=True)
        objects = []
        for source in SOURCES:
            obj = obj_dir / (Path(source).stem + '.o')
            cmd = [clang, f'--target={triple}', *COMMON_FLAGS,
                   '-I', ROOT / 'native', '-I', sysroot_include,
                   '-c', ROOT / 'native' / source, '-o', obj]
            run(cmd)
            objects.append(obj)
        so = dest / 'libtemproot.so'
        run([clang, f'--target={triple}', *COMMON_FLAGS, *objects,
             f'-Wl,--version-script={export_map}', *LINK_FLAGS, '-o', so])
        size_before = so.stat().st_size
        run([strip, '--strip-unneeded', so])
        sha = hashlib.sha256(so.read_bytes()).hexdigest()
        results['abis'][abi] = {
            'so': str(so.relative_to(ROOT)).replace('\\', '/'),
            'sha256': sha,
            'size_before_strip': size_before,
            'size': so.stat().st_size,
            'triple': triple,
        }
        print(f'{abi}: {so}  {results["abis"][abi]["size"]} bytes  sha256={sha}')

    (out_root / 'native-build.json').write_text(
        json.dumps(results, indent=2, ensure_ascii=False), encoding='utf-8')
    print(json.dumps({'abis': list(results['abis'])}, ensure_ascii=False))


if __name__ == '__main__':
    main()
