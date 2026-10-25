"""Build the TemporaryRoot APK with pinned Android SDK tools (no Gradle).

Reuses the pipeline that was already validated on the target device by the
previous research round (aapt2 + javac + D8 + zipalign + apksigner), extended
with native libraries produced by scripts/build_native.py.

Outputs:
  dist/temproot-<version>.apk
  dist/temproot-<version>.apk.sha256
  dist/build-result.json
"""
import argparse
import hashlib
import json
import os
import secrets
import struct
import subprocess
import sys
import zipfile
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
FIXED_ZIP_TIME = (2026, 1, 1, 0, 0, 0)
ANDROID_TOOLS = ROOT.parent / 'android-kernel/.tools/android'
NS = '{http://schemas.android.com/apk/res/android}'
ABIS = ['arm64-v8a', 'x86_64']


def run(args, env=None, allow_fail=False):
    env = dict(os.environ) if env is None else dict(env)
    env['JAVA_TOOL_OPTIONS'] = '-Dfile.encoding=UTF-8 -Duser.language=en -Duser.country=US'
    result = subprocess.run([str(a) for a in args], cwd=ROOT, env=env, text=True,
                            encoding='utf-8', errors='replace', capture_output=True)
    if result.stdout.strip():
        print(result.stdout.strip())
    if result.returncode and not allow_fail:
        if result.stderr.strip():
            print(result.stderr.strip(), file=sys.stderr)
        raise RuntimeError(f'{Path(str(args[0])).name} failed ({result.returncode})')
    return (result.stdout + result.stderr).strip()


def archive_entries(dest, entries):
    """Write a deterministic ZIP. resources.arsc stays STORED and 4-byte aligned."""
    with zipfile.ZipFile(dest, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, data in sorted(entries):
            info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_STORED if name == 'resources.arsc' else zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, data)


def verify_resource_table(apk):
    with zipfile.ZipFile(apk) as archive:
        info = archive.getinfo('resources.arsc')
        if info.compress_type != zipfile.ZIP_STORED:
            raise RuntimeError('resources.arsc must be uncompressed (install error -124)')
        with Path(apk).open('rb') as stream:
            stream.seek(info.header_offset)
            header = stream.read(30)
        if header[:4] != b'PK\x03\x04':
            raise RuntimeError('invalid ZIP local header')
        name_length, extra_length = struct.unpack_from('<HH', header, 26)
        offset = info.header_offset + 30 + name_length + extra_length
        if offset % 4:
            raise RuntimeError('resources.arsc must be 4-byte aligned')
        return {'compression': 'stored', 'data_offset': offset, 'aligned_4_bytes': True}


def native_libs():
    libs = []
    for abi in ABIS:
        so = ROOT / 'dist/lib' / abi / 'libtemproot.so'
        if not so.exists():
            raise FileNotFoundError(f'{so} missing; run scripts/build_native.py first')
        libs.append((f'lib/{abi}/libtemproot.so', so.read_bytes(), so))
    return libs


def main():
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    parser = argparse.ArgumentParser()
    parser.add_argument('--jdk', default=os.environ.get('TEMPROOT_JDK', r'C:\Program Files (x86)\jdk-26'))
    args = parser.parse_args()

    jdk = Path(args.jdk) / 'bin'
    platform = ANDROID_TOOLS / 'platform-35_r02/android-35/android.jar'
    bt = ANDROID_TOOLS / 'build-tools_r35_windows/android-15'
    for required in (jdk / 'java.exe', jdk / 'javac.exe', platform, bt / 'aapt2.exe'):
        if not required.exists():
            raise FileNotFoundError(required)

    build = ROOT / 'build'
    number = 1
    while (build / f'run-{number}').exists():
        number += 1
    build = build / f'run-{number}'
    classes, dex = build / 'classes', build / 'dex'
    classes.mkdir(parents=True)
    dex.mkdir(parents=True)
    out = ROOT / 'dist'
    out.mkdir(exist_ok=True)

    java_version = run([jdk / 'java.exe', '-version'])
    libs = native_libs()

    run([bt / 'aapt2.exe', 'compile', '--dir', ROOT / 'app/res', '-o', build / 'compiled-res.zip'])
    run([bt / 'aapt2.exe', 'link', '-I', platform, '--manifest', ROOT / 'app/AndroidManifest.xml',
         '-o', build / 'resources.apk', build / 'compiled-res.zip'])

    sources = sorted((ROOT / 'app/src').rglob('*.java'))
    if not sources:
        raise RuntimeError('no Java sources found')
    run([jdk / 'javac.exe', '-encoding', 'UTF-8', '--release', '8', '-classpath', platform,
         '-d', classes, *sources])
    archive_entries(build / 'classes.jar',
                    [(p.relative_to(classes).as_posix(), p.read_bytes()) for p in classes.rglob('*.class')])
    run([jdk / 'java.exe', '-cp', bt / 'lib/d8.jar', 'com.android.tools.r8.D8', '--release',
         '--min-api', '26', '--lib', platform, '--output', dex, build / 'classes.jar'])

    with zipfile.ZipFile(build / 'resources.apk') as z:
        entries = [(n, z.read(n)) for n in z.namelist()]
    entries.extend((p.name, p.read_bytes()) for p in dex.glob('*.dex'))
    entries.extend((name, data) for name, data, _ in libs)
    archive_entries(build / 'unsigned.apk', entries)
    run([bt / 'zipalign.exe', '-f', '4', build / 'unsigned.apk', build / 'aligned.apk'])

    private = ROOT / 'private'
    private.mkdir(exist_ok=True)
    key = private / 'temproot-signing.jks'
    password_file = private / 'signing-password.txt'
    if not key.exists():
        if password_file.exists():
            raise RuntimeError('password file without key; inspect private/ before rebuilding')
        password_file.write_text(secrets.token_urlsafe(32), encoding='ascii')
        env = dict(os.environ)
        env['TEMPROOT_SIGNING_PASSWORD'] = password_file.read_text(encoding='ascii').strip()
        run([jdk / 'keytool.exe', '-genkeypair', '-keystore', key, '-storetype', 'JKS',
             '-alias', 'temproot', '-keyalg', 'RSA', '-keysize', '3072', '-validity', '3650',
             '-dname', 'CN=TemporaryRoot Research', '-storepass:env', 'TEMPROOT_SIGNING_PASSWORD',
             '-keypass:env', 'TEMPROOT_SIGNING_PASSWORD'], env=env)

    manifest = ET.parse(ROOT / 'app/AndroidManifest.xml').getroot()
    version = manifest.get(NS + 'versionName')
    if manifest.get('package') != 'org.fujiang.temproot':
        raise RuntimeError('unexpected package name')
    provider = manifest.find('application/provider')
    if provider is None or provider.get(NS + 'exported') != 'false':
        raise RuntimeError('log provider must be private')
    app = manifest.find('application')
    if app is None or app.get(NS + 'extractNativeLibs') != 'true':
        raise RuntimeError('extractNativeLibs must be true so the .so is loadable')

    apk = out / f'temproot-{version}.apk'
    signing_env = dict(os.environ)
    signing_env['TEMPROOT_SIGNING_PASSWORD'] = password_file.read_text(encoding='ascii').strip()
    run([jdk / 'java.exe', '-jar', bt / 'lib/apksigner.jar', 'sign', '--ks', key,
         '--ks-key-alias', 'temproot', '--ks-pass', 'env:TEMPROOT_SIGNING_PASSWORD',
         '--key-pass', 'env:TEMPROOT_SIGNING_PASSWORD', '--v4-signing-enabled', 'false',
         '--out', apk, build / 'aligned.apk'], env=signing_env)

    signature = run([jdk / 'java.exe', '-jar', bt / 'lib/apksigner.jar', 'verify', '--verbose',
                     '--print-certs', apk])
    run([bt / 'zipalign.exe', '-c', '4', apk])
    resource_check = verify_resource_table(apk)
    badging = run([bt / 'aapt2.exe', 'dump', 'badging', apk])
    if 'uses-permission:' in badging:
        raise RuntimeError('APK declares permissions; none are needed')
    if 'application-debuggable' in badging:
        raise RuntimeError('APK must not be debuggable')
    if 'native-code' not in badging:
        raise RuntimeError('native libraries missing from the APK manifest')

    with zipfile.ZipFile(apk) as z:
        if z.testzip() is not None:
            raise RuntimeError('corrupt APK archive')
        names = z.namelist()
        for abi in ABIS:
            if f'lib/{abi}/libtemproot.so' not in names:
                raise RuntimeError(f'lib/{abi}/libtemproot.so missing from APK')
        if 'classes.dex' not in names:
            raise RuntimeError('classes.dex missing from APK')

    sha = hashlib.sha256(apk.read_bytes()).hexdigest()
    (out / (apk.name + '.sha256')).write_text(sha + '  ' + apk.name + '\n', encoding='ascii')
    result = {
        'apk': apk.name,
        'sha256': sha,
        'bytes': apk.stat().st_size,
        'version': version,
        'min_sdk': 26,
        'target_sdk': 35,
        'java_version': java_version,
        'android_platform': '35_r02',
        'build_tools': '35.0.0',
        'ndk_build': json.loads((out / 'native-build.json').read_text(encoding='utf-8'))
        if (out / 'native-build.json').exists() else None,
        'native_libs': {name: hashlib.sha256(data).hexdigest() for name, data, _ in libs},
        'resource_table': resource_check,
        'signature_verification': signature,
        'manifest_badging': badging,
        'device_tested': False,
        'source_files': {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in sources + sorted((ROOT / 'app/res').rglob('*.xml'))
                         + [ROOT / 'app/AndroidManifest.xml', Path(__file__)]},
    }
    (out / 'build-result.json').write_text(json.dumps(result, indent=2, ensure_ascii=False),
                                           encoding='utf-8')
    print(json.dumps({'apk': str(apk), 'sha256': sha, 'bytes': result['bytes']}, indent=2))


if __name__ == '__main__':
    main()
