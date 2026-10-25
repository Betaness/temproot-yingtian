"""Host-side BTF dump for the extracted stock kernel (research only).

Implements the same record-walking rules as native/tr_btf.c so the offsets used
in the reports are cross-checked by an independent implementation. This script
never runs on the device; the on-device copy is the C parser.
"""
import argparse
import json
import struct
import sys
from pathlib import Path

KIND_NAMES = {
    0: 'UNKN', 1: 'INT', 2: 'PTR', 3: 'ARRAY', 4: 'STRUCT', 5: 'UNION',
    6: 'ENUM', 7: 'FWD', 8: 'TYPEDEF', 9: 'VOLATILE', 10: 'CONST',
    11: 'RESTRICT', 12: 'FUNC', 13: 'FUNC_PROTO', 14: 'VAR', 15: 'DATASEC',
    16: 'FLOAT', 17: 'DECL_TAG', 18: 'TYPE_TAG', 19: 'ENUM64',
}
MODIFIERS = {8, 9, 10, 11, 17, 18}


def extra_size(kind, vlen):
    if kind == 1:
        return 4
    if kind == 3:
        return 12
    if kind in (4, 5):
        return vlen * 12
    if kind == 6:
        return vlen * 8
    if kind == 19:
        return vlen * 12
    if kind == 13:
        return vlen * 8
    if kind == 14:
        return 4
    if kind == 15:
        return vlen * 12
    if kind == 17:
        return 4
    return 0


class Btf:
    def __init__(self, path):
        data = Path(path).read_bytes()
        magic, version, flags, hdr_len, type_off, type_len, str_off, str_len = \
            struct.unpack_from('<HBBIIIII', data, 0)
        if magic != 0xEB9F:
            raise SystemExit(f'bad BTF magic 0x{magic:04x}')
        self.data = data
        self.version = version
        self.strings = data[hdr_len + str_off: hdr_len + str_off + str_len]
        self.types_blob = data[hdr_len + type_off: hdr_len + type_off + type_len]
        self.types = [None]
        self.by_name = {}
        self._parse()

    def name(self, off):
        if off == 0 or off >= len(self.strings):
            return ''
        end = self.strings.find(b'\0', off)
        return self.strings[off:end].decode('utf-8', 'replace')

    def _parse(self):
        pos = 0
        blob = self.types_blob
        while pos + 12 <= len(blob):
            name_off, info, size_or_type = struct.unpack_from('<III', blob, pos)
            vlen = info & 0xffff
            kind = (info >> 24) & 0x1f
            kflag = (info >> 31) & 1
            extra = extra_size(kind, vlen)
            record = {
                'id': len(self.types),
                'name': self.name(name_off),
                'kind': kind,
                'vlen': vlen,
                'kflag': kflag,
                'size': size_or_type,
                'members': [],
                'pos': pos,
            }
            if kind in (4, 5):
                for i in range(vlen):
                    m_name, m_type, m_off = struct.unpack_from('<III', blob, pos + 12 + i * 12)
                    bit = (m_off & 0x00ffffff) if kflag else m_off
                    record['members'].append({
                        'name': self.name(m_name),
                        'type': m_type,
                        'bit_offset': bit,
                        'byte_offset': bit // 8,
                    })
            self.types.append(record)
            if record['name'] and kind in (4, 5, 8, 6):
                self.by_name.setdefault(record['name'], record['id'])
            pos += 12 + extra

    def resolve(self, type_id, depth=0):
        while depth < 32:
            rec = self.types[type_id] if 0 < type_id < len(self.types) else None
            if rec is None:
                return None
            if rec['kind'] not in MODIFIERS:
                return rec
            type_id = rec['size']
            depth += 1
        return None

    def find(self, name):
        for rec in self.types[1:]:
            if rec['name'] == name and rec['kind'] in (4, 5, 8, 6):
                return rec
        return None

    def member(self, struct_name, member_name, depth=0):
        rec = self.find(struct_name)
        if rec is None:
            return None
        return self._member_of(rec, member_name, depth)

    def _member_of(self, rec, member_name, depth=0):
        resolved = self.resolve(rec['id'])
        if resolved is None:
            return None
        for m in resolved['members']:
            if m['name'] == member_name:
                return m
            if m['name'] == '' and depth < 4:
                inner = self.resolve(m['type'])
                if inner is not None and inner['kind'] in (4, 5):
                    nested = self._member_of(inner, member_name, depth + 1)
                    if nested is not None:
                        return {**nested,
                                'byte_offset': m['byte_offset'] + nested['byte_offset'],
                                'bit_offset': m['bit_offset'] + nested['bit_offset']}
        return None


REQUIRED = [
    ('task_struct', 'pid'), ('task_struct', 'tgid'), ('task_struct', 'comm'),
    ('task_struct', 'tasks'), ('task_struct', 'cred'), ('task_struct', 'real_cred'),
    ('task_struct', 'signal'), ('task_struct', 'mm'), ('task_struct', 'files'),
    ('cred', 'uid'), ('cred', 'euid'), ('cred', 'fsuid'),
    ('cred', 'cap_effective'), ('cred', 'cap_permitted'), ('cred', 'user_ns'),
    ('cred', 'security'),
    ('signal_struct', 'posix_timers'), ('signal_struct', 'posix_cputimers'),
    ('pipe_buffer', 'page'), ('pipe_buffer', 'offset'), ('pipe_buffer', 'len'),
    ('pipe_buffer', 'ops'), ('pipe_buffer', 'flags'),
    ('pipe_inode_info', 'bufs'), ('pipe_inode_info', 'head'),
    ('pipe_inode_info', 'tail'), ('pipe_inode_info', 'ring_size'),
    ('k_itimer', 'it_clock'), ('k_itimer', 'it_signal'), ('k_itimer', 'it'),
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('btf')
    parser.add_argument('--json', default=None)
    args = parser.parse_args()

    btf = Btf(args.btf)
    print(f'BTF v{btf.version}: {len(btf.types) - 1} types, strings {len(btf.strings)} bytes')
    report = {'types': len(btf.types) - 1, 'fields': {}, 'missing': []}
    for struct_name, member_name in REQUIRED:
        m = btf.member(struct_name, member_name)
        if m is None:
            report['missing'].append(f'{struct_name}.{member_name}')
            print(f'  MISSING  {struct_name}.{member_name}')
            continue
        key = f'{struct_name}.{member_name}'
        report['fields'][key] = m['byte_offset']
        print(f'  {key:<32} +0x{m["byte_offset"]:03x} ({m["byte_offset"]})')
    print(f'missing: {len(report["missing"])}')

    for struct_name in ('task_struct', 'cred', 'pipe_buffer', 'k_itimer', 'signal_struct'):
        rec = btf.find(struct_name)
        if rec:
            resolved = btf.resolve(rec['id'])
            print(f'{struct_name}: size={resolved["size"]} members={len(resolved["members"])}')

    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2), encoding='utf-8')
        print(f'wrote {args.json}')


if __name__ == '__main__':
    main()
