#!/usr/bin/env python3
"""Extract offset-annotated struct layouts from Zeal / MQ2 headers into JSON
for ApplyEqStructs.java.

Only members carrying an explicit /*0xOFFSET*/ comment are trusted. Inline
method bodies are skipped, unions contribute their first member, and base
classes (struct A : B) inherit B's fields.

usage: eqstructs_to_json.py OUT.json HEADER [HEADER...]   (earlier headers win)
"""
import json
import re
import sys

PRIM = {
    'BYTE': ('byte', 1), 'UCHAR': ('byte', 1), 'uint8_t': ('byte', 1), 'unsigned char': ('byte', 1),
    'CHAR': ('char', 1), 'char': ('char', 1), 'int8_t': ('sbyte', 1),
    'bool': ('bool', 1), 'BOOLEAN': ('bool', 1),
    'WORD': ('word', 2), 'USHORT': ('word', 2), 'uint16_t': ('word', 2), 'unsigned short': ('word', 2),
    'SHORT': ('short', 2), 'short': ('short', 2), 'int16_t': ('short', 2),
    'DWORD': ('dword', 4), 'UINT': ('uint', 4), 'uint32_t': ('uint', 4), 'unsigned int': ('uint', 4),
    'ULONG': ('uint', 4), 'unsigned long': ('uint', 4), 'size_t': ('uint', 4), 'COLORREF': ('dword', 4),
    'INT': ('int', 4), 'int': ('int', 4), 'int32_t': ('int', 4), 'LONG': ('int', 4), 'long': ('int', 4),
    'BOOL': ('int', 4), 'HWND': ('pointer', 4), 'HANDLE': ('pointer', 4),
    'FLOAT': ('float', 4), 'float': ('float', 4),
    'DOUBLE': ('double', 8), 'double': ('double', 8),
    'int64_t': ('qword', 8), 'uint64_t': ('qword', 8), '__int64': ('qword', 8), 'QWORD': ('qword', 8),
    'PVOID': ('pointer', 4), 'LPVOID': ('pointer', 4), 'PCHAR': ('pointer', 4), 'PBYTE': ('pointer', 4),
    'LPSTR': ('pointer', 4), 'LPCSTR': ('pointer', 4),
}
# struct-by-value types not defined as structs in these headers
VALUE_TYPES = {'Vec3': 12, 'CXPoint': 8, 'CXRect': 16}

OFF = r'/\*\s*(0x[0-9A-Fa-f]+)\s*\**\s*\*/'
STRUCT_START = re.compile(r'^\s*(?:typedef\s+)?(?:struct|class)\s+(\w+)\s*(?::\s*(?:public\s+)?(\w+))?\s*(?://(.*))?$|'
                          r'^\s*(?:typedef\s+)?(?:struct|class)\s+(\w+)\s*(?::\s*(?:public\s+)?(\w+))?\s*\{\s*(?://(.*))?$')
MEMBER = re.compile(r'^\s*(?:' + OFF + r')?\s*'
                    r'((?:(?:struct|class|const|unsigned|signed|volatile|enum)\s+)*[A-Za-z_][\w:]*(?:\s*<[^>]*>)?)'
                    r'\s*(\*+)?\s*(?:const\s+)?([A-Za-z_]\w*)\s*((?:\[[^\]]+\])*)\s*(?::\s*\d+)?\s*;')
SIZE_HINT = re.compile(r'(?:sizeof|size|operator\s*new\s*(?:of)?)\s*[=:(]?\s*(0x[0-9A-Fa-f]+)', re.I)


def strip_comments_keep_offsets(line):
    # keep the leading offset comment, drop trailing // and other /* */ comments
    m = re.match(r'^(\s*' + OFF + r')(.*)$', line)
    head, rest = (m.group(1), m.group(3)) if m else ('', line)
    rest = re.sub(r'/\*.*?\*/', ' ', rest)
    rest = rest.split('//')[0]
    return head + rest


def parse_header(path, defines):
    text = open(path, encoding='latin-1').read()
    for m in re.finditer(r'^\s*#define\s+(\w+)\s+(0x[0-9A-Fa-f]+|\d+)\b', text, re.M):
        defines.setdefault(m.group(1), int(m.group(2), 0))
    for m in re.finditer(r'(?:constexpr|const)\s+(?:static\s+)?(?:int|size_t|DWORD)\s+(\w+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*;', text):
        defines.setdefault(m.group(1), int(m.group(2), 0))

    structs = {}
    lines = text.split('\n')
    i = 0
    while i < len(lines):
        m = STRUCT_START.match(lines[i])
        if not m or lines[i].rstrip().endswith(';'):
            i += 1
            continue
        name = m.group(1) or m.group(4)
        base = m.group(2) or m.group(5)
        hint_text = (m.group(3) or m.group(6) or '')
        # find opening brace (same or next line)
        j = i
        while j < len(lines) and '{' not in lines[j]:
            j += 1
        if j >= len(lines) or j - i > 2:
            i += 1
            continue
        st = {'name': name, 'base': base, 'fields': [], 'source': path}
        hm = SIZE_HINT.search(hint_text)
        if hm:
            st['size'] = int(hm.group(1), 16)
        depth = 0
        union_off = None      # offset of the union currently being read
        union_taken = False   # first union member already recorded
        union_depth = None
        nested_skip = None    # depth of a method body / nested struct definition being skipped
        k = j
        while k < len(lines):
            raw = lines[k]
            line = strip_comments_keep_offsets(raw)
            opens, closes = line.count('{'), line.count('}')
            if k == j:
                depth += opens - closes
                after = line.split('{', 1)[1] if '{' in line else ''
                k += 1
                if depth <= 0:
                    break
                continue
            if nested_skip is not None:
                depth += opens - closes
                if depth <= nested_skip:
                    nested_skip = None
                k += 1
                continue
            stripped = line.strip()
            um = re.match(r'^\s*(?:' + OFF + r')?\s*union\s*\{', line)
            if um:
                union_off = int(um.group(1), 16) if um.group(1) else None
                union_taken = False
                union_depth = depth
                depth += opens - closes
                k += 1
                continue
            if stripped.startswith('}') and union_depth is not None and depth - closes <= union_depth:
                depth += opens - closes
                union_depth = None
                union_off = None
                k += 1
                if depth <= 0:
                    break
                continue
            if '(' in stripped and not MEMBER.match(line):
                # method declaration or definition
                if opens > closes:
                    nested_skip = depth
                depth += opens - closes
                k += 1
                if depth <= 0:
                    break
                continue
            if opens > closes:
                # nested struct definition / initializer block: skip it
                nested_skip = depth
                depth += opens - closes
                k += 1
                continue
            mm = MEMBER.match(line)
            if mm and not stripped.startswith(('return', 'using', 'typedef', 'static', 'friend')):
                off = mm.group(1)
                off = int(off, 16) if off else None
                if union_depth is not None:
                    if union_taken:
                        mm = None
                    else:
                        if off is None:
                            off = union_off
                        union_taken = True
                if mm and off is not None:
                    typ = re.sub(r'^(?:(?:struct|class|const|volatile|enum)\s+)+', '', mm.group(2)).strip()
                    typ = typ.split('::')[-1]
                    dims = re.findall(r'\[([^\]]+)\]', mm.group(5) or '')
                    st['fields'].append({'offset': off, 'name': mm.group(4), 'type': typ,
                                         'ptr': len(mm.group(3) or ''), 'dims': dims})
            depth += opens - closes
            k += 1
            if depth <= 0:
                break
        # the typedef name after the closing brace (MQ2 style: } CHARINFO, *PCHARINFO;)
        tail = lines[k - 1] if k - 1 < len(lines) else ''
        tm = re.match(r'^\s*\}\s*(\w+)', tail)
        if tm and tm.group(1) not in ('', name):
            st['alias'] = tm.group(1)
        if st['fields']:
            structs[name] = st
        i = k
    return structs


def eval_dim(expr, defines):
    expr = expr.strip()
    try:
        return int(expr, 0)
    except ValueError:
        pass
    if expr in defines:
        return defines[expr]
    tokens = re.findall(r'0x[0-9A-Fa-f]+|\d+|[A-Za-z_]\w*|[*+\-()]', expr)
    out = []
    for t in tokens:
        if re.match(r'[A-Za-z_]', t):
            if t not in defines:
                return None
            out.append(str(defines[t]))
        else:
            out.append(str(int(t, 0)) if t[0].isdigit() else t)
    try:
        return int(eval(''.join(out), {'__builtins__': {}}))
    except Exception:
        return None


def resolve(structs, defines):
    by_alias = {}
    for s in structs.values():
        by_alias[s['name']] = s['name']
        if 'alias' in s:
            by_alias[s['alias']] = s['name']
            by_alias['P' + s['alias']] = s['name'] + '*'

    def flatten(s, seen=()):
        fields = []
        if s.get('base') and s['base'] in structs and s['base'] not in seen:
            fields = flatten(structs[s['base']], seen + (s['name'],))
        own_min = min((f['offset'] for f in s['fields']), default=0)
        fields = [f for f in fields if f['offset'] < own_min]
        return fields + list(s['fields'])

    for s in structs.values():
        s['all_fields'] = sorted(flatten(s), key=lambda f: f['offset'])

    sizes = {}

    def struct_size(name, stack=()):
        if name in sizes:
            return sizes[name]
        if name in VALUE_TYPES:
            return VALUE_TYPES[name]
        s = structs.get(name)
        if s is None or name in stack:
            return None
        if 'size' in s:
            sizes[name] = s['size']
            return s['size']
        fs = s['all_fields']
        if not fs:
            return None
        last = fs[-1]
        esz = elem_size(last, stack + (name,))
        if esz is None:
            return None
        n = 1
        for d in last['dims']:
            v = eval_dim(d, defines)
            if v is None:
                return None
            n *= v
        sizes[name] = last['offset'] + esz * n
        return sizes[name]

    def elem_size(f, stack=()):
        if f['ptr'] or f['type'] in ('CXSTR', 'CXStr'):
            return 4
        t = f['type']
        if t in PRIM:
            return PRIM[t][1]
        if t in by_alias:
            tgt = by_alias[t]
            if tgt.endswith('*'):
                return 4
            return struct_size(tgt, stack)
        return struct_size(t, stack)

    out = {}
    for s in structs.values():
        fs = s['all_fields']
        rec = {'name': s['name'], 'alias': s.get('alias'), 'base': s.get('base'),
               'source': s['source'], 'fields': []}
        for idx, f in enumerate(fs):
            nxt = fs[idx + 1]['offset'] if idx + 1 < len(fs) else None
            if nxt is not None and nxt == f['offset']:
                continue  # duplicate offset (union alt / comment mistake): keep last
            t = f['type']
            ptr = f['ptr']
            kind, target = 'unknown', None
            if t in ('CXSTR', 'CXStr') and not ptr:
                # the client's CXStr object is a single pointer to its string rep
                ptr, t = 1, '_CXSTR'
            if t in by_alias and by_alias[t].endswith('*'):
                ptr += 1
                t = by_alias[t][:-1]
            elif t in by_alias:
                t = by_alias[t]
            if ptr:
                kind = 'pointer'
                target = t if (t in structs and ptr == 1) else None
            elif t in PRIM:
                kind = PRIM[t][0]
            elif t in structs or t in VALUE_TYPES:
                kind, target = 'struct', t
            count = 1
            ok_dims = True
            for d in f['dims']:
                v = eval_dim(d, defines)
                if v is None:
                    ok_dims = False
                    break
                count *= v
            esz = 4 if ptr else elem_size(f)
            gap = (nxt - f['offset']) if nxt is not None else None
            size = esz * count if (esz and ok_dims) else None
            if size is None or (gap is not None and size > gap):
                # untrusted size: name the bytes up to the next field
                if gap is None:
                    if size is None:
                        continue
                else:
                    if size is not None and esz and gap % esz == 0 and kind != 'unknown':
                        count = gap // esz
                    else:
                        kind, target, esz, count = 'byte', None, 1, gap
                    size = gap
            rec['fields'].append({'offset': f['offset'], 'name': f['name'], 'kind': kind,
                                  'target': target, 'count': count, 'size': size})
        sz = struct_size(s['name'])
        if sz:
            rec['size'] = sz
        if rec['fields']:
            out[s['name']] = rec
    for name, size in VALUE_TYPES.items():
        if name not in out:
            elems = {'Vec3': [('y', 0), ('x', 4), ('z', 8)], 'CXPoint': [('x', 0), ('y', 4)],
                     'CXRect': [('left', 0), ('top', 4), ('right', 8), ('bottom', 12)]}[name]
            kind = 'float' if name == 'Vec3' else 'int'
            out[name] = {'name': name, 'alias': None, 'base': None, 'source': 'builtin', 'size': size,
                         'fields': [{'offset': o, 'name': n, 'kind': kind, 'target': None, 'count': 1, 'size': 4}
                                    for n, o in elems]}
    return out


def main():
    out_path, headers = sys.argv[1], sys.argv[2:]
    defines, structs = {}, {}
    for h in headers:
        for name, s in parse_header(h, defines).items():
            structs.setdefault(name, s)  # earlier headers win
    result = resolve(structs, defines)
    with open(out_path, 'w') as f:
        json.dump(result, f, indent=1)
    nf = sum(len(s['fields']) for s in result.values())
    print(f'{len(result)} structs, {nf} fields -> {out_path}')


if __name__ == '__main__':
    main()
