#!/usr/bin/env python3
"""把同目录 libil2cpp.so / global-metadata.dat 转为 rainbow_tw.json。
运行：python3 decode_rainbow_tw.py（Python 3.10+，仅标准库）。
输出通过内置兼容规则恢复标准名称；不依赖旧映射或数据库。当前支持 IL2CPP v31 / ARM64。
旧参考未覆盖的新名称保留客户端 snake_case；不能据此保证任意新增字段符合 ORM。
地址、哈希和表数动态读取；格式或代码布局不支持时停止，保留旧 JSON。
"""

from pathlib import Path
from collections import defaultdict, deque
import bisect
import json
import os
import re
import struct
import sys
import tempfile


class Metadata:
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        self.header = struct.unpack_from('<64I', self.data)
        if self.header[:2] != (0xFAB11BAF, 31):
            raise ValueError('Expected unencrypted IL2CPP metadata version 31')
        for i in range(2, 64, 2):
            if sum(self.header[i:i + 2]) > len(self.data):
                raise ValueError('Metadata section outside file')
        self.types = self.records(40, '<16i8H2I')
        self.fields = self.records(24, '<IiI')
        self.methods = self.records(12, '<7i4H')
        self.properties = self.records(10, '<5I')
        self.defaults = {f: (t, d) for f, t, d in self.records(16, '<iii')}
        self.nested = [v[0] for v in self.records(32, '<i')]
        self.literals = []
        for size, offset in self.records(2, '<II'):
            start = self.header[4] + offset
            self.literals.append(self.data[start:start + size].decode('utf-8'))

    def records(self, section, fmt):
        offset, size = self.header[section:section + 2]
        return list(struct.iter_unpack(fmt, self.data[offset:offset + size]))

    def string(self, index):
        if not 0 <= index < self.header[7]:
            raise ValueError('Invalid metadata string index')
        start = self.header[6] + index
        return self.data[start:self.data.index(b'\0', start)].decode('utf-8')

    def table_constant(self, type_index):
        t = self.types[type_index]
        for i in range(t[8], t[8] + t[18]):
            if self.string(self.fields[i][0]) != 'TABLE_NAME' or i not in self.defaults:
                continue
            _, offset = self.defaults[i]
            start = self.header[18] + offset
            # IL2CPP v29+ stores strings with a compressed signed length.
            # A 67-byte v1_ SHA256 identifier has prefix 0x80, 0x86.
            value = self.data[start:start + 69]
            if value[:2] == b'\x80\x86' and re.fullmatch(rb'v1_[0-9a-f]{64}', value[2:]):
                return value[2:].decode('ascii')
        return None

    def queries(self):
        result = defaultdict(set)
        pattern = re.compile(r'^SELECT ((?:`[0-9a-f]{64}`)(?:,`[0-9a-f]{64}`)*) FROM `(v1_[0-9a-f]{64})`')
        for text in self.literals:
            match = pattern.match(text)
            if match:
                result[match[2]].add(tuple(re.findall(r'`([^`]+)`', match[1])))
        return result


def snake(name):
    name = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', name)
    return re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', name).lower()



class Elf:
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        if self.data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', self.data, 18)[0] != 183:
            raise ValueError('Expected little-endian AArch64 ELF64')
        start = struct.unpack_from('<Q', self.data, 40)[0]
        size, count, strings_index = struct.unpack_from('<HHH', self.data, 58)
        headers = [struct.unpack_from('<IIQQQQIIQQ', self.data, start + i * size) for i in range(count)]
        strings = headers[strings_index]
        strings = self.data[strings[4]:strings[4] + strings[5]]
        self.sections = {strings[h[0]:strings.index(b'\0', h[0])].decode(): h for h in headers}
        self.loaded = [h for h in headers if h[2] & 2 and h[1] != 8]
        section = self.sections['.rela.dyn']
        self.relocations = {address: addend for address, info, addend in struct.iter_unpack(
            '<QQq', self.data[section[4]:section[4] + section[5]]) if info & 0xffffffff == 1027}

    def offset(self, address):
        for h in self.loaded:
            if h[3] <= address < h[3] + h[5]:
                return address - h[3] + h[4]
        raise ValueError(f'Address not in file-backed section: {address:#x}')

    def u64(self, address):
        if address in self.relocations:
            return self.relocations[address]
        return struct.unpack_from('<Q', self.data, self.offset(address))[0]

    def code_module(self, name):
        pos = self.data.index(name.encode() + b'\0')
        address = next(pos - h[4] + h[3] for h in self.loaded if h[4] <= pos < h[4] + h[5])
        candidates = [a for a, v in self.relocations.items() if v == address]
        valid = [(a, self.u64(a + 8), self.u64(a + 16)) for a in candidates
                 if 0 < self.u64(a + 8) < 1000000]
        if len(valid) != 1:
            raise ValueError(f'Ambiguous code module: {valid}')
        return valid[0]

    def words(self, address, count):
        return struct.unpack_from('<' + 'I' * count, self.data, self.offset(address))

    def metadata_types(self, type_count):
        needle = struct.pack('<Q', type_count)
        candidates = []
        for h in self.loaded:
            if h[2] & 4:
                continue
            pos = h[4]
            while True:
                pos = self.data.find(needle, pos, h[4] + h[5])
                if pos < 0:
                    break
                if self.data[pos + 16:pos + 24] == needle:
                    candidates.append(pos - h[4] + h[3])
                pos += 8
        if len(candidates) != 1:
            raise ValueError(f'Ambiguous metadata registration: {candidates}')
        count_address = candidates[0]
        count, pointer = self.u64(count_address - 32), self.u64(count_address - 24)
        return [((self.u64(self.u64(pointer + i * 8) + 8) >> 16) & 255) for i in range(count)]


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def decode(pc, word):
    """Small, explicit instruction subset for readable inspection, not an emulator."""
    rd, rn, rm = word & 31, (word >> 5) & 31, (word >> 16) & 31
    sf = word >> 31
    reg = 'x' if sf else 'w'
    if word & 0xfc000000 in (0x94000000, 0x14000000):
        return ('bl' if word & 0x80000000 else 'b', pc + signed(word & 0x3ffffff, 26) * 4)
    if word == 0xd65f03c0:
        return ('ret',)
    if word & 0xffe0ffe0 in (0xaa0003e0, 0x2a0003e0):
        return ('mov', f'{reg}{rd}', f'{reg}{rm}')
    if word & 0x7f800000 in (0x52800000, 0x72800000, 0x12800000):
        op = {0x52800000: 'movz', 0x72800000: 'movk', 0x12800000: 'movn'}[word & 0x7f800000]
        return (op, f'{reg}{rd}', ((word >> 5) & 0xffff) << (((word >> 21) & 3) * 16))
    if word & 0x1f000000 == 0x11000000:
        imm = ((word >> 10) & 0xfff) << (12 if word & (1 << 22) else 0)
        return ('sub' if word & (1 << 30) else 'add', f'{reg}{rd}', f'{reg}{rn}', imm)
    if word & 0x9f000000 == 0x90000000:
        imm = ((word >> 5) & 0x7ffff) * 4 + ((word >> 29) & 3)
        return ('adrp', f'x{rd}', (pc & ~0xfff) + signed(imm, 21) * 4096)
    if word & 0x3b000000 == 0x39000000:
        size = word >> 30
        dest = ('x' if size == 3 else 'w') + str(rd)
        if word & (1 << 26):
            dest = ('d' if size == 3 else 's') + str(rd)
        return ('ldr' if word & (1 << 22) else 'str', dest, f'x{rn}', ((word >> 10) & 0xfff) << size)
    if word & 0x3b200000 == 0x38000000:
        size = word >> 30
        dest = ('x' if size == 3 else 'w') + str(rd)
        if word & (1 << 26):
            dest = ('d' if size == 3 else 's') + str(rd)
        mode = (word >> 10) & 3
        return ('ldur' if word & (1 << 22) else 'stur', dest, f'x{rn}', signed((word >> 12) & 0x1ff, 9), mode)
    if word & 0x3a000000 == 0x28000000:
        size = 8 if word & (1 << (30 if word & (1 << 26) else 31)) else 4
        prefix = 'x' if size == 8 else 'w'
        if word & (1 << 26):
            prefix = 'd' if size == 8 else 's'
        return ('ldp' if word & (1 << 22) else 'stp', prefix + str(rd), prefix + str((word >> 10) & 31),
                f'x{rn}', signed((word >> 15) & 127, 7) * size, (word >> 23) & 3)
    if word & 0x7e000000 == 0x36000000:
        return ('tbnz' if word & (1 << 24) else 'tbz', rd, pc + signed((word >> 5) & 0x3fff, 14) * 4)
    if word & 0x7e000000 == 0x34000000:
        return ('cbnz' if word & (1 << 24) else 'cbz', rd, pc + signed((word >> 5) & 0x7ffff, 19) * 4)
    if word & 0xff000010 == 0x54000000:
        return ('b.cond', word & 15, pc + signed((word >> 5) & 0x7ffff, 19) * 4)
    if word & 0xfffffc00 in (0x1e604000, 0x1e204000):
        prefix = 'd' if word & (1 << 22) else 's'
        return ('mov', prefix + str(rd), prefix + str(rn))
    if word & 0x7fe00c00 == 0x1a800400 and rn == 31 and rm == 31:
        return ('cset', f'{reg}{rd}')
    if word & 0x1f800000 == 0x12000000:
        return ('logical_imm', f'{reg}{rd}', f'{reg}{rn}')
    if word & 0x1f800000 == 0x13000000:
        return ('bitfield', f'{reg}{rd}', f'{reg}{rn}')
    if word & 0x1f000000 == 0x0a000000:
        return ('logical_reg', f'{reg}{rd}', f'{reg}{rn}', f'{reg}{rm}')
    if word == 0xd503201f:
        return ('nop',)
    return ('unknown', hex(word))


class NativeClient:
    def __init__(self, elf, metadata):
        self.elf, self.metadata = elf, metadata
        self.addresses = {}
        self.names = {}
        self.module_starts = {}
        self.type_kinds = elf.metadata_types(len(metadata.types))
        self.parameters = metadata.records(22, '<IIi')
        # Find relevant assemblies by their types, not version-specific DLL names.
        needed_types = {i for i, t in enumerate(metadata.types)
                        if metadata.table_constant(i) or metadata.string(t[0]) == 'Query'}
        for image in metadata.records(42, '<10i'):
            name = metadata.string(image[0])
            if not any(image[2] <= i < image[2] + image[3] for i in needed_types):
                continue
            _, count, pointer = elf.code_module(name)
            pointers = [elf.u64(pointer + i * 8) for i in range(count)]
            starts = sorted(set(pointers) - {0})
            for t in metadata.types[image[2]:image[2] + image[3]]:
                for index in range(t[9], t[9] + t[16]):
                    method = metadata.methods[index]
                    addr = pointers[(method[6] & 0xffffff) - 1]
                    self.addresses[index] = addr
                    self.names[addr] = metadata.string(t[0]) + '.' + metadata.string(method[0])
                    self.module_starts[index] = starts
        self.readers = {addr: name.split('.')[-1] for addr, name in self.names.items()
                        if name in ('Query.GetInt', 'Query.GetLong', 'Query.GetDouble', 'Query.GetText')}
        if set(self.readers.values()) != {'GetInt', 'GetLong', 'GetDouble', 'GetText'}:
            raise ValueError('数据库读取方法不完整；客户端布局可能已变化')

    def instructions(self, index):
        address = self.addresses[index]
        starts = self.module_starts[index]
        end = starts[bisect.bisect_right(starts, address)]
        return {address + i * 4: (decode(address + i * 4, word), word)
                for i, word in enumerate(self.elf.words(address, (end - address) // 4))}

    def method_parameters(self, index):
        method = self.metadata.methods[index]
        return [(self.metadata.string(p[0]), self.type_kinds[p[2]])
                for p in self.parameters[method[4]:method[4] + method[-1]]]

    def trace_constructor(self, reader_index, ctor_index):
        """Conservative symbolic dataflow on paths reaching a particular constructor.

        Only primitive AAPCS64 arguments are supported. Unknown instructions
        invalidate a path rather than allowing stale registers to look proven.
        """
        instructions = self.instructions(reader_index)
        target = self.addresses[ctor_index]
        sinks = {pc for pc, (ins, _) in instructions.items() if ins == ('bl', target)}
        if not sinks:
            return {'error': 'constructor not directly called'}
        edges, reverse = {}, defaultdict(set)
        for pc, (ins, _) in instructions.items():
            if pc in sinks or ins[0] == 'ret':
                nxt = []
            elif ins[0] == 'b':
                nxt = [ins[1]]
            elif ins[0] in ('cbz', 'cbnz', 'tbz', 'tbnz', 'b.cond'):
                nxt = [pc + 4, ins[-1]]
            else:
                nxt = [pc + 4]
            edges[pc] = [p for p in nxt if p in instructions]
            for p in edges[pc]:
                reverse[p].add(pc)
        relevant, todo = set(sinks), list(sinks)
        while todo:
            for pc in reverse[todo.pop()]:
                if pc not in relevant:
                    relevant.add(pc)
                    todo.append(pc)
        start = min(instructions)
        if start not in relevant:
            return {'error': 'no constructor path'}
        # State stores only known values. At joins, retain equal values only.
        initial = {'x1': ('query',), 'sp': ('stack', 0)}
        states, queue, results = {start: initial}, deque([start]), {}
        unknown, steps = set(), 0

        def key(reg):
            return 'x' + reg[1:] if reg.startswith('w') else 'd' + reg[1:] if reg.startswith('s') else reg

        def get(state, reg, base=False):
            if reg in ('x31', 'w31'):
                return state.get('sp') if base else 0
            return state.get(key(reg))

        def put(state, reg, value, base=False):
            if reg in ('x31', 'w31') and not base:
                return
            k = 'sp' if reg in ('x31', 'w31') else key(reg)
            if value is None:
                state.pop(k, None)
            else:
                state[k] = value

        def add(value, delta):
            if isinstance(value, int):
                return value + delta
            if isinstance(value, tuple) and value[0] == 'stack':
                return ('stack', value[1] + delta)
            return None

        def memory(state, base, delta, reg, load):
            address = add(get(state, base, True), delta)
            if not (isinstance(address, tuple) and address[0] == 'stack'):
                if load:
                    put(state, reg, None)
                return
            k = 'mem:' + str(address[1])
            if load:
                put(state, reg, state.get(k))
            else:
                value = get(state, reg)
                if value is None:
                    state.pop(k, None)
                else:
                    state[k] = value

        while queue:
            pc = queue.popleft()
            state = dict(states[pc])
            steps += 1
            if steps > 100000:
                return {'error': 'dataflow iteration limit'}
            ins, word = instructions[pc]
            op = ins[0]
            if pc in sinks:
                params, integer, floating, stack = [], 1, 0, 0
                for name, kind in self.method_parameters(ctor_index):
                    if kind in (12, 13):
                        if floating < 8:
                            value = get(state, 'd' + str(floating))
                            floating += 1
                        else:
                            sp = get(state, 'x31', True)
                            value = state.get('mem:' + str(sp[1] + stack)) if sp else None
                            stack += 8
                    elif kind in (2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 14, 18, 28):
                        if integer < 8:
                            value = get(state, 'x' + str(integer))
                            integer += 1
                        else:
                            sp = get(state, 'x31', True)
                            value = state.get('mem:' + str(sp[1] + stack)) if sp else None
                            stack += 8
                    else:
                        return {'error': f'unsupported constructor argument kind {kind}'}
                    params.append({'parameter': name, 'query_column': value[1] if isinstance(value, tuple) and value[0] == 'column' else None})
                results[pc] = params
                continue
            if op == 'unknown':
                unknown.add((pc, hex(word)))
                continue
            if op == 'mov':
                put(state, ins[1], get(state, ins[2]))
            elif op in ('movz', 'movn', 'movk'):
                value = ins[2] if op == 'movz' else ~ins[2] if op == 'movn' else None
                put(state, ins[1], value)
            elif op == 'adrp':
                put(state, ins[1], ins[2])
            elif op in ('add', 'sub'):
                value = get(state, ins[2], True)
                if word & (1 << 29):
                    state.pop('flags', None)
                    if isinstance(value, tuple) and value[0] == 'column':
                        state['flags'] = value
                if not (word & (1 << 29) and ins[1] in ('x31', 'w31')):
                    put(state, ins[1], add(value, ins[3] if op == 'add' else -ins[3]), True)
            elif op == 'cset':
                put(state, ins[1], state.get('flags'))
            elif op in ('logical_imm', 'bitfield'):
                # Preserve source provenance through scalar masks/extensions.
                # BFM merges destination bits and cannot be treated this way.
                value = get(state, ins[2])
                if op == 'bitfield' and (word >> 29) & 3 == 1:
                    value = None
                put(state, ins[1], value if isinstance(value, tuple) and value[0] == 'column' else None)
                if op == 'logical_imm' and (word >> 29) & 3 == 3:
                    state.pop('flags', None)
            elif op == 'logical_reg':
                # Composite cache keys are not a single database field.
                put(state, ins[1], None)
                if (word >> 29) & 3 == 3:
                    state.pop('flags', None)
            elif op in ('ldr', 'str', 'ldur', 'stur'):
                delta = ins[3]
                mode = ins[4] if len(ins) > 4 else 0
                if mode == 3:
                    put(state, ins[2], add(get(state, ins[2], True), delta), True)
                    delta = 0
                memory(state, ins[2], 0 if mode == 1 else delta, ins[1], op in ('ldr', 'ldur'))
                if mode == 1:
                    put(state, ins[2], add(get(state, ins[2], True), delta), True)
            elif op in ('ldp', 'stp'):
                delta, mode = ins[4:]
                if mode == 3:
                    put(state, ins[3], add(get(state, ins[3], True), delta), True)
                    delta = 0
                size = 8 if ins[1][0] in ('x', 'd') else 4
                memory(state, ins[3], 0 if mode == 1 else delta, ins[1], op == 'ldp')
                memory(state, ins[3], size if mode == 1 else delta + size, ins[2], op == 'ldp')
                if mode == 1:
                    put(state, ins[3], add(get(state, ins[3], True), delta), True)
            elif op == 'bl':
                column = get(state, 'x1')
                is_query = get(state, 'x0') == ('query',)
                # Unknown callees could modify stack storage passed by address.
                escaped_stack = any(isinstance(get(state, 'x' + str(i)), tuple)
                                    and get(state, 'x' + str(i))[0] == 'stack'
                                    for i in range(8))
                if ins[1] not in self.readers and escaped_stack:
                    for k in list(state):
                        if k.startswith('mem:'):
                            del state[k]
                for i in range(19):
                    state.pop('x' + str(i), None)
                for i in list(range(8)) + list(range(16, 32)):
                    state.pop('d' + str(i), None)
                state.pop('flags', None)
                if ins[1] in self.readers and is_query and isinstance(column, int) and column >= 0:
                    put(state, 'd0' if self.readers[ins[1]] == 'GetDouble' else 'x0', ('column', column))
            for dest in edges[pc]:
                if dest not in relevant:
                    continue
                if dest not in states:
                    states[dest] = dict(state)
                    queue.append(dest)
                else:
                    joined = {k: v for k, v in states[dest].items() if k in state and state[k] == v}
                    if joined != states[dest]:
                        states[dest] = joined
                        queue.append(dest)
        if unknown:
            return {'error': 'unsupported instructions on constructor path', 'instructions': sorted(unknown)}
        if not results:
            return {'error': 'no analyzed constructor call'}
        values = list(results.values())
        if any(v != values[0] for v in values):
            return {'error': 'different constructor calls disagree'}
        return {'reader_address': self.addresses[reader_index], 'constructor_address': target,
                'constructor_calls': sorted(results), 'parameters': values[0]}



def analyze(client, *, evidence=None):
    """Build client-named mappings using only the two client files."""
    metadata = client.metadata
    projections = metadata.queries()
    output, failures = {}, {}
    null_flags = 0
    for index, t in enumerate(metadata.types):
        table = metadata.table_constant(index)
        if not table:
            continue
        class_name = metadata.string(t[0])
        readers = [i for i in range(t[9], t[9] + t[16])
                   if metadata.string(metadata.methods[i][0]) == '_CreateCachedOrmByQueryResult']
        nested = metadata.nested[t[12]:t[12] + t[20]] if t[12] >= 0 else []
        records = [metadata.types[n] for n in nested if metadata.string(metadata.types[n][0]) == class_name[6:]]
        constructors = [i for r in records for i in range(r[9], r[9] + r[16])
                        if metadata.string(metadata.methods[i][0]) == '.ctor']
        attempts = [client.trace_constructor(r, c) for r in readers for c in constructors]
        valid = [v for v in attempts if 'parameters' in v]
        queries = projections.get(table, set())
        longest = max(map(len, queries), default=0)
        queries = [q for q in queries if len(q) == longest]
        if len(valid) != 1 or len(queries) != 1:
            failures[table] = {'class': class_name, 'attempts': attempts, 'projection_candidates': len(queries)}
            continue
        result, columns = valid[0], queries[0]
        parameters = result['parameters']
        unresolved = [p for p in parameters if p['query_column'] is None and not p['parameter'].endswith('IsNull')]
        indexes = [p['query_column'] for p in parameters if p['query_column'] is not None]
        if unresolved or sorted(indexes) != list(range(len(columns))):
            failures[table] = {'class': class_name, 'reason': 'projection not covered exactly once', 'trace': result}
            continue
        entry = {columns[p['query_column']]: snake(p['parameter']) for p in parameters if p['query_column'] is not None}
        if len(set(entry.values())) != len(entry):
            failures[table] = {'class': class_name, 'reason': 'normalized parameter names collide'}
            continue
        entry['--table_name'] = snake(class_name[6:])
        if table in output:
            raise ValueError(f'Duplicate table constant: {table}')
        output[table] = entry
        if evidence is not None:
            evidence[table] = {
                'class': class_name,
                'columns': {columns[p['query_column']]: p['parameter']
                            for p in parameters if p['query_column'] is not None},
                'reader_address': result['reader_address'],
                'constructor_address': result['constructor_address'],
            }
        null_flags += sum(p['query_column'] is None for p in parameters)
    real_names = [v['--table_name'] for v in output.values()]
    if len(set(real_names)) != len(real_names):
        raise ValueError('Normalized table names collide')
    if failures:
        details = json.dumps(failures, ensure_ascii=False)
        raise ValueError(f"{len(failures)} 张客户端表未能可靠解析；不覆盖旧 JSON。详情：{details[:2000]}")
    if not output:
        raise ValueError("没有提取到表；请检查两个文件是否来自同一受支持版本")
    return output


# BEGIN VERIFIED ALIASES
# Derived by exact old hash joins; see tools/build_tw_aliases.py.
TABLE_ALIASES = {'MasterAsm4ChoiceData': 'asm_4_choice_data', 'MasterClanBattle2BossData': 'clan_battle_2_boss_data', 'MasterClanBattle2MapData': 'clan_battle_2_map_data', 'MasterGoldsetData2': 'goldset_data_2', 'MasterRarity6QuestData': 'rarity_6_quest_data', 'MasterUnlockRarity6': 'unlock_rarity_6'}
COLUMN_ALIASES = {
    'MasterAlbumVoiceList': {'CueName': 'voice_id', 'CueSheetName': 'sheet_id'},
    'MasterBirthdayLoginBonusData': {'storyId': 'adv_id'},
    'MasterDungeonArea': {'ContentReleaseStoryId': 'content_release_story', 'InitialClearStoryId': 'initial_clear_story'},
    'MasterDungeonAreaData': {'ContentReleaseStoryId': 'content_release_story', 'InitialClearStoryId': 'initial_clear_story'},
    'MasterEReduction': {'Threshold1': 'threshold_1', 'Threshold2': 'threshold_2', 'Threshold3': 'threshold_3', 'Threshold4': 'threshold_4', 'Threshold5': 'threshold_5', 'Value1': 'value_1', 'Value2': 'value_2', 'Value3': 'value_3', 'Value4': 'value_4', 'Value5': 'value_5'},
    'MasterEquipmentCraft': {'Id': 'equipment_id'},
    'MasterEquipmentData': {'Attack': 'atk', 'CraftFlag': 'craft_flg', 'Critical': 'physical_critical', 'Defense': 'def', 'EnhancementPoint': 'equipment_enhance_point', 'Id': 'equipment_id', 'MagicAttack': 'magic_str', 'MagicDefense': 'magic_def', 'MagicPenetration': 'magic_penetrate', 'Name': 'equipment_name', 'Penetration': 'physical_penetrate', 'SellPrice': 'sale_price'},
    'MasterEquipmentEnhanceData': {'EnhanceLevel': 'equipment_enhance_level'},
    'MasterEquipmentEnhanceRate': {'Attack': 'atk', 'Critical': 'physical_critical', 'Defense': 'def', 'Id': 'equipment_id', 'MagicAttack': 'magic_str', 'MagicDefense': 'magic_def', 'MagicPenetration': 'magic_penetrate', 'Penetration': 'physical_penetrate'},
    'MasterEventNaviComment': {'commentType': 'comment_id', 'unitId': 'character_id', 'unitName': 'character_name'},
    'MasterEventNaviCommentCondition': {'commentType': 'comment_id'},
    'MasterExEquipmentData': {'DefaultCritical': 'default_physical_critical', 'DefaultPenetrate': 'default_physical_penetrate', 'MaxCritical': 'max_physical_critical', 'MaxPenetrate': 'max_physical_penetrate', 'Skill1': 'passive_skill_id_1', 'Skill2': 'passive_skill_id_2', 'SkillPower': 'passive_skill_power'},
    'MasterExEquipmentEnhanceData': {'NeededGold': 'needed_mana'},
    'MasterGoldsetData': {'UserJewelCount': 'use_jewel_count'},
    'MasterGoldsetData2': {'UserJewelCount': 'use_jewel_count'},
    'MasterGrowthParameter': {'Equipment1': 'equipment_1', 'Equipment2': 'equipment_2', 'Equipment3': 'equipment_3', 'Equipment4': 'equipment_4', 'Equipment5': 'equipment_5', 'Equipment6': 'equipment_6', 'Rarity': 'unit_rarity'},
    'MasterItemData': {'Id': 'item_id', 'Name': 'item_name', 'Type': 'item_type'},
    'MasterLegionEffect': {'ExSkillBonus': 'bonus_5', 'LevelBonus': 'bonus_1', 'SkillBonus1': 'bonus_3', 'SkillBonus2': 'bonus_4', 'UbBonus': 'bonus_2'},
    'MasterLoginBonusAdv': {'storyId': 'adv_id', 'targetDay': 'count_key'},
    'MasterNaviComment': {'commentType': 'comment_id', 'unitId': 'character_id', 'unitName': 'character_name'},
    'MasterPromotionBonus': {'Attack': 'atk', 'Critical': 'physical_critical', 'Defense': 'def', 'MagicAttack': 'magic_str', 'MagicDefense': 'magic_def', 'MagicPenetration': 'magic_penetrate', 'Penetration': 'physical_penetrate'},
    'MasterRewardCollectGuide': {'Id': 'object_id'},
    'MasterRoomCharacterPersonality': {'characterPersonality': 'personality_id'},
    'MasterRoomChatFormation': {'unit1Dir': 'unit_1_dir', 'unit1X': 'unit_1_x', 'unit1Y': 'unit_1_y', 'unit2Dir': 'unit_2_dir', 'unit2X': 'unit_2_x', 'unit2Y': 'unit_2_y', 'unit3Dir': 'unit_3_dir', 'unit3X': 'unit_3_x', 'unit3Y': 'unit_3_y', 'unit4Dir': 'unit_4_dir', 'unit4X': 'unit_4_x', 'unit4Y': 'unit_4_y', 'unit5Dir': 'unit_5_dir', 'unit5X': 'unit_5_x', 'unit5Y': 'unit_5_y'},
    'MasterRoomItem': {'effectID1': 'effect_id_1'},
    'MasterRoomItemAnnouncement': {'endTime': 'announcement_end', 'startTime': 'announcement_start'},
    'MasterRoomItemDetail': {'levelUpId': 'lvup_trigger_id', 'levelUpId2': 'lvup_trigger_id_2', 'levelUpItemNum1': 'lvup_item1_num', 'levelUpItemType1': 'lvup_item1_type', 'levelUpTime': 'lvup_time', 'levelUpType': 'lvup_trigger_type', 'levelUpType2': 'lvup_trigger_type_2', 'levelUpValue': 'lvup_trigger_value', 'levelUpValue2': 'lvup_trigger_value_2'},
    'MasterSdNaviComment': {'commentType': 'comment_id', 'unitId': 'character_id'},
    'MasterSpDetailVoice': {'CueName01': 'cue_name_1', 'CueName02': 'cue_name_2', 'CueName03': 'cue_name_3', 'CueName04': 'cue_name_4', 'CueName05': 'cue_name_5'},
    'MasterSreEffect': {'ExSkillBonus': 'bonus_5', 'LevelBonus': 'bonus_1', 'SkillBonus1': 'bonus_3', 'SkillBonus2': 'bonus_4', 'UbBonus': 'bonus_2'},
    'MasterUniqueEquipEnhanceRate': {'Attack': 'atk', 'Critical': 'physical_critical', 'Defense': 'def', 'MagicAttack': 'magic_str', 'MagicDefense': 'magic_def', 'MagicPenetration': 'magic_penetrate', 'Penetration': 'physical_penetrate'},
    'MasterUniqueEquipmentCraft': {'Id': 'equip_id'},
    'MasterUniqueEquipmentData': {'Attack': 'atk', 'CraftFlag': 'craft_flg', 'Critical': 'physical_critical', 'Defense': 'def', 'EnhancementPoint': 'equipment_enhance_point', 'Id': 'equipment_id', 'MagicAttack': 'magic_str', 'MagicDefense': 'magic_def', 'MagicPenetration': 'magic_penetrate', 'Name': 'equipment_name', 'Penetration': 'physical_penetrate', 'SellPrice': 'sale_price'},
    'MasterUniqueEquipmentEnhanceData': {'NeededGold': 'needed_mana'},
    'MasterUniqueEquipmentEnhanceRate': {'Attack': 'atk', 'Critical': 'physical_critical', 'Defense': 'def', 'Id': 'equipment_id', 'MagicAttack': 'magic_str', 'MagicDefense': 'magic_def', 'MagicPenetration': 'magic_penetrate', 'Penetration': 'physical_penetrate'},
    'MasterUniqueEquipmentRankup': {'Id': 'equip_id'},
    'MasterUnitData': {'AtkCastTime': 'normal_atk_cast_time', 'CutIn1': 'cutin_1', 'CutIn2': 'cutin_2'},
    'MasterUnitPromotionStatus': {'Attack': 'atk', 'Critical': 'physical_critical', 'Defense': 'def', 'MagicAttack': 'magic_str', 'MagicDefense': 'magic_def', 'MagicPenetration': 'magic_penetrate', 'Penetration': 'physical_penetrate'},
    'MasterUnlockRarity6': {'Attack': 'atk', 'Critical': 'physical_critical', 'Defense': 'def', 'MagicAttack': 'magic_str', 'MagicDefense': 'magic_def', 'MagicPenetration': 'magic_penetrate', 'Penetration': 'physical_penetrate'},
}
# END VERIFIED ALIASES


def standard_names(mapping, evidence):
    """Use exact client class/parameter keys; never apply aliases globally."""
    result = {}
    for table, entry in mapping.items():
        source = evidence[table]
        class_name = source['class']
        aliases = COLUMN_ALIASES.get(class_name, {})
        restored = {h: aliases.get(source['columns'][h], name)
                    for h, name in entry.items() if h != '--table_name'}
        if len(set(restored.values())) != len(restored):
            raise ValueError(f'{class_name} 的标准字段名称冲突')
        restored['--table_name'] = TABLE_ALIASES.get(class_name, entry['--table_name'])
        result[table] = restored
    names = [v['--table_name'] for v in result.values()]
    if len(set(names)) != len(names):
        raise ValueError('标准表名冲突')
    return result


def write_mapping(path, mapping):
    # Same-directory temporary file + replace: a failure never publishes half a JSON.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                                         dir=path.parent, prefix=path.name + '.',
                                         suffix='.tmp', delete=False) as fp:
            temporary = Path(fp.name)
            json.dump(mapping, fp, ensure_ascii=False, indent=4)
            fp.write('\n')
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def main():
    directory = Path(__file__).resolve().parent
    try:
        metadata = Metadata(directory / 'global-metadata.dat')
        elf = Elf(directory / 'libil2cpp.so')
        evidence = {}
        mapping = standard_names(analyze(NativeClient(elf, metadata), evidence=evidence), evidence)
        path = directory / 'rainbow_tw.json'
        write_mapping(path, mapping)
    except (OSError, ValueError, KeyError, IndexError, StopIteration, struct.error) as exc:
        print(f'解码失败，旧 rainbow_tw.json 保持不变：{exc}', file=sys.stderr)
        return 1
    print(f'已生成 {path}：{len(mapping)} 张表，'
          f'{sum(len(v) - 1 for v in mapping.values())} 个字段（已应用标准名称兼容规则）')
    return 0


if __name__ == '__main__':
    sys.exit(main())
