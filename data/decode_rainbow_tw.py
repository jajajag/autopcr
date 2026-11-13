#!/usr/bin/env python3
"""从 APK / XAPK / APKS 生成 rainbow_tw.json（IL2CPP v31，ARM32 / ARM64）。
python -m pip install 'capstone>=5,<6'
python data/decode_rainbow_tw.py client.xapk
python data/decode_rainbow_tw.py client.apks --db master.db
省略安装包时，在当前目录、脚本目录及项目根目录寻找唯一安装包。
DB 模式生成 *.decoded.db，使用客户端 snake_case 名称、不应用 aliases。
JSON 使用内置兼容名称；新字段保留客户端 snake_case，失败时保留原输出。
"""
# /// script
# requires-python = ">=3.10"
# dependencies = ["capstone>=5,<6"]
# ///

from pathlib import Path
from collections import defaultdict, deque
import bisect
import json
import os
import re
import struct
import sys
import tempfile
import argparse
import sqlite3
import shutil
from contextlib import closing
from zipfile import ZipFile, BadZipFile


ABIS = ('arm64-v8a', 'armeabi-v7a')


def find_package():
    directory = Path(__file__).resolve().parent
    candidates = {p.resolve() for root in (Path.cwd(), directory, directory.parent)
                  for p in root.iterdir() if p.is_file() and p.suffix.lower() in ('.apk', '.xapk', '.apks')}
    if len(candidates) != 1:
        raise ValueError(f'找到 {len(candidates)} 个安装包，请显式传入 APK / XAPK / APKS 路径')
    return candidates.pop()


def load_package(path, abi=None):
    """Read only required ZIP members; nested split APKs never extract to caller paths."""
    metadata, libraries = None, {}
    native_paths = {f'lib/{a}/libil2cpp.so' for a in ABIS if abi is None or a == abi}

    def collect(apk):
        nonlocal metadata
        for item in apk.infolist():
            name = item.filename
            if name.endswith('/global-metadata.dat'):
                data = apk.read(item)
                if metadata is not None and metadata != data:
                    raise ValueError('包内包含不同的 metadata；请使用单一客户端版本的安装包')
                metadata = data
            elif name in native_paths:
                architecture, data = name.split('/')[1], apk.read(item)
                if architecture in libraries and libraries[architecture] != data:
                    raise ValueError(f'包内存在多个不同的 {architecture} 库；请使用单一客户端版本的安装包')
                libraries[architecture] = data

    with ZipFile(path) as archive:
        collect(archive)
        for item in archive.infolist():
            if not item.filename.lower().endswith('.apk'):
                continue
            with archive.open(item) as source, tempfile.SpooledTemporaryFile(max_size=8 << 20) as temporary:
                shutil.copyfileobj(source, temporary)
                temporary.seek(0)
                with ZipFile(temporary) as apk:
                    collect(apk)
    if metadata is None:
        raise ValueError('包内未找到 global-metadata.dat')
    selected = next((a for a in ABIS if a in libraries), None)
    if selected is None:
        raise ValueError(f'包内未找到 {abi or "ARM32 / ARM64"} 的 libil2cpp.so')
    return libraries[selected], metadata, selected


class Metadata:
    def __init__(self, source):
        self.data = source if isinstance(source, bytes) else Path(source).read_bytes()
        self.header = struct.unpack_from('<64I', self.data)
        if self.header[:2] != (0xFAB11BAF, 31):
            raise ValueError('Expected unencrypted IL2CPP metadata version 31')
        for i in range(2, 64, 2):
            if sum(self.header[i:i + 2]) > len(self.data):
                raise ValueError('Metadata section outside file')
        self.types = self.records(40, '<16i8H2I')
        self.fields = self.records(24, '<IiI')
        self.methods = self.records(12, '<7i4H')
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
    def __init__(self, source):
        self.data = source if isinstance(source, bytes) else Path(source).read_bytes()
        if self.data[:4] != b'\x7fELF' or self.data[5] != 1:
            raise ValueError('Expected little-endian ARM ELF')
        self.bits = {1: 32, 2: 64}[self.data[4]]
        self.ptr = self.bits // 8
        self.fmt = '<I' if self.bits == 32 else '<Q'
        if struct.unpack_from('<H', self.data, 18)[0] != (40 if self.bits == 32 else 183):
            raise ValueError('Only ARM32 / ARM64 are supported')
        if self.bits == 32 and struct.unpack_from('<I', self.data, 36)[0] & 0x400:
            raise ValueError('ARM32 hard-float ABI is not supported; expected Android softfp')
        start = struct.unpack_from(self.fmt, self.data, 32 if self.bits == 32 else 40)[0]
        size, count = struct.unpack_from('<HH', self.data, 46 if self.bits == 32 else 58)
        headers = [struct.unpack_from('<10I' if self.bits == 32 else '<IIQQQQIIQQ', self.data, start + i * size)
                   for i in range(count)]
        self.loaded = [h for h in headers if h[2] & 2 and h[1] != 8]
        self.relocations = {}
        for h in headers:
            if h[1] not in (4, 9):  # SHT_RELA / SHT_REL
                continue
            fmt = ('<IIi' if h[1] == 4 else '<II') if self.bits == 32 else ('<QQq' if h[1] == 4 else '<QQ')
            for row in struct.iter_unpack(fmt, self.data[h[4]:h[4] + h[5]]):
                address, info = row[:2]
                if info & (255 if self.bits == 32 else 0xffffffff) == (23 if self.bits == 32 else 1027):
                    self.relocations[address] = row[2] if h[1] == 4 else self.unpack(address)

    def offset(self, address):
        for h in self.loaded:
            if h[3] <= address < h[3] + h[5]:
                return address - h[3] + h[4]
        raise ValueError(f'Address not in file-backed section: {address:#x}')

    def unpack(self, address):
        return struct.unpack_from(self.fmt, self.data, self.offset(address))[0]

    def pointer(self, address):
        if address in self.relocations:
            return self.relocations[address]
        return self.unpack(address)

    def code_module(self, name):
        pos = self.data.index(name.encode() + b'\0')
        address = next(pos - h[4] + h[3] for h in self.loaded if h[4] <= pos < h[4] + h[5])
        candidates = [a for a, v in self.relocations.items() if v == address]
        valid = [(a, self.pointer(a + self.ptr), self.pointer(a + 2 * self.ptr)) for a in candidates
                 if 0 < self.pointer(a + self.ptr) < 1000000]
        if len(valid) != 1:
            raise ValueError(f'Ambiguous code module: {valid}')
        return valid[0]

    def metadata_types(self, type_count):
        p = self.ptr
        needle = struct.pack(self.fmt, type_count)
        candidates = []
        for h in self.loaded:
            if h[2] & 4:
                continue
            pos = h[4]
            while True:
                pos = self.data.find(needle, pos, h[4] + h[5])
                if pos < 0:
                    break
                if self.data[pos + 2 * p:pos + 3 * p] == needle:
                    candidates.append(pos - h[4] + h[3])
                pos += p
        if len(candidates) != 1:
            raise ValueError(f'Ambiguous metadata registration: {candidates}')
        count_address = candidates[0]
        count, pointer = self.pointer(count_address - 4 * p), self.pointer(count_address - 3 * p)
        return [(self.pointer(self.pointer(pointer + i * p) + p) >> 16) & 255 for i in range(count)]


class NativeClient:
    def __init__(self, elf, metadata):
        try:
            import capstone as cs
        except ImportError:
            raise ValueError('请先安装反汇编依赖：python -m pip install "capstone>=5,<6"') from None
        self.elf, self.metadata, self.cs = elf, metadata, cs
        self.disassembler = cs.Cs(cs.CS_ARCH_ARM64 if elf.bits == 64 else cs.CS_ARCH_ARM, cs.CS_MODE_ARM)
        self.disassembler.detail = True
        self.disassembler.skipdata = True  # ARM methods can contain branched-over literal pools.
        self.addresses, self.names, self.module_starts, self.targets = {}, {}, {}, {}
        self.type_kinds = elf.metadata_types(len(metadata.types))
        self.parameters = metadata.records(22, '<IIi')
        needed = {i for i, t in enumerate(metadata.types)
                  if metadata.table_constant(i) or metadata.string(t[0]) == 'Query'}
        for image in metadata.records(42, '<10i'):
            if not any(image[2] <= i < image[2] + image[3] for i in needed):
                continue
            _, count, pointer = elf.code_module(metadata.string(image[0]))
            pointers = [elf.pointer(pointer + i * elf.ptr) for i in range(count)]
            starts = sorted({p & ~1 for p in pointers} - {0})
            for t in metadata.types[image[2]:image[2] + image[3]]:
                for index in range(t[9], t[9] + t[16]):
                    addr = pointers[(metadata.methods[index][6] & 0xffffff) - 1]
                    self.addresses[index] = addr
                    self.names[addr] = metadata.string(t[0]) + '.' + metadata.string(metadata.methods[index][0])
                    self.module_starts[index] = starts
        self.readers = {self.call_target(addr): name.split('.')[-1] for addr, name in self.names.items()
                        if name in ('Query.GetInt', 'Query.GetLong', 'Query.GetDouble', 'Query.GetText')}
        if set(self.readers.values()) != {'GetInt', 'GetLong', 'GetDouble', 'GetText'}:
            raise ValueError('数据库读取方法不完整；客户端布局可能已变化')

    def disassemble(self, address, size):
        self.disassembler.mode = (self.cs.CS_MODE_THUMB if address & 1 else self.cs.CS_MODE_ARM)
        offset = self.elf.offset(address & ~1)
        return list(self.disassembler.disasm(self.elf.data[offset:offset + size], address & ~1))

    def instructions(self, index):
        address = self.addresses[index]
        starts = self.module_starts[index]
        next_index = bisect.bisect_right(starts, address & ~1)
        end = starts[next_index] if next_index < len(starts) else next(
            h[3] + h[5] for h in self.elf.loaded if h[3] <= (address & ~1) < h[3] + h[5])
        return {ins.address: ins for ins in self.disassemble(address, end - (address & ~1)) if ins.id}

    def call_target(self, address):
        """Resolve direct branches and ARM linker veneers, without following method bodies."""
        if address in self.targets:
            return self.targets[address]
        original, seen = address, set()
        while address not in seen:
            seen.add(address)
            code = self.disassemble(address, 16)
            if code and code[0].id and code[0].insn_name() == 'b' and code[0].cc in (0, 15):
                address = code[0].operands[0].imm | (address & 1)
            elif self.elf.bits == 32 and [i.mnemonic for i in code] == ['movw', 'movt', 'add', 'bx']:
                a, b, c, d = [i.operands for i in code]
                reg = code[0].reg_name(a[0].reg)
                if (all(i.reg_name(o.reg) == reg for i, o in
                        [(code[1], b[0]), (code[2], c[0]), (code[2], c[1]), (code[3], d[0])])
                        and code[2].reg_name(c[2].reg) == 'pc'):
                    address = (((b[1].imm << 16) | a[1].imm) + code[2].address + 8) & 0xffffffff
                else:
                    break
            else:
                break
        self.targets[original] = address & ~1
        return address & ~1

    def method_parameters(self, index):
        method = self.metadata.methods[index]
        return [(self.metadata.string(p[0]), self.type_kinds[p[2]])
                for p in self.parameters[method[4]:method[4] + method[-1]]]

    def trace_constructor(self, reader_index, ctor_index):
        """Track query-column provenance through registers, stack slots and control-flow joins."""
        code = self.instructions(reader_index)
        target = self.call_target(self.addresses[ctor_index])
        calls = {}
        for pc, ins in code.items():
            if ins.mnemonic in ('bl', 'blx') and ins.operands[0].type == 2:
                thumb = self.elf.bits == 32 and bool(self.addresses[reader_index] & 1) != (ins.mnemonic == 'blx')
                calls[pc] = self.call_target(ins.operands[0].imm | int(thumb))
        sinks = {pc for pc, addr in calls.items() if addr == target}
        if not sinks:
            return {'error': 'constructor not directly called'}
        arm32 = self.elf.bits == 32
        # Capstone shares REG/IMM/MEM operand tags and EQ/NE/AL condition values.
        def register_name(name):
            name = {'sb': 'r9', 'sl': 'r10', 'fp': 'r11' if arm32 else 'x29',
                    'ip': 'r12', 'lr': 'r14' if arm32 else 'x30'}.get(name, name)
            if name.startswith(('w', 'x')) and name[1:].isdigit():
                name = 'r' + name[1:]
            if not arm32 and name.startswith('s') and name[1:].isdigit():
                name = 'd' + name[1:]
            return name

        def reg(ins, operand):
            return register_name(ins.reg_name(operand.reg))

        def get(state, ins, operand):
            if operand.type == 2:
                return operand.imm << getattr(operand.shift, 'value', 0)
            if operand.type != 1:
                return None
            name = reg(ins, operand)
            if name in ('xzr', 'wzr'):
                return 0
            if name == 'pc':
                return (ins.address + (4 if ins.size == 2 or self.addresses[reader_index] & 1 else 8)) & ~3
            value = state.get(name)
            if getattr(operand.shift, 'value', 0):
                return value if column(value) else None
            return value

        def put(state, ins, operand, value):
            name = reg(ins, operand)
            if name not in ('xzr', 'wzr'):
                if value is None:
                    state.pop(name, None)
                else:
                    state[name] = value

        def column(value):
            return isinstance(value, tuple) and value[0] == 'column'

        def add(value, delta):
            if not isinstance(delta, int):
                return None
            if isinstance(value, int):
                return value + delta
            return ('stack', value[1] + delta) if isinstance(value, tuple) and value[0] == 'stack' else None

        def load(state, address, size):
            if not (isinstance(address, tuple) and address[0] == 'stack'):
                return None
            cells = [state.get(('mem', address[1] + n)) for n in range(0, size, 4)]
            return cells[0] if cells and all(c == cells[0] for c in cells) else None

        def store(state, address, value, size):
            if isinstance(address, tuple) and address[0] == 'stack':
                for n in range(0, size, 4):
                    key = ('mem', address[1] + n)
                    if value is None:
                        state.pop(key, None)
                    else:
                        state[key] = value

        def width(ins, operand):
            name = ins.reg_name(operand.reg)
            return 8 if name.startswith(('x', 'd')) or (not arm32 and name in ('fp', 'lr', 'sp')) else 4

        def condition(state, cc):
            if cc in (0, 15):
                return True
            a, b = state.get('flags', (None, None))
            equal = None
            if isinstance(a, int) and isinstance(b, int):
                equal = a == b
            elif a is not None and a == b:
                equal = True
            if (a == ('query',) and b == 0) or (b == ('query',) and a == 0):
                equal = False
            if cc == 1:
                return equal
            return not equal if cc == 2 and equal is not None else None

        edges, reverse = {}, defaultdict(set)
        for pc, ins in code.items():
            op = ins.insn_name()
            if pc in sinks or op in ('ret', 'bx') or (op == 'pop' and 'pc' in ins.op_str):
                nxt = []
            elif op == 'b':
                nxt = [ins.operands[0].imm]
                if ins.cc not in (0, 15):
                    nxt.append(pc + ins.size)
            elif op in ('cbz', 'cbnz', 'tbz', 'tbnz'):
                nxt = [ins.operands[-1].imm, pc + ins.size]
            else:
                nxt = [pc + ins.size]
            edges[pc] = [p for p in nxt if p in code]
            for p in edges[pc]:
                reverse[p].add(pc)
        relevant, todo = set(sinks), list(sinks)
        while todo:
            for pc in reverse[todo.pop()]:
                if pc not in relevant:
                    relevant.add(pc)
                    todo.append(pc)
        start = min(code)
        if start not in relevant:
            return {'error': 'no constructor path'}
        states, queue, results, errors = {start: {'r1': ('query',), 'sp': ('stack', 0)}}, deque([start]), {}, set()

        def arguments(state):
            params, integer, floating, stack = [], 1, 0, 0
            for name, kind in self.method_parameters(ctor_index):
                if kind not in (2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 18, 28):
                    raise ValueError(f'Unsupported constructor argument kind {kind}')
                wide = kind in (10, 11, 13)
                if not arm32 and kind in (12, 13) and floating < 8:
                    value = state.get('d' + str(floating))
                    floating += 1
                else:
                    size = 8 if not arm32 or wide else 4
                    if arm32 and wide:
                        integer = (integer + 1) & ~1
                    limit = 4 if arm32 else 8
                    if (arm32 or kind not in (12, 13)) and integer < limit:
                        value = state.get('r' + str(integer))
                        if arm32 and wide and state.get('r' + str(integer + 1)) != value:
                            value = None
                        integer += size // self.elf.ptr
                    else:
                        stack = (stack + size - 1) & -size
                        value = load(state, add(state.get('sp'), stack), size)
                        stack += size
                params.append({'parameter': name, 'query_column': value[1] if column(value) else None})
            return params

        steps = 0
        while queue:
            pc = queue.popleft()
            state = dict(states[pc])
            steps += 1
            if steps > 100000:
                return {'error': 'dataflow iteration limit'}
            ins, successors = code[pc], edges[pc]
            op, operands = ins.mnemonic, ins.operands
            if pc in sinks:
                results[pc] = arguments(state)
                continue
            execute = condition(state, ins.cc) if arm32 else True
            # ARM predicates are suffixes; ARM64 encodes conditions on branches/selects only.
            base = ins.insn_name()
            before = dict(state)
            values = [get(state, ins, o) for o in operands]
            if execute is not False:
                if base in ('mov', 'movw', 'movz', 'movn', 'movk', 'movt', 'fmov'):
                    value = values[1]
                    if base in ('movt', 'movk'):
                        old = values[0]
                        shift = 16 if base == 'movt' else operands[1].shift.value
                        value = ((old & ~(0xffff << shift)) | (value << 16 if base == 'movt' else value)) if isinstance(old, int) else None
                    elif base == 'movn':
                        value = ~value
                    if execute is None and isinstance(value, int) and value in (0, 1):
                        a, b = state.get('flags', (None, None))
                        if column(a) and b == 0 and values[0] == 1 - value:
                            value = a
                            before[reg(ins, operands[0])] = value
                    put(state, ins, operands[0], value)
                elif base == 'vmov':
                    if len(operands) == 2:
                        put(state, ins, operands[0], values[1])
                    elif reg(ins, operands[0]).startswith('d'):
                        put(state, ins, operands[0], values[1] if values[1] == values[2] else None)
                    else:
                        for o in operands[:2]:
                            put(state, ins, o, values[2])
                elif base in ('adr', 'adrp'):
                    put(state, ins, operands[0], values[1])
                elif base in ('add', 'sub'):
                    delta = values[2]
                    if base == 'sub':
                        delta = -delta if isinstance(delta, int) else None
                    value = add(values[1], delta)
                    if column(values[1]) and isinstance(values[2], int):
                        value = values[1]
                    put(state, ins, operands[0], value)
                elif base in ('cmp', 'cmn', 'tst'):
                    state['flags'] = (values[0], values[1])
                elif base in ('cset', 'csetm'):
                    a, b = state.get('flags', (None, None))
                    put(state, ins, operands[0], a if column(a) and b == 0 else None)
                elif base in ('and', 'ands', 'ubfx', 'sbfx', 'uxtb', 'uxth', 'sxtb', 'sxth', 'sxtw', 'lsl', 'lsr', 'asr', 'clz'):
                    put(state, ins, operands[0], values[1] if column(values[1]) else None)
                elif base in ('orr', 'eor', 'bic', 'bfi', 'bfxil', 'pkhbt'):
                    put(state, ins, operands[0], None)
                elif base.startswith(('ldr', 'str', 'ldur', 'stur', 'vldr', 'vstr')) or base in ('ldp', 'stp'):
                    memory = next(o for o in operands if o.type == 3)
                    regs = operands[:list(operands).index(memory)]
                    name = register_name(ins.reg_name(memory.mem.base))
                    address = add(state.get(name), memory.mem.disp) if not memory.mem.index else None
                    if ins.writeback and ins.op_str.rstrip().endswith('!'):
                        state[name] = address
                    delta = 0
                    for o in regs:
                        size = width(ins, o)
                        if base in ('ldrd', 'strd'):
                            size = 4
                        if 'ld' in base:
                            put(state, ins, o, load(state, add(address, delta), size))
                        else:
                            store(state, add(address, delta), get(state, ins, o), size)
                        delta += size
                    if ins.writeback and operands[-1].type == 2:
                        state[name] = add(state.get(name), operands[-1].imm)
                elif base in ('push', 'vpush', 'pop', 'vpop') or base.startswith(('stm', 'ldm', 'vstm', 'vldm')):
                    push, pop = base in ('push', 'vpush'), base in ('pop', 'vpop')
                    name = 'sp' if push or pop else reg(ins, operands[0])
                    regs = operands if push or pop else operands[1:]
                    size = sum(width(ins, o) for o in regs)
                    address = add(state.get(name), -size if push or 'db' in base else 4 if 'ib' in base else 0)
                    delta = 0
                    for o in regs:
                        if pop or 'ldm' in base:
                            put(state, ins, o, load(state, add(address, delta), width(ins, o)))
                        else:
                            store(state, add(address, delta), get(state, ins, o), width(ins, o))
                        delta += width(ins, o)
                    if push or pop or ins.writeback:
                        state[name] = add(state.get(name), -size if push or 'db' in base else size)
                elif pc in calls:
                    addr, index = calls[pc], state.get('r1')
                    is_query = state.get('r0') == ('query',)
                    if addr not in self.readers and any(isinstance(state.get('r' + str(i)), tuple)
                            and state['r' + str(i)][0] == 'stack' for i in range(4 if arm32 else 8)):
                        state = {k: v for k, v in state.items() if not isinstance(k, tuple)}
                    for name in [*('r' + str(i) for i in ([0, 1, 2, 3, 12, 14] if arm32 else range(19))),
                                 *('d' + str(i) for i in [*range(8), *range(16, 32)]), 'flags']:
                        state.pop(name, None)
                    if addr in self.readers and is_query and isinstance(index, int) and index >= 0:
                        value = ('column', index)
                        state['d0' if not arm32 and self.readers[addr] == 'GetDouble' else 'r0'] = value
                        if arm32 and self.readers[addr] in ('GetLong', 'GetDouble'):
                            state['r1'] = value
                elif base not in ('b', 'cbz', 'cbnz', 'tbz', 'tbnz', 'nop', 'ret', 'bx'):
                    errors.add(f'{pc:#x}: {op} {ins.op_str}')
                    continue
                if getattr(ins, 'update_flags', False) and base not in ('cmp', 'cmn', 'tst'):
                    state.pop('flags', None)
                if execute is None:
                    state = {k: v for k, v in state.items() if before.get(k) == v}
            if base == 'b':
                branch = condition(before, ins.cc)
                if branch is not None:
                    successors = [ins.operands[0].imm] if branch else [pc + ins.size]
            elif base in ('cbz', 'cbnz'):
                value = values[0]
                if value == ('query',) or isinstance(value, int):
                    zero = value == 0
                    successors = [operands[-1].imm] if zero == (base == 'cbz') else [pc + ins.size]
            for dest in successors:
                if dest not in relevant:
                    continue
                joined = {k: v for k, v in states[dest].items() if k in state and state[k] == v} if dest in states else state
                if dest not in states or joined != states[dest]:
                    states[dest] = dict(joined)
                    queue.append(dest)
        if errors or not results:
            return {'error': 'unsupported constructor path', 'instructions': sorted(errors)}
        values = list(results.values())
        if any(v != values[0] for v in values):
            return {'error': 'different constructor calls disagree'}
        return {'reader_address': self.addresses[reader_index], 'constructor_address': target,
                'parameters': values[0]}


def analyze(client, *, evidence=None):
    """Build mappings from native argument provenance and metadata SQL projections."""
    metadata = client.metadata
    projections = metadata.queries()
    output, failures = {}, {}
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
    real_names = [v['--table_name'] for v in output.values()]
    if len(set(real_names)) != len(real_names):
        raise ValueError('Normalized table names collide')
    if failures:
        details = json.dumps(failures, ensure_ascii=False)
        raise ValueError(f"{len(failures)} 张客户端表未能可靠解析；不覆盖旧 JSON。详情：{details[:2000]}")
    if not output:
        raise ValueError('没有提取到表；请检查安装包是否为受支持的客户端版本')
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


def decode_database(source, mapping):
    """Decode a read-only input into a separate, atomically published copy."""
    source = Path(source).resolve(strict=True)
    output = source.with_name(source.stem + '.decoded.db')
    names = {}
    for table, columns in mapping.items():
        for hashed, name in [(table, columns['--table_name']),
                             *((h, n) for h, n in columns.items() if h != '--table_name')]:
            if hashed in names and names[hashed] != name:
                raise ValueError(f'冲突的哈希名称：{hashed}')
            names[hashed] = name

    # Replace SQL identifiers only, never string literals or comments.
    tokens = re.compile(r"'[^']*(?:''[^']*)*'|--[^\n]*|/\*.*?\*/|"
                        r'"(?:[^"]|"")*"|`(?:[^`]|``)*`|\[[^\]]*\]|[A-Za-z0-9_]+', re.S)

    def restore(sql, kind):
        depth, previous, constraint_depth, keyword = 0, 0, None, ''
        def replace(match):
            nonlocal depth, previous, constraint_depth, keyword
            gap = sql[previous:match.start()]
            depth += gap.count('(') - gap.count(')')
            if constraint_depth is not None and depth < constraint_depth:
                constraint_depth = None
            if '(' in gap and keyword in ('KEY', 'UNIQUE'):
                constraint_depth = depth
            previous = match.end()
            token = match[0]
            if token.startswith(('--', '/*')):
                return token
            if token.startswith("'"):
                # SQLite accepts legacy single-quoted table/column declarations.
                # DEFAULT strings and expressions must remain literal values.
                declaration = kind == 'table' and (depth == 0 or depth == constraint_depth
                                                   or (depth == 1 and gap.strip() in ('(', ',')))
                index_identifier = kind == 'index' and (keyword == 'ON'
                                                        or (depth == 1 and gap.strip() in ('(', ',')))
                if not (declaration or index_identifier):
                    return token
            if token[0] in ('"', '`', '[', "'"):
                quote = token[0]
                key = token[1:-1].replace(quote * 2, quote)
            else:
                key = token
            keyword = token.upper()
            return '"' + names[key].replace('"', '""') + '"' if key in names else token
        return tokens.sub(replace, sql) if sql else sql

    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=output.parent, suffix='.tmp', delete=False) as fp:
            temporary = Path(fp.name)
        with closing(sqlite3.connect(source.as_uri() + '?mode=ro', uri=True)) as original:
            with closing(sqlite3.connect(temporary)) as target:
                original.backup(target)
                rows = target.execute('SELECT rowid,type,name,tbl_name,sql FROM sqlite_master').fetchall()
                matched = [name for _, kind, name, _, _ in rows if kind == 'table' and name in mapping]
                if not matched:
                    raise ValueError('DB 中没有匹配的哈希表；请使用同版本原始 DB，而非已经解码的 DB')
                version = target.execute('PRAGMA schema_version').fetchone()[0]
                target.execute('PRAGMA writable_schema=ON')
                updates = []
                for rowid, kind, name, table, sql in rows:
                    new_name = names.get(name, name)
                    if kind == 'index' and sql is None and name.startswith('sqlite_autoindex_' + table + '_'):
                        new_name = 'sqlite_autoindex_' + names.get(table, table) + name[len('sqlite_autoindex_' + table):]
                    updates.append((new_name, names.get(table, table), restore(sql, kind), rowid))
                target.executemany('UPDATE sqlite_master SET name=?,tbl_name=?,sql=? WHERE rowid=?', updates)
                target.execute(f'PRAGMA schema_version={version + 1}')
                target.commit()
                target.execute('PRAGMA writable_schema=OFF')
        # A fresh connection must be able to parse and validate the new schema.
        with closing(sqlite3.connect(temporary)) as target:
            if target.execute("SELECT 1 FROM sqlite_master WHERE name='sqlite_sequence'").fetchone():
                target.executemany('UPDATE sqlite_sequence SET name=? WHERE name=?',
                                   [(mapping[t]['--table_name'], t) for t in matched])
            target.execute('ANALYZE')
            target.commit()
            check = target.execute('PRAGMA integrity_check').fetchall()
            if check != [('ok',)]:
                raise ValueError(f'解码后数据库完整性检查失败：{check[:5]}')
        os.replace(temporary, output)
        return output, len(matched)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('package', nargs='?', type=Path, help='APK / XAPK / APKS；省略则自动寻找唯一安装包')
    parser.add_argument('--db', type=Path, help='解码同版本原始哈希 SQLite DB，生成 *.decoded.db')
    parser.add_argument('--abi', choices=ABIS, help='指定架构；默认优先 ARM64，其次 ARM32')
    parser.add_argument('-o', '--output', type=Path, help='JSON 输出路径；默认 data/rainbow_tw.json')
    args = parser.parse_args()
    if args.db and args.output:
        parser.error('--db 与 --output 不能同时使用')
    directory = Path(__file__).resolve().parent
    try:
        package = args.package if args.package is not None else find_package()
        native, metadata, abi = load_package(package, args.abi)
        elf = Elf(native)
        if elf.bits != (64 if abi == 'arm64-v8a' else 32):
            raise ValueError(f'{abi} 与库的 ELF 架构不匹配')
        client = NativeClient(elf, Metadata(metadata))
        print(f'读取 {package}（{abi}）')
        evidence = {}
        mapping = analyze(client, evidence=evidence)
        if args.db is not None:
            path, count = decode_database(args.db, mapping)
            print(f'已生成 {path}：恢复 {count} 张表（客户端 snake_case 名称，不使用 aliases；未识别名称保留哈希）')
            return 0
        mapping = standard_names(mapping, evidence)
        path = args.output or directory / 'rainbow_tw.json'
        write_mapping(path, mapping)
    except (OSError, ValueError, KeyError, IndexError, StopIteration, struct.error, sqlite3.Error, BadZipFile) as exc:
        print(f'解码失败，原输出保持不变：{exc}', file=sys.stderr)
        return 1
    print(f'已生成 {path}：{len(mapping)} 张表，'
          f'{sum(len(v) - 1 for v in mapping.values())} 个字段（已应用标准名称兼容规则）')
    return 0


if __name__ == '__main__':
    sys.exit(main())
