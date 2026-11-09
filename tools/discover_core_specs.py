"""Read-only discovery of exact native public-root blocks; no engine is run."""
import ast
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
VENDOR_SHA = 'a06b13013ce57e00dcc222153c0bad1bde7b6cac984e59f4e7bf86495e3e86f8'
KEY_BYTES = 294


def key_block(data, seeds):
    a, b = seeds
    result = bytearray()
    mask = (1 << 64) - 1
    for octet in data:
        previous = b
        a = ((a << 23) ^ a) & mask
        b = ((a >> 17) ^ (previous >> 26) ^ previous ^ a) & mask
        result.append(((previous + b) & 255) ^ octet)
        a = previous
    return bytes(result)


def all_offsets(data, needle):
    start = 0
    result = []
    while (found := data.find(needle, start)) >= 0:
        result.append(found)
        start = found + 1
    return result


def pinned_specs():
    source = ROOT / 'app/core_specs.py'
    if not source.is_file():
        source = ROOT / 'app/local_engine.py'
    tree = ast.parse(source.read_text(encoding='utf-8-sig'))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(x, ast.Name) and x.id in ('CORE_SPECS', '_SUPPORTED') for x in node.targets):
            return ast.literal_eval(node.value)
    raise ValueError('Pinned specifications unavailable')


def main():
    stock_root = Path(os.environ['APPDATA']) / 'BitBrowser/Chrome-bin'
    stock = sorted(stock_root.rglob('chrome.dll'), key=lambda p: int(p.relative_to(stock_root).parts[0]))
    specs = pinned_specs()
    known = specs['124']
    source = next(p for p in stock if p.relative_to(stock_root).parts[0] == '124')
    with source.open('rb') as stream:
        stream.seek(known['offset'])
        vendor = key_block(stream.read(KEY_BYTES), known['seeds'])
    assert hashlib.sha256(vendor).hexdigest() == VENDOR_SHA
    patterns = {major: key_block(vendor, tuple(specs[major]['seeds'])) for major in ('124', '148')}
    rows = []
    for path in stock:
        with path.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            row = {'major': path.relative_to(stock_root).parts[0], 'relative_dll': path.relative_to(stock_root).as_posix(),
                   'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data), 'matches': [],
                   'seed_occurrences': {major: [[hex(x) for x in all_offsets(data, struct.pack('<Q', seed))] for seed in specs[major]['seeds']] for major in ('124', '148')}}
            for major, pattern in patterns.items():
                for offset in all_offsets(data, pattern):
                    row['matches'].append({'offset': hex(offset), 'seeds': [hex(x) for x in specs[major]['seeds']], 'vendor_der_sha256': VENDOR_SHA})
            if '--discover' in sys.argv:
                discover(data, path, vendor, row)
            rows.append(row)
            print(json.dumps({'major': row['major'], 'known_seed_matches': len(row['matches']),
                              'discovered_block_matches': len(row.get('discovered_matches', [])),
                              'native_functions': len(row.get('native_decoder_functions', []))}, sort_keys=True), flush=True)
    output = ROOT / 'analysis/reports/core-spec-discovery.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({'format': 1, 'scope': 'stock Chrome-bin only; read-only static observations',
                                  'method': 'mmap byte matches, pefile PE mappings/.pdata, Capstone bounded function disassembly',
                                  'not_rea_evidence': True,
                                  'limitations': ['No executable was run.', 'Static public-root and input-chain observations do not prove browser acceptance.'],
                                  'vendor_der_sha256': VENDOR_SHA, 'engines': rows}, indent=2) + '\n', encoding='utf-8')


def discover(data, path, vendor, row):
    # These optional analysis packages live outside the product runtime.
    sys.path.insert(0, str(ROOT / 'analysis/core-spec-work/lib'))
    import capstone
    import pefile
    pe = pefile.PE(str(path), fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    text = next(s for s in pe.sections if s.Name.rstrip(b'\0') == b'.text')
    begin, end = text.PointerToRawData, text.PointerToRawData + text.SizeOfRawData
    candidates = []
    for pos in all_offsets(data, b'\x26\x01\x00\x00'):
        if not begin <= pos < end:
            continue
        before = data[max(begin, pos - 160):pos]
        if all(re.search(rb'\xc1[\xc0-\xff]' + bytes([shift]), before) for shift in (23, 26, 17)):
            candidates.append(pos)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    row['decoder_candidates'] = [hex(x) for x in candidates]
    discoveries = []
    for pos in candidates:
        # Find real MOVABS boundaries by opcode; decoding arbitrary preceding
        # bytes risks losing instruction alignment in a variable-length ISA.
        before_begin = max(begin, pos - 256)
        before = data[before_begin:pos]
        constants = []
        for match in re.finditer(rb'[\x48\x49][\xb8-\xbf].{8}', before, re.S):
            offset = before_begin + match.start()
            instruction = next(decoder.disasm(match.group(), base + pe.get_rva_from_offset(offset)), None)
            if instruction and instruction.mnemonic == 'movabs':
                constants.append((offset, int.from_bytes(match.group()[2:10], 'little')))
        for left_offset, a in constants:
            for right_offset, b in constants:
                if left_offset == right_offset:
                    continue
                encoded = key_block(vendor, (a, b))
                offsets = all_offsets(data, encoded)
                for offset in offsets:
                    item = {'offset': hex(offset), 'seeds': [hex(a), hex(b)], 'vendor_der_sha256': VENDOR_SHA,
                            'decoder_cmp_offset': hex(pos), 'seed_instruction_offsets': [hex(left_offset), hex(right_offset)]}
                    if not any(x['offset'] == item['offset'] and x['seeds'] == item['seeds'] for x in discoveries):
                        discoveries.append(item)
    row['discovered_matches'] = discoveries
    if discoveries:
        corroborate(data, pe, decoder, row, discoveries[0])


def corroborate(data, pe, decoder, row, match):
    import bisect
    from capstone import x86_const as x86
    base = pe.OPTIONAL_HEADER.ImageBase
    pdata = next(s for s in pe.sections if s.Name.rstrip(b'\0') == b'.pdata')
    functions = []
    for offset in range(pdata.PointerToRawData, pdata.PointerToRawData + pdata.SizeOfRawData - 11, 12):
        begin, end, unwind = struct.unpack_from('<III', data, offset)
        if begin and begin < end:
            functions.append((begin, end))
    functions.sort()
    starts = [x[0] for x in functions]

    def instructions_at(va):
        rva = va - base
        index = bisect.bisect_right(starts, rva) - 1
        if index < 0 or not functions[index][0] <= rva < functions[index][1]:
            return []
        start, finish = functions[index]
        if finish - start > 16384:
            return []
        offset = pe.get_offset_from_rva(start)
        length = pe.get_offset_from_rva(finish - 1) + 1 - offset
        return list(decoder.disasm(data[offset:offset + length], base + start))

    def verifier_labels(instructions):
        found = []
        for ins in instructions:
            for op in ins.operands:
                if op.type != x86.X86_OP_MEM or op.mem.base != x86.X86_REG_RIP:
                    continue
                rva = ins.address + ins.size + op.mem.disp - base
                try:
                    value = pe.get_data(rva, 64).split(b'\0')[0]
                except Exception:
                    continue
                if value in (b'VerifyInit', b'VerifyUpdate', b'VerifyFinal'):
                    found.append({'instruction_va': hex(ins.address), 'label': value.decode('ascii')})
        return found
    seeds = [int(x, 16) for x in match['seeds']]
    ranges = set()
    for offset in all_offsets(data, struct.pack('<Q', seeds[0])):
        rva = pe.get_rva_from_offset(offset)
        index = bisect.bisect_right(starts, rva) - 1
        if index >= 0 and functions[index][0] <= rva < functions[index][1]:
            ranges.add(functions[index])
    details = []
    target_rva = pe.get_rva_from_offset(int(match['offset'], 16))
    work = ROOT / 'analysis/core-spec-work'
    work.mkdir(exist_ok=True, parents=True)
    for begin, end in sorted(ranges):
        first = pe.get_offset_from_rva(begin)
        last = pe.get_offset_from_rva(end - 1) + 1
        instructions = list(decoder.disasm(data[first:last], base + begin))
        lines = [f'{ins.address:x} {ins.mnemonic} {ins.op_str}' for ins in instructions]
        alias = f"{row['major']}-decoder-{begin:x}.asm.txt"
        (work / alias).write_text('\n'.join(lines) + '\n', encoding='utf-8')
        refs, updates, direct_calls, init_calls, labels = [], [], [], [], []
        immediate_stores = {}
        length_arguments = {}
        for i, ins in enumerate(instructions):
            for op in ins.operands:
                if op.type == x86.X86_OP_MEM and op.mem.base == x86.X86_REG_RIP:
                    rva = ins.address + ins.size + op.mem.disp - base
                    if abs(rva - target_rva) <= 256:
                        refs.append({'instruction_va': hex(ins.address), 'referenced_rva': hex(rva), 'delta_to_blob': target_rva - rva})
                    try:
                        value = pe.get_data(rva, 64).split(b'\0')[0]
                    except Exception:
                        value = b''
                    if value in (b'VerifyInit', b'VerifyUpdate', b'VerifyFinal'):
                        labels.append({'instruction_va': hex(ins.address), 'label': value.decode('ascii')})
            if (ins.mnemonic == 'mov' and len(ins.operands) == 2 and ins.operands[1].type == x86.X86_OP_IMM):
                value = ins.operands[1].imm
                if ins.operands[0].type == x86.X86_OP_MEM:
                    immediate_stores[i] = value
                elif ins.reg_name(ins.operands[0].reg) == 'r8d' and value in (16, 32):
                    length_arguments[i] = value
                if ins.reg_name(ins.operands[0].reg) == 'edx' and value == 1:
                    for following in instructions[i + 1:i + 5]:
                        if following.mnemonic == 'call' and following.operands[0].type == x86.X86_OP_IMM:
                            init_calls.append({'argument_instruction_va': hex(ins.address), 'call_va': hex(following.address), 'target_va': hex(following.operands[0].imm)})
                            break
            if ins.mnemonic == 'call' and ins.operands[0].type == x86.X86_OP_IMM:
                target = ins.operands[0].imm
                direct_calls.append({'instruction_va': hex(ins.address), 'target_va': hex(target)})
                preceding_lengths = [value for index, value in immediate_stores.items() if i - 10 < index < i and value in (16, 32)]
                for length in preceding_lengths[-1:]:
                    updates.append({'call_va': hex(ins.address), 'target_va': hex(target), 'input_length': length})
            elif ins.mnemonic == 'call':
                preceding_lengths = [value for index, value in length_arguments.items() if i - 5 < index < i]
                if preceding_lengths:
                    operand = ins.operands[0]
                    target = (hex(ins.address + ins.size + operand.mem.disp) if operand.type == x86.X86_OP_MEM and operand.mem.base == x86.X86_REG_RIP else ins.op_str)
                    updates.append({'call_va': hex(ins.address), 'indirect_slot_va': target,
                                    'input_length': preceding_lengths[-1]})
        pairs = []
        for i, update in enumerate(updates):
            if update['input_length'] != 32:
                continue
            for following in updates[i + 1:i + 3]:
                if following['input_length'] == 16 and following.get('target_va', following.get('indirect_slot_va')) == update.get('target_va', update.get('indirect_slot_va')):
                    after = next((x for x in direct_calls if int(x['instruction_va'], 16) > int(following['call_va'], 16)), None)
                    pairs.append({'first': update, 'second': following, 'next_direct_call': after})
                    break
        wrapper_targets = {int(x['target_va'], 16) for x in init_calls}
        for pair in pairs:
            for item in (pair['first'], pair['second']):
                if 'target_va' in item:
                    wrapper_targets.add(int(item['target_va'], 16))
            second = int(pair['second']['call_va'], 16)
            wrapper_targets.update(int(x['target_va'], 16) for x in direct_calls if second < int(x['instruction_va'], 16) < second + 128)
        wrappers = []
        for target in sorted(wrapper_targets):
            wrapper_instructions = instructions_at(target)
            wrapper_labels = verifier_labels(wrapper_instructions)
            if not wrapper_labels:
                continue
            wrapper_alias = f"{row['major']}-verifier-{target:x}.asm.txt"
            (work / wrapper_alias).write_text('\n'.join(f'{ins.address:x} {ins.mnemonic} {ins.op_str}' for ins in wrapper_instructions) + '\n', encoding='utf-8')
            wrappers.append({'target_va': hex(target), 'named_verifier_refs': wrapper_labels, 'assembly_alias': wrapper_alias})
        details.append({'function_begin_va': hex(base + begin), 'function_end_exclusive_va': hex(base + end),
                        'complete_pdata_range_disassembled': bool(instructions and instructions[-1].address + instructions[-1].size == base + end),
                        'assembly_alias': alias, 'public_blob_candidate_refs': refs,
                        'named_verifier_refs': labels,
                        'named_verifier_wrappers': wrappers,
                        'algorithm_argument_one_call_candidates': init_calls, 'update_32_then_16_same_target': pairs})
    row['native_decoder_functions'] = details


if __name__ == '__main__':
    main()
