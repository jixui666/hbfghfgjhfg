import struct, sys
from capstone import *
from capstone.arm64 import *

path = sys.argv[1]
data = open(path, 'rb').read()
ncmds = struct.unpack('<I', data[16:20])[0]
off = 32
segs = {}
secs = {}
fixups_off = fixups_size = 0
for i in range(ncmds):
    cmd, cmdsize = struct.unpack('<II', data[off:off+8])
    if cmd == 0x19:
        segname = data[off+8:off+24].rstrip(b'\0').decode()
        vmaddr, vmsize = struct.unpack('<QQ', data[off+24:off+40])
        foff = struct.unpack('<Q', data[40+off:48+off])[0]
        segs[segname] = (vmaddr, vmsize, foff)
        nsects = struct.unpack('<I', data[off+64:off+68])[0]
        so = off + 72
        for j in range(nsects):
            name = data[so:so+16].rstrip(b'\0').decode()
            addr = struct.unpack('<Q', data[so+32:so+40])[0]
            size = struct.unpack('<Q', data[so+40:so+48])[0]
            secs[(segname, name)] = (addr, size)
            so += 80
    if cmd == 0x80000034:
        fixups_off, fixups_size = struct.unpack('<II', data[off+8:off+16])
    off += cmdsize

def v2f(addr):
    for name, (vmaddr, vmsize, foff) in segs.items():
        if vmaddr <= addr < vmaddr + vmsize:
            return foff + (addr - vmaddr)
    return None

hdr = struct.unpack('<7I', data[fixups_off:fixups_off+28])
imports_off, symbols_off = hdr[2], hdr[3]
imports_count = hdr[4]
imports = []
p = fixups_off + imports_off
for k in range(imports_count):
    u = struct.unpack('<I', data[p:p+4])[0]
    no = u >> 9
    end = data.find(b'\0', fixups_off + symbols_off + no)
    imports.append(data[fixups_off+symbols_off+no:end].decode())
    p += 4

got_addr, got_size = secs[('__DATA_CONST', '__got')]
got_map = {}
f = v2f(got_addr)
for i in range(got_size // 8):
    ptr = struct.unpack('<Q', data[f+i*8:f+i*8+8])[0]
    if ptr >> 63:
        ordinal = ptr & 0xFFFFFF
        got_map[got_addr + i*8] = imports[ordinal] if ordinal < len(imports) else '?'
    else:
        got_map[got_addr + i*8] = None

stubs_addr, stubs_size = secs[('__TEXT', '__stubs')]
stub_names = {}
for i in range(stubs_size // 12):
    sa = stubs_addr + i*12
    ins = data[v2f(sa):v2f(sa)+12]
    if len(ins) < 12: break
    ldr = struct.unpack('<I', ins[4:8])[0]
    imm = (ldr >> 10) & 0xFFF
    adrp = struct.unpack('<I', ins[0:4])[0]
    immlo = (adrp >> 29) & 3
    immhi = (adrp >> 5) & 0x7FFFF
    val = (immhi << 2 | immlo) << 12
    if val & (1 << 32): val -= 1 << 33
    base = (sa & ~0xFFF) + val
    slot = base + (imm << 3)
    stub_names[sa] = got_map.get(slot) or f'<slot 0x{slot:x}>'

selrefs_addr, selrefs_size = secs[('__DATA', '__objc_selrefs')]
MASK = 0x7FFFFFFFFFF
sel_map = {}
f = v2f(selrefs_addr)
for i in range(selrefs_size // 8):
    sa = selrefs_addr + i*8
    p_ = struct.unpack('<Q', data[f+i*8:f+i*8+8])[0] & MASK
    end = data.find(b'\0', p_)
    sel_map[sa] = data[p_:end].decode()

text_addr, text_size = secs[('__TEXT', '__text')]
code = data[v2f(text_addr): v2f(text_addr)+text_size]
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
insns = {}
for ins in md.disasm(code, text_addr):
    insns[ins.address] = ins

# function starts: entry + branch targets
starts = {text_addr}
for addr, ins in insns.items():
    if ins.mnemonic in ('b', 'bl', 'cbz', 'cbnz', 'tbz', 'tbnz') or ins.mnemonic.startswith('b.'):
        for op in ins.operands:
            if op.type == ARM64_OP_IMM:
                starts.add(op.imm)

def annotate(ins, addr):
    extra = []
    if ins.mnemonic == 'bl' and ins.operands[0].type == ARM64_OP_IMM:
        tgt = ins.operands[0].imm
        if tgt in stub_names:
            extra.append(f'[{stub_names[tgt]}]')
        else:
            extra.append(f'[fn 0x{tgt:x}]')
    # data refs: adrp xN,page
    if ins.mnemonic == 'adrp':
        base = ins.operands[1].imm
        extra.append(f'(page 0x{base:x})')
    # ldr x?, [xN, #imm] after adrp -> possible selref/got
    if ins.mnemonic in ('ldr', 'ldur') and ins.operands[1].type == ARM64_OP_MEM:
        rn = ins.operands[1].mem.base
        disp = ins.operands[1].mem.disp
        # find recent adrp for rn
        for back in range(1, 6):
            a2 = addr - back*4
            if a2 in insns and insns[a2].mnemonic == 'adrp' and insns[a2].operands[0].reg == rn:
                slot = insns[a2].operands[1].imm + disp
                if slot in sel_map:
                    extra.append(f'SEL:{sel_map[slot]}')
                if slot in got_map:
                    extra.append(f'GOT:{got_map[slot]}')
                break
    return extra

def dump_fn(start, end=None):
    print(f'== function 0x{start:x} ==')
    a = start
    while a in insns and (end is None or a < end):
        ins = insns[a]
        if a != start and a in starts and ins.mnemonic != 'ret':
            break
        ex = annotate(ins, a)
        print(f'0x{a:x}: {ins.mnemonic:8s} {ins.op_str:40s} {" ".join(ex)}')
        a += 4

# dump functions containing interesting addresses
interesting = {
    0x53980: 'HTTP wrapper A',
    0xd010: 'JSON parse A',
    0xf4cc: 'JSON parse B',
    0x6c034: 'JSON parse C',
    0x31b3c: 'isEqual A',
    0x362dc: 'isEqual B',
    0x388c8: 'isEqual C',
    0x3d2ec: 'isEqual D',
    0x1f99c: 'isEqual E',
}
for addr, label in sorted(interesting.items()):
    # find containing function start
    fn_start = max(s for s in starts if s <= addr)
    print(f'#### {label} @ 0x{addr:x} in fn 0x{fn_start:x}')
    dump_fn(fn_start)
    print()
