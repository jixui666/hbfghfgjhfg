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
starts_off, imports_off, symbols_off = hdr[1], hdr[2], hdr[3]
imports_count, imports_format = hdr[4], hdr[5]
imports = []
p = fixups_off + imports_off
for k in range(imports_count):
    u = struct.unpack('<I', data[p:p+4])[0]
    lib = u & 0xff
    no = u >> 9
    end = data.find(b'\0', fixups_off + symbols_off + no)
    name = data[fixups_off+symbols_off+no:end].decode()
    imports.append((lib, name))
    p += 4

got_addr, got_size = secs[('__DATA_CONST', '__got')]
got_map = {}
f = v2f(got_addr)
for i in range(got_size // 8):
    ptr = struct.unpack('<Q', data[f+i*8:f+i*8+8])[0]
    if ptr >> 63:
        ordinal = ptr & 0xFFFFFF
        got_map[got_addr + i*8] = imports[ordinal][1] if ordinal < len(imports) else '?'
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
    nm = got_map.get(slot)
    stub_names[sa] = nm or f'<slot 0x{slot:x}>'

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

# xrefs to data: adrp reg -> base; add reg, reg, imm -> target
interesting = set(sel_map.keys())
interesting.add(0x12c798)
interesting.add(0x130dd0)
interesting.add(0x12c778)
interesting.add(0x12c798 + 32)
interesting.add(0x130cc0)
xrefs = {}
last_adrp = {}
for addr in sorted(insns):
    ins = insns[addr]
    if ins.mnemonic == 'adrp':
        rd = ins.operands[0].reg
        base = ins.operands[1].imm  # capstone gives the page address directly
        last_adrp[rd] = base
    elif ins.mnemonic == 'add' and len(ins.operands) == 3:
        rd = ins.operands[0].reg
        rn = ins.operands[1].reg
        if ins.operands[2].type == ARM64_OP_IMM and rn in last_adrp:
            tgt = last_adrp[rn] + ins.operands[2].imm
            if tgt in interesting or 0x12c000 <= tgt <= 0x170000:
                xrefs.setdefault(tgt, []).append(addr)

print('=== data xrefs ===')
for tgt in sorted(xrefs):
    label = sel_map.get(tgt) or got_map.get(tgt) or (f'0x{tgt:x}')
    print(f'{label:50s} <- {[hex(x) for x in xrefs[tgt]]}')

print('=== stub call sites ===')
for addr in sorted(insns):
    ins = insns[addr]
    if ins.mnemonic == 'bl' and ins.operands[0].type == ARM64_OP_IMM:
        tgt = ins.operands[0].imm
        if tgt in stub_names:
            print(f'0x{addr:x}: bl {stub_names[tgt]}')
