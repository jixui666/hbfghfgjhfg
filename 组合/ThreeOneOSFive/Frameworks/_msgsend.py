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
imports_count, imports_format = hdr[4], hdr[5]
imports = []
p = fixups_off + imports_off
for k in range(imports_count):
    u = struct.unpack('<I', data[p:p+4])[0]
    lib = u & 0xff
    no = u >> 9
    end = data.find(b'\0', fixups_off + symbols_off + no)
    imports.append((lib, data[fixups_off+symbols_off+no:end].decode()))
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

addrs = sorted(insns)
by_addr = {a: insns[a] for a in addrs}

def sel_for_msgSend(addr):
    a = addr
    for _ in range(8):
        a -= 4
        if a not in by_addr: break
        ins = by_addr[a]
        # pattern: ldr x1, [xN, #imm] with adrp xN,page before
        if ins.mnemonic == 'ldr' and ins.operands[0].reg == ARM64_REG_X1 and \
           ins.operands[1].type == ARM64_OP_MEM:
            rn = ins.operands[1].mem.base
            disp = ins.operands[1].mem.disp
            b = a - 4
            if b in by_addr and by_addr[b].mnemonic == 'adrp' and by_addr[b].operands[0].reg == rn:
                base = by_addr[b].operands[1].imm
                slot = base + disp
                return sel_map.get(slot)
        # pattern: adrp x1,page + add x1,x1,#imm
        if ins.mnemonic == 'add' and len(ins.operands) == 3 and \
           ins.operands[0].reg == ARM64_REG_X1 and ins.operands[1].reg == ARM64_REG_X1 and \
           ins.operands[2].type == ARM64_OP_IMM:
            b = a - 4
            if b in by_addr and by_addr[b].mnemonic == 'adrp' and by_addr[b].operands[0].reg == ARM64_REG_X1:
                base = by_addr[b].operands[1].imm
                slot = base + ins.operands[2].imm
                return sel_map.get(slot)
    return None

for addr in addrs:
    ins = insns[addr]
    if ins.mnemonic == 'bl' and ins.operands[0].type == ARM64_OP_IMM:
        tgt = ins.operands[0].imm
        if tgt in stub_names and stub_names[tgt] == '_objc_msgSend':
            sel = sel_for_msgSend(addr)
            if sel:
                print(f'0x{addr:x}: msgSend {sel}')
