import struct, sys, re
from capstone import *
from capstone.arm64 import *

path = sys.argv[1]
data = open(path, 'rb').read()
ncmds = struct.unpack('<I', data[16:20])[0]
off = 32
segs = {}
secs = {}
for i in range(ncmds):
    cmd, cmdsize = struct.unpack('<II', data[off:off+8])
    if cmd == 0x19:
        segname = data[off+8:off+24].rstrip(b'\0').decode()
        vmaddr, vmsize = struct.unpack('<QQ', data[off+24:off+40])
        foff = struct.unpack('<Q', data[40+off:48+48])[0] if False else struct.unpack('<Q', data[40+off:48+off])[0]
        segs[segname] = (vmaddr, vmsize, foff)
        nsects = struct.unpack('<I', data[off+64:off+68])[0]
        so = off + 72
        for j in range(nsects):
            name = data[so:so+16].rstrip(b'\0').decode()
            addr = struct.unpack('<Q', data[so+32:so+40])[0]
            size = struct.unpack('<Q', data[so+40:so+48])[0]
            secs[(segname, name)] = (addr, size)
            so += 80
    off += cmdsize

def v2f(addr):
    for name, (vmaddr, vmsize, foff) in segs.items():
        if vmaddr <= addr < vmaddr + vmsize:
            return foff + (addr - vmaddr)
    return None

text_addr, text_size = secs[('__TEXT', '__text')]
data_addr, data_size = secs[('__DATA', '__data')]
code = data[v2f(text_addr): v2f(text_addr)+text_size]
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

shadow = bytearray(data[v2f(data_addr): v2f(data_addr)+data_size])
insns = list(md.disasm(code, text_addr))
by_addr = {i.address: i for i in insns}

WRITES = set()

def resolve(reg, ins, limit=20):
    a = ins.address
    page = None
    add_offs = None
    steps = 0
    while steps < limit:
        a -= 4
        steps += 1
        if a not in by_addr:
            return None
        p = by_addr[a]
        if p.mnemonic == 'adrp' and p.operands[0].reg == reg:
            page = p.operands[1].imm
            if add_offs is not None:
                return page + add_offs
            continue
        if p.mnemonic == 'add' and len(p.operands) == 3 and \
           p.operands[0].reg == reg and p.operands[1].reg == reg and p.operands[2].type == ARM64_OP_IMM:
            add_offs = p.operands[2].imm
            continue
        # any other instruction that writes reg invalidates the base
        if p.operands and p.operands[0].type == ARM64_OP_REG and p.operands[0].reg == reg:
            return None
    return None

# We'll do multiple passes: simple snippets where value = membyte ^ imm
def apply_snippet(ins):
    # pattern at ins: strb wB, [xD, #j]
    if ins.mnemonic != 'strb':
        return False
    dst = ins.operands[1]
    if dst.type != ARM64_OP_MEM:
        return False
    db = resolve(dst.mem.base, ins)
    if db is None:
        return False
    val_reg = ins.operands[0].reg
    # walk back to find eor wB, wS, wK or eor wB, wK, wS within 12 insns
    a = ins.address
    for _ in range(12):
        a -= 4
        if a not in by_addr:
            return False
        p = by_addr[a]
        if p.mnemonic == 'eor' and len(p.operands) == 3 and p.operands[0].reg == val_reg:
            s1, s2 = p.operands[1].reg, p.operands[2].reg
            # one side = mem byte, other = imm
            mem_side = imm_side = None
            # look back from eor for ldrb into s1
            b = a
            memv = None
            for _ in range(10):
                b -= 4
                if b not in by_addr:
                    break
                q = by_addr[b]
                if q.mnemonic in ('ldrb', 'ldrsb') and q.operands[0].reg in (s1, s2):
                    src = q.operands[1]
                    if src.type == ARM64_OP_MEM:
                        sb = resolve(src.mem.base, q)
                        if sb is not None:
                            memv = shadow[sb + src.mem.disp - data_addr] if data_addr <= sb + src.mem.disp < data_addr + data_size else None
                            mem_reg = q.operands[0].reg
                if q.mnemonic in ('mov', 'movz') and q.operands[0].reg in (s1, s2) and q.operands[1].type == ARM64_OP_IMM:
                    imm_reg = q.operands[0].reg
                    imm_val = q.operands[1].imm & 0xFF
                    if memv is not None and imm_reg != mem_reg:
                        dst_addr = db + dst.mem.disp
                        if data_addr <= dst_addr < data_addr + data_size:
                            shadow[dst_addr - data_addr] = (memv ^ imm_val) & 0xFF
                            return True
    return False

n_applied = 0
for ins in insns:
    if apply_snippet(ins):
        n_applied += 1

print('applied strb ops:', n_applied)
runs = []
for m in re.finditer(rb'[\x20-\x7e]{4,}', bytes(shadow)):
    runs.append((data_addr + m.start(), m.group().decode()))
for addr, s in runs:
    print(f'0x{addr:x}: {s}')
