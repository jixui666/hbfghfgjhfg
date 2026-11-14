import struct, sys
from capstone import *

path = sys.argv[1]
data = open(path, 'rb').read()
ncmds = struct.unpack('<I', data[16:20])[0]
off = 32
segs = {}
fixups_off = fixups_size = 0
for i in range(ncmds):
    cmd, cmdsize = struct.unpack('<II', data[off:off+8])
    if cmd == 0x19:
        segname = data[off+8:off+24].rstrip(b'\0').decode()
        vmaddr, vmsize = struct.unpack('<QQ', data[off+24:off+40])
        foff = struct.unpack('<Q', data[off+40:off+48])[0]
        segs[segname] = (vmaddr, vmsize, foff)
    if cmd == 0x80000034:  # LC_DYLD_CHAINED_FIXUPS
        fixups_off, fixups_size = struct.unpack('<II', data[off+8:off+16])
    off += cmdsize

def v2f(addr):
    for name, (vmaddr, vmsize, foff) in segs.items():
        if vmaddr <= addr < vmaddr + vmsize:
            return foff + (addr - vmaddr)
    return None

# ---- parse chained fixups imports ----
hdr = struct.unpack('<7I', data[fixups_off:fixups_off+28])
starts_offset = hdr[1]
imports_offset = hdr[2]
symbols_offset = hdr[3]
imports_count = hdr[4]
imports_format = hdr[5]
print('imports_format', imports_format, 'count', imports_count)
libs = []
if imports_format in (1, 2):  # DYLD_CHAINED_IMPORT / IMPORT_ADDEND
    p = fixups_off + imports_offset
    es = 12 if imports_format == 1 else 16
    for k in range(imports_count):
        lib_ordinal, weak, name_off = struct.unpack('<iii', data[p:p+12])
        end = data.find(b'\0', fixups_off + name_off)
        name = data[fixups_off+name_off:end].decode()
        libs.append((lib_ordinal, weak, name))
        p += es

# got slots: parse dyld_chained_starts_in_segment to find __DATA_CONST page starts
# simpler: scan got region 0x12c000.. for entries with bind bit set, decode ordinal
got_start = 0x12c000
got_end = 0x12c470
bind_map = {}
for a in range(got_start, got_end, 8):
    ptr = struct.unpack('<Q', data[a:a+8])[0]
    if ptr >> 63:
        ordinal = ptr & 0xFFFFFF
        bind_map[a] = libs[ordinal][2] if ordinal < len(libs) else f'?{ordinal}'

print('bind_map entries:', len(bind_map))
for a in sorted(bind_map):
    print(hex(a), bind_map[a])
