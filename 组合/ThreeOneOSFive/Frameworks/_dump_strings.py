import struct, sys, re

def load_commands(path):
    data = open(path, 'rb').read()
    magic = struct.unpack('<I', data[:4])[0]
    assert magic in (0xFEEDFACF, 0xFEEDFACE, 0xFEEDFACF + 0x100000000), hex(magic)
    # 64-bit: header is 32 bytes
    ncmds = struct.unpack('<I', data[16:20])[0]
    off = 32
    cmds = []
    for i in range(ncmds):
        cmd, cmdsize = struct.unpack('<II', data[off:off+8])
        cmds.append((cmd, cmdsize, off))
        off += cmdsize
    return data, cmds

def cstrings(path):
    data, cmds = load_commands(path)
    out = []
    for cmd, size, off in cmds:
        if cmd == 0x19:  # LC_SEGMENT_64
            segname = data[off+8:off+24].rstrip(b'\0').decode()
            nsects = struct.unpack('<I', data[off+64:off+68])[0]
            so = off + 72
            for j in range(nsects):
                sectname = data[so:so+16].rstrip(b'\0').decode()
                addr, size2 = struct.unpack('<QQ', data[so+32:so+48])
                foff = struct.unpack('<I', data[so+48:so+52])[0]
                if segname == '__TEXT' and sectname == '__cstring':
                    blob = data[foff:foff+size2]
                    for m in re.finditer(rb'[^\x00-\x1f]{4,}', blob):
                        out.append((m.start()+foff, m.group().decode('utf-8', errors='replace')))
                so += 80
    return out

if __name__ == '__main__':
    for p in sys.argv[1:]:
        print('='*100)
        print(p)
        for off, s in cstrings(p):
            print(f'{off:08x}: {s}')
