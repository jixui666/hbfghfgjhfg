import struct, sys

def symtab(path):
    data = open(path, 'rb').read()
    ncmds = struct.unpack('<I', data[16:20])[0]
    off = 32
    symoff = None; nsyms = 0; stroff = None; strsize = 0
    for i in range(ncmds):
        cmd, cmdsize = struct.unpack('<II', data[off:off+8])
        if cmd == 0x2:  # LC_SYMTAB
            symoff, nsyms, stroff, strsize = struct.unpack('<IIII', data[off+8:off+24])
        off += cmdsize
    if symoff is None:
        print(path, '-> NO LC_SYMTAB (stripped)')
        return
    strs = data[stroff:stroff+strsize]
    names = []
    for i in range(nsyms):
        e = data[symoff+i*16 : symoff+i*16+16]
        n_strx, n_type, n_sect, n_desc, n_value = struct.unpack('<IBBHQ', e)
        if n_strx and n_strx < len(strs):
            end = strs.find(b'\0', n_strx)
            name = strs[n_strx:end].decode('utf-8', 'replace')
            if name and not name.startswith('_'):
                names.append(name)
    print(path, f'symbols: {nsyms}, named: {len(names)}')
    for n in sorted(set(names))[:400]:
        print('  ', n)

symtab(sys.argv[1])
