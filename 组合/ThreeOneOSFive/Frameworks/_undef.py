import struct, sys

def undef_syms(path):
    data = open(path, 'rb').read()
    ncmds = struct.unpack('<I', data[16:20])[0]
    off = 32
    symoff=None; nsyms=0; stroff=None; strsize=0
    inds=None; extrel=None; extdef=None; ilocal=None; nind=0
    dysym = None
    for i in range(ncmds):
        cmd, cmdsize = struct.unpack('<II', data[off:off+8])
        if cmd == 0x2:
            symoff, nsyms, stroff, strsize = struct.unpack('<IIII', data[off+8:off+24])
        if cmd == 0xB:  # LC_DYSYMTAB
            dysym = data[off:off+cmdsize]
            ilocal, nloc, iext, next_, iundef, nundef, toco, ntoc, modtaboff, nmodtab, extrefsymoff, nextrefsyms, indirectsymoff, nindirect, extreloff, nextrel, locreloff, nlocrel = struct.unpack('<18I', dysym[8:80])
        off += cmdsize
    if symoff is None: return []
    strs = data[stroff:stroff+strsize]
    out=[]
    for i in range(iundef, iundef+nundef):
        e = data[symoff+i*16 : symoff+i*16+16]
        n_strx, n_type, n_sect, n_desc, n_value = struct.unpack('<IBBHQ', e)
        if n_strx and n_strx < len(strs):
            end = strs.find(b'\0', n_strx)
            out.append(strs[n_strx:end].decode('utf-8','replace'))
    return out

p = sys.argv[1]
syms = undef_syms(p)
print(p, 'undefined:', len(syms))
for s in sorted(set(syms)):
    print('  ', s)
