import struct, sys

def parse_objc(path):
    data = open(path, 'rb').read()
    ncmds = struct.unpack('<I', data[16:20])[0]
    off = 32
    segs = {}
    secs = {}
    for i in range(ncmds):
        cmd, cmdsize = struct.unpack('<II', data[off:off+8])
        if cmd == 0x19:
            segname = data[off+8:off+24].rstrip(b'\0').decode()
            vmaddr = struct.unpack('<Q', data[off+24:off+32])[0]
            vmsize = struct.unpack('<Q', data[off+32:off+40])[0]
            foff = struct.unpack('<Q', data[off+40:off+48])[0]
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
    MASK = 0x7FFFFFFFFFF
    def fix(p): return p & MASK
    def cstr_at(addr):
        f = v2f(addr)
        if f is None: return None
        end = data.find(b'\0', f)
        return data[f:end].decode('utf-8','replace') if end > 0 else None
    def read_at(addr, n):
        f = v2f(addr)
        return data[f:f+n] if f is not None else None

    def dump_methods(mlistptr, indent='    '):
        ml = read_at(mlistptr, 8)
        if not ml: return
        entsize = struct.unpack('<I', ml[0:4])[0]
        count = struct.unpack('<I', ml[4:8])[0]
        if count > 500 or entsize != 24: return
        base = mlistptr + 8
        for m in range(count):
            me = read_at(base + m*entsize, entsize)
            if not me: break
            sname = cstr_at(fix(struct.unpack('<Q', me[0:8])[0]))
            print(f'{indent}-{sname}')

    for (seg, name), (addr, size) in sorted(secs.items()):
        if name == '__objc_classlist':
            f = v2f(addr)
            if f is None: continue
            n = size // 8
            for k in range(n):
                clsptr = fix(struct.unpack('<Q', data[f+k*8:f+k*8+8])[0])
                d = read_at(clsptr, 40)
                if not d: continue
                dataptr = fix(struct.unpack('<Q', d[32:40])[0])
                cd = read_at(dataptr, 56)
                if not cd: continue
                cname = cstr_at(fix(struct.unpack('<Q', cd[24:32])[0]))
                print(f'class {cname}  (ro=0x{dataptr:x})')
                ml = fix(struct.unpack('<Q', cd[32:40])[0])
                if ml: dump_methods(ml)
                protos = fix(struct.unpack('<Q', cd[40:48])[0])
                if protos:
                    pl = read_at(protos, 8)
                    if pl:
                        count = struct.unpack('<Q', pl[0:8])[0]
                        if 0 < count < 100:
                            for p in range(count):
                                pp = fix(struct.unpack('<Q', read_at(protos+8+p*8, 8))[0])
                                pd = read_at(pp, 16)
                                if pd:
                                    pn = cstr_at(fix(struct.unpack('<Q', pd[8:16])[0]))
                                    print(f'    <{pn}>')
        if name == '__objc_catlist':
            f = v2f(addr)
            if f is None: continue
            n = size // 8
            for k in range(n):
                cptr = fix(struct.unpack('<Q', data[f+k*8:f+k*8+8])[0])
                cd = read_at(cptr, 56)
                if not cd: continue
                clsname = cstr_at(fix(struct.unpack('<Q', cd[0:8])[0]))
                catname = cstr_at(fix(struct.unpack('<Q', cd[8:16])[0]))
                print(f'category {clsname}({catname})')
                for idx in (0,1):
                    mlistptr = fix(struct.unpack('<Q', cd[32+idx*8:40+idx*8])[0])
                    if mlistptr: dump_methods(mlistptr)

parse_objc(sys.argv[1])
