import struct, sys, re

def iter_sections(path):
    data = open(path, 'rb').read()
    magic = struct.unpack('<I', data[:4])[0]
    ncmds = struct.unpack('<I', data[16:20])[0]
    off = 32
    for i in range(ncmds):
        cmd, cmdsize = struct.unpack('<II', data[off:off+8])
        if cmd == 0x19:  # LC_SEGMENT_64
            segname = data[off+8:off+24].rstrip(b'\0').decode()
            nsects = struct.unpack('<I', data[off+64:off+68])[0]
            so = off + 72
            for j in range(nsects):
                sectname = data[so:so+16].rstrip(b'\0').decode()
                foff = struct.unpack('<I', data[so+48:so+52])[0]
                size2 = struct.unpack('<Q', data[so+32:so+40])[0]
                if foff + size2 <= len(data):
                    yield segname, sectname, data[foff:foff+size2]
                so += 80
        off += cmdsize

def extract(path, pat):
    print('='*100)
    print(path)
    hits = []
    for seg, sec, blob in iter_sections(path):
        # ASCII runs
        for m in re.finditer(rb'[\x20-\x7e]{4,}', blob):
            s = m.group().decode('ascii', 'replace')
            if re.search(pat, s):
                hits.append(f'[{seg},{sec}] {s}')
        # UTF-16LE runs
        for m in re.finditer(rb'(?:[\x20-\x7e\x00-\xff]\x00){4,}', blob):
            try:
                s = m.group().decode('utf-16-le', 'replace')
            except Exception:
                continue
            if re.search(pat, s):
                hits.append(f'[{seg},{sec},u16] {s}')
    seen = set(); out = []
    for h in hits:
        if h not in seen:
            seen.add(h); out.append(h)
    for h in out:
        print(h)

if __name__ == '__main__':
    extract(sys.argv[1], sys.argv[2])
