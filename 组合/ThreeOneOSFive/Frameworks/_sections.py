import struct, sys

def sections(path):
    data = open(path, 'rb').read()
    ncmds = struct.unpack('<I', data[16:20])[0]
    off = 32
    for i in range(ncmds):
        cmd, cmdsize = struct.unpack('<II', data[off:off+8])
        if cmd == 0x19:
            segname = data[off+8:off+24].rstrip(b'\0').decode()
            nsects = struct.unpack('<I', data[off+64:off+68])[0]
            so = off + 72
            for j in range(nsects):
                name = data[so:so+16].rstrip(b'\0').decode()
                addr = struct.unpack('<Q', data[so+32:so+40])[0]
                size = struct.unpack('<Q', data[so+40:so+48])[0]
                print(f'{segname},{name} addr=0x{addr:x} size=0x{size:x}')
                so += 80
        off += cmdsize

sections(sys.argv[1])
