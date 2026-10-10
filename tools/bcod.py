#!/usr/bin/env python3
"""
bcod.py - parse a KEF LSX (BridgeCo JukeBlox) .fw firmware image.

The .fw is a BridgeCo "bCoD" container: an outer header, a CRC-32 over the body,
and a segment table. Integrity is CRC-32 only (the image is NOT signed).

Usage:
    python3 bcod.py info   KEF_LSX_V520_S270_D100.fw
    python3 bcod.py extract KEF_LSX_V520_S270_D100.fw out_dir/

Get the firmware (public KEF CDN, undocumented):
    curl -s https://assets.kef.com/pm/pm_firmware/lsx/LSXUpdate.json
    # -> {"version":520,"url":".../KEF_LSX_V520_S270_D100.fw", ...}

Read-only: this only parses/extracts. It does not modify firmware.
"""
import sys, os, struct, zlib

HDR_CRC_OFF   = 0x10          # uint32 LE: CRC-32 of file[0x20:]
MAGIC_OFF     = 0x20          # b"bCoD"
BUILD_OFF     = 0x28          # ASCII build timestamp
SEG_TABLE_OFF = 0x48          # segment entries, stride 0x20
SEG_STRIDE    = 0x20
SEG_PAYLOAD_SKIP = 0x20       # each segment's payload starts at off + 0x20

def u32(d, o): return struct.unpack_from('<I', d, o)[0]

def segments(d):
    """Yield (index, entry_off, payload_off, size, crc_field_off, crc)."""
    for i, e in enumerate(range(SEG_TABLE_OFF, SEG_TABLE_OFF + 4 * SEG_STRIDE, SEG_STRIDE)):
        _t, _h, off, _flash, size, crc, _x, _z = struct.unpack_from('<8I', d, e)
        # Real segments have a non-zero size and a non-zero CRC. The table can contain
        # empty/padding entries (size or crc == 0) which are not segments.
        if off == 0 or size == 0 or crc == 0:
            continue
        yield i, e, off + SEG_PAYLOAD_SKIP, size, e + 20, crc

def info(path):
    d = open(path, 'rb').read()
    assert d[MAGIC_OFF:MAGIC_OFF+4] == b'bCoD', "not a bCoD image"
    print("file           : %s (0x%x bytes)" % (path, len(d)))
    print("build          : %s" % d[BUILD_OFF:BUILD_OFF+16].decode('ascii', 'replace').strip())
    body_crc = zlib.crc32(d[0x20:]) & 0xffffffff
    print("container CRC  : stored=0x%08x computed=0x%08x %s"
          % (u32(d, HDR_CRC_OFF), body_crc, "OK" if u32(d, HDR_CRC_OFF) == body_crc else "MISMATCH"))
    for i, _e, poff, size, _cf, crc in segments(d):
        calc = zlib.crc32(d[poff:poff+size]) & 0xffffffff
        print("seg%d           : payload@0x%06x size=0x%x crc=0x%08x %s"
              % (i, poff, size, crc, "OK" if calc == crc else "MISMATCH"))

def extract(path, outdir):
    d = open(path, 'rb').read()
    os.makedirs(outdir, exist_ok=True)
    for i, _e, poff, size, _cf, _crc in segments(d):
        fn = os.path.join(outdir, "seg%d.bin" % i)
        open(fn, 'wb').write(d[poff:poff+size])
        print("wrote %s (0x%x bytes)" % (fn, size))

if __name__ == '__main__':
    if len(sys.argv) >= 3 and sys.argv[1] == 'info':
        info(sys.argv[2])
    elif len(sys.argv) >= 4 and sys.argv[1] == 'extract':
        extract(sys.argv[2], sys.argv[3])
    else:
        print(__doc__)
        sys.exit(1)
