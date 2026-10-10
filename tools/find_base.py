#!/usr/bin/env python3
"""
find_base.py - estimate the run (link) base of seg0 by pointer/string consistency.

seg0 is scatter-loaded into DDR, so the flat file does not sit at its run address.
This scores candidate load bases by how many 32-bit LE values in the image point at
the start of a C string when interpreted as (value - base). The best single base is
a useful anchor for a Ghidra import, though the image has multiple relocated regions
(see README - the full region map is not recoverable from the .fw alone).

Usage:
    python3 find_base.py seg0.bin
"""
import sys, re, struct, array

def main(path):
    d = open(path, 'rb').read()
    N = len(d)
    starts = set(m.start(1) for m in re.finditer(rb'(?:\x00|\A)([\x20-\x7e]{4,})\x00', d))
    allvals = array.array('I'); allvals.frombytes(d[:(N // 4) * 4])
    # Pre-filter to plausible pointer values (DDR/XIP ranges) so the inner loop is small.
    vals = [v for v in allvals if (0x40000000 <= v < 0x41000000) or (0 < v < 0x02000000)]

    def score(base):
        return sum(1 for v in vals if 0 <= v - base < N and (v - base) in starts)

    def best_of(candidates):
        return max(((score(b), b) for b in candidates), key=lambda x: x[0])

    # Hierarchical sweep: coarse (0x10000) -> refine (0x400) -> refine (4).
    c = best_of(list(range(0x00000000, 0x02000000, 0x10000)) +
                list(range(0x40000000, 0x41000000, 0x10000)))
    r = best_of(range(c[1] - 0x10000, c[1] + 0x10000, 0x400))
    f = best_of(range(r[1] - 0x400, r[1] + 0x400, 4))
    print("coarse 0x%08x (%d)  ->  refine 0x%08x (%d)  ->  base 0x%08x (%d hits)"
          % (c[1], c[0], r[1], r[0], f[1], f[0]))
    print("\nUse 0x%08x as the Ghidra BinaryLoader base address for seg0." % f[1])

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(__doc__); sys.exit(1)
    main(sys.argv[1])
