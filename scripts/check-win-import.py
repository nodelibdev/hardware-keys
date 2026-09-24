#!/usr/bin/env python3
"""Fail if a Windows PE file imports the Visual C++ runtime or the UCRT api-sets.

Usage: python scripts/check-win-imports.py <file.node> [more files...]
Exit code 0 when clean, 1 when a forbidden import is found or the file is not PE32+.
"""
import struct
import sys

FORBIDDEN = ("vcruntime", "msvcp", "api-ms-win-crt")


def imports(path):
    d = open(path, "rb").read()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    if d[pe:pe + 4] != b"PE\0\0":
        raise ValueError("not a PE file")
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    optsz = struct.unpack_from("<H", d, pe + 20)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", d, opt)[0]
    dd = opt + (112 if magic == 0x20B else 96)          # data directories
    imp_rva = struct.unpack_from("<I", d, dd + 8)[0]     # index 1: import table
    dimp_rva = struct.unpack_from("<I", d, dd + 13 * 8)[0]  # index 13: delay import
    secs = []
    so = opt + optsz
    for i in range(nsec):
        s = so + i * 40
        vsz, va, rsz, rp = struct.unpack_from("<IIII", d, s + 8)
        secs.append((va, max(vsz, rsz), rp))

    def r2o(rva):
        for va, sz, rp in secs:
            if va <= rva < va + sz:
                return rva - va + rp
        raise ValueError("rva outside sections: %#x" % rva)

    def cstr(off):
        return d[off:d.index(b"\0", off)].decode(errors="replace")

    names = []
    if imp_rva:
        o = r2o(imp_rva)
        while True:
            name_rva = struct.unpack_from("<I", d, o + 12)[0]
            if not name_rva:
                break
            names.append(cstr(r2o(name_rva)))
            o += 20
    if dimp_rva:
        o = r2o(dimp_rva)
        while True:
            name_rva = struct.unpack_from("<I", d, o + 4)[0]
            if not name_rva:
                break
            names.append(cstr(r2o(name_rva)) + " (delay-load)")
            o += 32
    return names


def main(paths):
    rc = 0
    for p in paths:
        names = imports(p)
        print("%s imports:" % p)
        for n in names:
            print("   ", n)
        bad = [n for n in names if n.lower().startswith(FORBIDDEN)]
        if bad:
            print("FAIL: depends on the VC++ runtime / UCRT:", ", ".join(bad))
            rc = 1
        else:
            print("OK")
    return rc


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1:]))