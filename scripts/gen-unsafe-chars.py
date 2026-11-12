#!/usr/bin/env python3
"""Generates crates/wire/src/text.rs's range table.

Usage: python3 -I scripts/gen-unsafe-chars.py DerivedCoreProperties.txt > table.rs
Needs Python's unicodedata at Unicode 16.0.0 and the 16.0.0 file
https://www.unicode.org/Public/16.0.0/ucd/DerivedCoreProperties.txt
Unsafe = categories Cc Cf Co Cs Zl Zp, plus Default_Ignorable_Code_Point,
minus TAB.
"""
import sys, unicodedata
assert unicodedata.unidata_version == "16.0.0", unicodedata.unidata_version
di = set()
for line in open(sys.argv[1], encoding="utf-8"):
    line = line.split("#")[0].strip()
    if not line:
        continue
    rng, prop = [x.strip() for x in line.split(";")[:2]]
    if prop != "Default_Ignorable_Code_Point":
        continue
    a, _, b = rng.partition("..")
    for c in range(int(a, 16), int(b or a, 16) + 1):
        di.add(c)
cats = {"Cc", "Cf", "Co", "Cs", "Zl", "Zp"}
out, start, prev = [], None, None
for c in range(0x110000):
    bad = (unicodedata.category(chr(c)) in cats or c in di) and c != 9
    if bad:
        if start is None:
            start = c
        prev = c
    elif start is not None:
        out.append((start, prev)); start = None
if start is not None:
    out.append((start, prev))
print("const UNSAFE: &[(u32, u32)] = &[")
for a, b in out:
    print(f"    (0x{a:X}, 0x{b:X}),")
print("];")
