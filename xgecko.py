#!/usr/bin/env python3
"""Unpack and repack XGecu programmer firmware update files.

    xgecko.py -u UpdateT76.Dat -o fw.bin
    xgecko.py -p my_fw.bin -k UpdateT76.Dat -o my_update.Dat

File magic identifies firmware type:

    T76           UpdateT76.Dat   0xF076_xxxx
    T48           UpdateT48.dat   0xF048_xxxx
    T56           updateT56.dat   0x5600_xxxx
    TL866II Plus  updateII.dat    0xF8CC_xxxx
"""
import argparse, hashlib, os, struct, sys, zlib
from collections import namedtuple

VERBOSE = False
def log(msg, tag="*"):
    """Verbose output: [*] progress, [+] check passed, [!] notable."""
    if VERBOSE:
        print(f"[{tag}] {msg}", file=sys.stderr)

def nblocks(n): return f"{n} block{'s' * (n != 1)}"
def base(path): return os.path.basename(path)

def read(path):
    try:
        return open(path, "rb").read()
    except OSError as e:
        sys.exit(f"{path}: {e.strerror}")

def write(path, data):
    try:
        open(path, "wb").write(data)
    except OSError as e:
        sys.exit(f"{path}: {e.strerror}")

def crc32(data, init):
    """Reflected CRC-32 (zlib polynomial), register starting at init, no final XOR."""
    return zlib.crc32(data, init ^ 0xFFFFFFFF) ^ 0xFFFFFFFF

def xor(a, b):
    return (int.from_bytes(a, "little") ^ int.from_bytes(b, "little")).to_bytes(len(a), "little")

def bits(x):
    """Indexes of the set bits of x, high to low."""
    while x:
        i = x.bit_length() - 1
        x ^= 1 << i
        yield i

ROL3 = bytes(((x << 3) | (x >> 5)) & 0xFF for x in range(256))
ROR3 = bytes(((x >> 3) | (x << 5)) & 0xFF for x in range(256))

class Bad(Exception):
    """A block fails the file's own checks with the key tried."""

File = namedtuple("File", "name version blocks extra")

# --- GF(2) linear algebra ----------------------------------------------------

class GF2:
    """Gaussian elimination over GF(2). A row (mask, rhs) says: the XOR of the
    unknowns in mask is rhs. rhs is a bit, or a byte (8 bit systems at once)."""
    def __init__(self):
        self.rows = {}                         # pivot (top bit of mask) -> (mask, rhs)

    def add(self, mask, rhs):
        """-> 1 new information, 0 redundant, -1 contradicts the rows so far."""
        while mask:
            p = mask.bit_length() - 1
            r = self.rows.get(p)
            if r is None:
                self.rows[p] = (mask, rhs)
                return 1
            mask, rhs = mask ^ r[0], rhs ^ r[1]
        return -1 if rhs else 0

    def solve(self, n, unknowns=None):
        """-> (x, null). x[i] is unknown i, with every free unknown 0; null holds
        one vector per free unknown, and together they span every solution.
        unknowns: mask of the unknowns among 0..n-1 (default: all)."""
        rows, pivots = {}, 0
        for p in sorted(self.rows):            # reduce: a pivot row keeps only free unknowns
            m, v = self.rows[p]
            for q in bits(m & pivots):
                m, v = m ^ rows[q][0], v ^ rows[q][1]
            rows[p], pivots = (m, v), pivots | 1 << p
        x = [0] * n
        free = ((1 << n) - 1 if unknowns is None else unknowns) & ~pivots
        null = {f: 1 << f for f in bits(free)}
        for p, (m, v) in rows.items():
            x[p] = v
            for f in bits(m ^ 1 << p):
                null[f] |= 1 << p
        return x, list(null.values())

def parity(x): return x.bit_count() & 1

def combine(vectors, sel):
    """XOR of vectors[i] for every bit i of sel."""
    e = 0
    for i in bits(sel):
        e ^= vectors[i]
    return e

def solve_key(fmt, files, target):
    """Solve the key from files (vendor files first) for unpacking target.
    -> key bytes; exits if target needs a key byte the files do not fix."""
    # 1. known plaintext, byte-wise over key slots
    S, contradict, rejected = GF2(), 0, 0
    for pass_ in range(fmt.PASSES):
        det = None
        if pass_:                              # TL866: erased runs are found with the pass-0 key
            x, null = S.solve(fmt.NSLOT)
            free = 0
            for v in null:
                free |= v
            det = {t: x[t] for t in range(fmt.NSLOT) if not free >> t & 1}
        for f in files:
            for blk, p, v, assumed in fmt.known(f, det, pass_):
                mask = 0
                for t in fmt.slots(blk, p):
                    mask ^= 1 << t
                if S.add(mask, fmt.ks_from_plain(blk, p, v)) < 0:
                    rejected += assumed
                    contradict += not assumed
    if contradict:
        sys.exit(f"{contradict} known plaintext bytes contradict each other; a file is "
                 f"damaged or has a layout this tool does not know")
    if rejected:
        log(f"{rejected} assumed plaintext bytes contradict the rest; not used", "!")
    x, null = S.solve(fmt.NSLOT)
    log(f"known plaintext fixes {fmt.NSLOT - len(null)} of {fmt.NSLOT} key slots")
    key = int.from_bytes(bytes(x), "little")
    # the free key bits, as directions in key-bit space
    E = []
    for v in null:
        for b in range(8):
            E.append(sum(1 << (8 * t + b) for t in bits(v)))

    # 2. block CRCs, bit-wise over the bits step 1 left free. A free direction
    #    that is one key bit stays that bit; the others (T56) get unknowns above
    #    the key bits, and a row gets their coefficients by projection.
    if fmt.CRC and E:
        unit = 0
        for e in E:
            if not e & (e - 1):
                unit |= e
        other, top = [e for e in E if e & (e - 1)], 8 * fmt.NSLOT
        S2, n, contradict = GF2(), 0, 0
        for f in files:
            one = {}
            for b in f.blocks:                 # CRC rows depend on the start only: one block each
                one.setdefault(fmt.sel(b), b)
            for s, blk in one.items():
                for m, rhs in zip(fmt.crc_rows(s), fmt.crc_target(blk)):
                    coeff = m & unit
                    for i, e in enumerate(other):
                        coeff |= parity(m & e) << (top + i)
                    contradict += S2.add(coeff, rhs ^ parity(m & key)) < 0
                    n += 1
                if len(S2.rows) == len(E):
                    break
            if len(S2.rows) == len(E):
                break
        if contradict:
            sys.exit(f"{contradict} block CRC equations contradict each other: a block is "
                     "damaged (no key makes its CRC match), or the files do not share one key")
        y, null2 = S2.solve(top + len(other), unit | ((1 << len(other)) - 1) << top)
        log(f"block CRCs ({n} equations) fix {len(E) - len(null2)} of {len(E)} free key bits")
        lift = lambda v: (v & unit) ^ combine(other, v >> top)
        key ^= lift(sum(b << i for i, b in enumerate(y)))
        E = [lift(v) for v in null2]

    # 3. what is still free: harmless for this file, small enough to search, or an error
    groups = sorted(fmt.groups(target))
    def effect(e):
        """-> the keystream change e causes, one byte per slot group target uses."""
        out = 0
        for i, g in enumerate(groups):
            d = 0
            for t in g:
                d ^= e >> (8 * t) & 0xFF
            out |= d << (8 * i)
        return out
    eff, H = GF2(), []
    for e in E:
        if eff.add(effect(e), 0) > 0:          # a new direction that changes target's bytes
            H.append(e)
    if E:
        log(f"{len(E)} key bits still free; {len(H)} of them matter for {base(target.name)}")
    if len(H) > 12:
        slots = sorted({i // 8 for e in H for i in bits(e)})
        sys.exit(f"{base(target.name)}: key slots {fmt.slot_list(slots)} are not fixed by the "
                 f"files given; add -k {fmt.FILE} (a vendor file)")
    good = []
    for c in range(1 << len(H)):
        k = (key ^ combine(H, c)).to_bytes(fmt.NSLOT, "little")
        try:
            fmt.unpack_blocks(k, target)
            good.append(k)
        except Bad:
            pass
    if len(good) != 1:
        sys.exit(f"{base(target.name)}: {len(good)} of {1 << len(H)} candidate keys pass its "
                 f"checks; add -k {fmt.FILE} (a vendor file)")
    if H:
        log(f"searched the {1 << len(H)} candidate keys: exactly one passes {fmt.CHECKS}", "+")
    log("key fixed for every byte the file uses", "+")
    return good[0]

# --- T76, T48, T56: one container family ---------------------------------------

Block = namedtuple("Block", "W F H C")         # H: block header bytes 6..15

class TFamily:
    """Container and cipher shared by the T76, T48 and T56.

    header, 16 bytes (all integers little-endian):
        u32  MAGIC << 16 | version    (version 0x0113 = 1.19)
        u32  file CRC                 crc32(all blocks, init 0xFFFFFFFF)
        u32  0
        u32  n                        number of blocks
    n blocks of 16 + DLEN bytes:
        u32  W                        crc32(P, CRC_INIT)
        u16  F                        cipher seed
        10   H                        model-specific
        DLEN C                        encrypted P

    P = u32 address marker || payload. Cipher, for p = 0 .. DLEN-1:
        s    = ((F & 0xFF) + (F >> 8)) % 256        the block's start offset
        G    = F & 0xFF if p % 4 == 0, F >> 8 if p % 4 == 1, else 0
        C[p] = ror3(P[p] ^ G) ^ ks[p]
    where ks[p] is the XOR of one slot from each key table: (s + p) % size for
    a table that follows the start, p % size for one that does not.
    """
    PASSES, CRC = 1, True
    CHECKS = "the address markers and CRCs"

    def __init__(self):
        self.BLK = 16 + self.DLEN
        self.NSLOT = sum(size for size, _ in self.TABLES)
        self._rows, self._win = {}, None

    def ver(self, v): return f"{v >> 8}.{v & 0xFF:02d}"
    def slot_list(self, slots): return f"{slots[:12]}{' ...' if len(slots) > 12 else ''}"

    @staticmethod
    def start(f): return ((f & 0xFF) + (f >> 8)) & 0xFF
    def sel(self, blk): return self.start(blk.F)

    def slots(self, blk, p):
        s, out, off = self.start(blk.F), [], 0
        for size, moves in self.TABLES:
            out.append(off + ((s if moves else 0) + p) % size)
            off += size
        return out

    def groups(self, f):
        """Every tuple of slots some keystream byte of f is made from."""
        return {tuple(self.slots(b, p)) for b in {self.sel(b): b for b in f.blocks}.values()
                for p in range(self.DLEN)}

    def gpat(self, f): return bytes((f & 0xFF, f >> 8, 0, 0)) * (self.DLEN // 4)

    def stream(self, K, s, cache):
        if s not in cache:
            ks, off = bytearray(self.DLEN), 0
            for size, moves in self.TABLES:
                t = K[off:off + size]
                r = (s if moves else 0) % size
                t = (t[r:] + t[:r]) * (-(-(self.DLEN + size) // size))
                ks = xor(ks, t[:self.DLEN])
                off += size
            cache[s] = bytes(ks)
        return cache[s]

    def decrypt(self, K, blk, cache):
        ks = self.stream(K, self.start(blk.F), cache)
        return xor(xor(blk.C, ks).translate(ROL3), self.gpat(blk.F))

    def encrypt(self, K, P, f, cache):
        return xor(xor(P, self.gpat(f)).translate(ROR3), self.stream(K, self.start(f), cache))

    def ks_from_plain(self, blk, p, v):
        g = (blk.F & 0xFF, blk.F >> 8, 0, 0)[p % 4]
        return blk.C[p] ^ ROR3[v ^ g]

    # block CRCs as equations in the key bits
    def crc_target(self, blk):
        """-> 32 bits: W ^ crc(P decrypted with an all-zero key)."""
        A = xor(blk.C.translate(ROL3), self.gpat(blk.F))
        t = blk.W ^ crc32(A, self.CRC_INIT)
        return [t >> r & 1 for r in range(32)]

    def crc_rows(self, s):
        """-> 32 key-bit masks: CRC bit r flips with the parity of the key bits in row r."""
        if self._win is None:                  # over window bits 8p + b (bit b of ks[p])
            win = [0] * 32
            for p in range(self.DLEN):
                for b in range(8):             # ks bit b is P bit b + 3 (rol3)
                    c = crc32(bytes(p) + bytes((1 << (b + 3) % 8,)) + bytes(self.DLEN - p - 1), 0)
                    for r in bits(c):
                        win[r] |= 1 << (8 * p + b)
            self._win = win
        if s not in self._rows:
            rows = []
            for w in self._win:
                out, off = 0, 0
                for size, moves in self.TABLES:
                    x, n = w << (8 * s if moves else 0), 8 * size
                    while x >> n:              # fold: slot (s + p) % size
                        x = (x & ((1 << n) - 1)) ^ (x >> n)
                    out |= x << (8 * off)
                    off += size
                rows.append(out)
            self._rows[s] = rows
        return self._rows[s]

    def parse(self, dat, name):
        what = f"{name}: not a {self.NAME} update file"
        if len(dat) < 16:
            sys.exit(what)
        magic, fcrc, _, n = struct.unpack_from("<IIII", dat)
        if magic >> 16 != self.MAGIC or n == 0 or len(dat) != 16 + n * self.BLK:
            sys.exit(what)
        if crc32(dat[16:], 0xFFFFFFFF) != fcrc:
            sys.exit(f"{name}: file CRC mismatch, the file is damaged")
        blocks = []
        for o in range(16, len(dat), self.BLK):
            W, F = struct.unpack_from("<IH", dat, o)
            blocks.append(Block(W, F, dat[o + 6:o + 16], dat[o + 16:o + self.BLK]))
        log(f"{base(name)}: {self.NAME} firmware {self.ver(magic & 0xFFFF)}, {nblocks(n)}")
        log(f"file CRC {fcrc:08x} ok", "+")
        return File(name, magic & 0xFFFF, blocks, None)

    def build(self, version, entries):
        """entries: (P, F, H) -> update file bytes."""
        body, cache = bytearray(), {}
        for P, f, H in entries:
            body += struct.pack("<IH", crc32(P, self.CRC_INIT), f) + H
            body += self.encrypt(self.K, P, f, cache)
        return struct.pack("<IIII", self.MAGIC << 16 | version,
                           crc32(body, 0xFFFFFFFF), 0, len(entries)) + body

    def blocks_ok(self, K, f, hint=""):
        """-> plaintexts; raises Bad unless every CRC is right."""
        cache, out = {}, []
        for i, blk in enumerate(f.blocks):
            P = self.decrypt(K, blk, cache)
            if crc32(P, self.CRC_INIT) != blk.W:
                raise Bad(f"block {i} does not decrypt correctly{hint}")
            out.append(P)
        return out

class T76(TFamily):
    """T76 (UpdateT76.Dat): 256-byte pages, P = u32(i * 0x100) || page i.
    One 515-byte key table; W = crc32(P, init 0); H is 10 zero bytes. The
    updater writes a fixed marker page at 0x49F00, so the image ends below it.
    Checked against all 14 distinct vendor files; a repacked, modified 1.19
    image has run on a T76."""
    NAME, FILE, MAGIC = "T76", "UpdateT76.Dat", 0xF076
    DLEN, TABLES, CRC_INIT = 260, [(515, True)], 0
    MAX_BLOCKS = 0x49F00 // 256

    def known(self, f, det, pass_):
        for i, blk in enumerate(f.blocks):     # the address marker
            for p, v in enumerate(struct.pack("<I", i * 0x100)):
                yield blk, p, v, False

    def unpack_blocks(self, K, f, hint=""):
        Ps = self.blocks_ok(K, f, hint)
        for i, P in enumerate(Ps):
            if P[:4] != struct.pack("<I", i * 0x100):
                raise Bad(f"block {i} does not decrypt correctly{hint}")
        log(f"{nblocks(len(Ps))} checked: address markers and CRC-32 correct", "+")
        return b"".join(P[4:] for P in Ps)

    def image(self, r): return r
    def describe(self, r): return ""

    def pack(self, image, v, r):
        n = -(-len(image) // 256)
        if not 0 < n <= self.MAX_BLOCKS:
            sys.exit(f"firmware must be 1 to {self.MAX_BLOCKS * 256} bytes")
        log(f"packing {len(image)} bytes -> {nblocks(n)}"
            f"{f' ({n * 256 - len(image)} zero bytes of padding)' if len(image) % 256 else ''}")
        image += bytes(n * 256 - len(image))   # zero-pad the last block, as the vendor does
        new = [(struct.pack("<I", i * 0x100) + image[i * 256:(i + 1) * 256],
                v.blocks[i % len(v.blocks)].F, bytes(10)) for i in range(n)]
        return self.build(v.version, new), image

class T48(TFamily):
    """T48 (UpdateT48.dat): as the T76, except
      * W = crc32(P, init 0xFFFFFFFF)
      * the address marker is the flash address: P = u32(base + i * 0x100) ||
        page i, base = 0x08005000 in vendor files (RISC-V code)
      * H = u16 0, u32 T, u32 0. T is 0 for most blocks and 1, 2, 3, ... from
        some address up (0x0803E000, a separate section); packing follows it
      * the updater writes a marker page at 0x0803FF00; the image ends below it
    Known plaintext is only P[0] = 0 (base is not known in advance); with the
    CRCs that leaves 256 keys, and the address rule picks one. Vendor seeds
    need not reach every slot (V13.16 never uses slot 514).
    Checked against all 27 distinct vendor files. Untested on hardware."""
    NAME, FILE, MAGIC = "T48", "UpdateT48.dat", 0xF048
    DLEN, TABLES, CRC_INIT = 260, [(515, True)], 0xFFFFFFFF
    MARKER_PAGE = 0x0803FF00

    def known(self, f, det, pass_):
        for blk in f.blocks:
            yield blk, 0, 0, False             # every address ends in 00

    def unpack_blocks(self, K, f, hint=""):
        Ps = self.blocks_ok(K, f, hint)
        b0 = struct.unpack_from("<I", Ps[0])[0]
        for i, P in enumerate(Ps):
            if struct.unpack_from("<I", P)[0] != b0 + i * 0x100 or b0 & 0xFF:
                raise Bad(f"block {i} does not decrypt correctly{hint}")
        log(f"{nblocks(len(Ps))} checked: CRC-32 and address markers correct "
            f"(load address {b0:#010x})", "+")
        return b0, b"".join(P[4:] for P in Ps)

    def image(self, r): return r[1]
    def describe(self, r): return f" at {r[0]:#010x}"

    def section_rule(self, blocks, b0):
        """-> address where the counter T starts (None if the file has none)."""
        Ts = [struct.unpack_from("<I", b.H, 2)[0] for b in blocks]
        first = next((i for i, t in enumerate(Ts) if t), None)
        if first is None:
            return None
        for i, t in enumerate(Ts):
            if t != (i - first + 1 if i >= first else 0):
                sys.exit(f"block {i}: unexpected section counter {t}; this file has a "
                         "layout this tool does not know")
        log(f"section counter from {b0 + first * 0x100:#010x} ({nblocks(len(blocks) - first)})")
        return b0 + first * 0x100

    def pack(self, image, v, r):
        b0 = r[0]
        sect = self.section_rule(v.blocks, b0)
        n, most = -(-len(image) // 256), (self.MARKER_PAGE - b0) // 256
        if not 0 < n <= most:
            sys.exit(f"firmware must be 1 to {most * 256} bytes (it loads at {b0:#010x} "
                     f"and must end below {self.MARKER_PAGE:#010x})")
        log(f"packing {len(image)} bytes -> {nblocks(n)}, load address {b0:#010x}")
        image += bytes(n * 256 - len(image))
        new = []
        for i in range(n):
            addr = b0 + i * 0x100
            T = (addr - sect) // 0x100 + 1 if sect is not None and addr >= sect else 0
            new.append((struct.pack("<I", addr) + image[i * 256:(i + 1) * 256],
                        v.blocks[i % len(v.blocks)].F, struct.pack("<HII", 0, T, 0)))
        return self.build(v.version, new), (b0, image)

class T56(TFamily):
    """T56 (updateT56.dat): the T48 cipher with bigger blocks and two tables.
      * a block carries one 2 KiB flash page (DLEN 2052)
      * ks[p] = K[(s + p) % 1024] ^ V[p % 32]: a 1024-byte table that follows
        the start and a fixed 32-byte one. (K ^ c, V ^ c) is the same cipher;
        that freedom never changes a byte and is left as it falls
      * H = u16 0, u16 B (a second seed, unused by the cipher), u16 0, u32 Z
        (0, or a per-file constant in 2021-2022 files); packing copies H
      * blocks are records P = u32 address || 2048 bytes. Block 0 is a record
        for 0xFFFF0000 with 24 bytes of unknown meaning (not a hash of the
        image) and 2024 zero bytes; packing copies it. The others are the
        flash pages that are not all 0xFF, in address order, from program
        flash address 0 (PIC32MZ EF, MIPS32, runs at 0x9D000000)
    Known plaintext: the address bytes, and the record padding. Positions p
    and p + 1024 share every key slot and G, so P[p] ^ P[p + 1024] =
    rol3(C[p] ^ C[p + 1024]) needs no key: the padding is checked constant
    before it is used. Without it the system has rank ~2100 of 8448.
    Checked against all 51 distinct vendor files. Untested on hardware."""
    NAME, FILE, MAGIC = "T56", "updateT56.dat", 0x5600
    DLEN, TABLES, CRC_INIT = 2052, [(1024, True), (32, False)], 0xFFFFFFFF
    PAGE, RECORD, FLASH, REC_LEN = 0x800, 0xFFFF0000, 0x100000, 24

    def known(self, f, det, pass_):
        b0 = f.blocks[0]
        for p, v in enumerate(struct.pack("<I", self.RECORD)):
            yield b0, p, v, False
        pad = range(4 + self.REC_LEN, self.DLEN)
        if all(b0.C[p] == b0.C[p + 1024] for p in pad if p + 1024 < self.DLEN):
            for p in pad:
                yield b0, p, 0, True
        else:
            log(f"{base(f.name)}: record padding is not constant; not used", "!")
        for blk in f.blocks[1:]:               # page addresses: 2 KiB aligned, below 1 MiB
            yield blk, 0, 0, False
            yield blk, 3, 0, False

    def unpack_blocks(self, K, f, hint=""):
        Ps = self.blocks_ok(K, f, hint)
        record, pages = None, {}
        for i, P in enumerate(Ps):
            addr = struct.unpack_from("<I", P)[0]
            if i == 0:
                good = addr == self.RECORD
                record = P[4:]
            else:
                good = (addr % self.PAGE == 0 and addr + self.PAGE <= self.FLASH
                        and addr > max(pages, default=-1))
                pages[addr] = P[4:]
            if not good:
                raise Bad(f"block {i} does not decrypt correctly{hint}")
        log(f"{nblocks(len(Ps))} checked: CRC-32 and address markers correct "
            f"(record at {self.RECORD:#010x}, {len(pages)} pages)", "+")
        log(f"record: {record.rstrip(bytes(1)).hex()}")
        return record, pages

    def image(self, r):
        record, pages = r
        if not pages:
            sys.exit("no firmware pages")
        img = bytearray(b"\xff" * (max(pages) + self.PAGE))
        for a, data in pages.items():
            img[a:a + self.PAGE] = data
        return bytes(img)

    def describe(self, r): return " from address 0"

    def pack(self, image, v, r):
        record = r[0]
        if not 0 < len(image) <= self.FLASH:
            sys.exit(f"firmware must be 1 to {self.FLASH} bytes (the image starts at flash address 0)")
        image += b"\xff" * (-len(image) % self.PAGE)
        pages = [(a, image[a:a + self.PAGE]) for a in range(0, len(image), self.PAGE)
                 if image[a:a + self.PAGE] != b"\xff" * self.PAGE]
        if not pages:
            sys.exit("every byte is 0xFF; nothing to pack")
        log(f"packing {len(image)} bytes -> {len(pages)} non-empty pages + the record")
        new = []
        for i, (addr, data) in enumerate([(self.RECORD, record)] + pages):
            b = v.blocks[i % len(v.blocks)]
            new.append((struct.pack("<I", addr) + data, b.F, b.H))
        return self.build(v.version, new), (record, dict(pages))

# --- TL866II Plus ----------------------------------------------------------------

LBlock = namedtuple("LBlock", "W x addr i C")

class TL866:
    """TL866II Plus (updateII.dat): PIC24FJ256GB110 firmware, a different
    container from the T family but the same kind of cipher: a key table not
    in the file, a per-block start into it, plain XOR (no rotation, no seed).

      * the file carries a 1024-byte table X that only hides the low byte of
        each block's address (see minipro's tl866iiplus.c)
      * K has 512 bytes; block index i (0..127): C[j] = P[j] ^ K[(2i + j) % 512]
      * block CRCs cover the ciphertext, so they say nothing about the key.
        The PIC24 layout does instead: every instruction word is 3 bytes and
        a 0x00 pad byte
      * PIC24 program addresses count 2 per 4-byte word: offset = 2 * address

        u32  0xF8CC_xxxx    xxxx = version, (xxxx >> 12).(xxxx >> 8 & 15).(xxxx & 255)
        u32  file CRC       zlib crc32 of: all blocks, then bytes 8..1035
        1024 X              address table
        u32  n              number of 256-byte blocks
    n blocks of 272 bytes, then the last block of 2064 bytes:
        u32  W              crc32(bytes 4.. of the block, plain address, init 0)
        u32  x              start offset into X
        u32  addr           PIC24 address; low byte XORed with X[(x + k) % 1024],
                            k < 264 (2056 in the last block)
        u32  i              key index (0..127)
        256 / 2048          encrypted data

    The 256-byte blocks cover the image from its start up to the last 256
    bytes that are not all erased (FF FF FF 00 words), rounded up to 512
    bytes. The last block is always the last 2048 bytes of the image.

    Known plaintext: pad bytes are 0 (exact: the PIC24 layout) and fix every
    odd slot. Erased flash, FF FF FF 00, fixes the even ones: a run of RUN or
    more words whose middle byte decrypts to FF (with the odd slots) is taken
    as erased. That is an assumption, so a slot is used only if every run in
    a file agrees on it; every vendor file has such a run in its last block,
    more than one turn of K, and all runs agree. Checked against all 43
    distinct vendor files. Untested on hardware."""
    NAME, FILE, MAGIC = "TL866II", "updateII.dat", 0xF8CC
    HDR, BLK, LAST, NSLOT = 1036, 272, 2064, 512
    ERASED, RUN = b"\xff\xff\xff\x00", 64
    PASSES, CRC = 2, False
    CHECKS = "the pad bytes and layout"

    def ver(self, v): return f"{v >> 12:02d}.{v >> 8 & 15}.{v & 0xFF:02d}"
    def slot_list(self, slots): return f"{slots[:12]}{' ...' if len(slots) > 12 else ''}"
    def sel(self, blk): return blk.i
    def slots(self, blk, j): return [(2 * blk.i + j) % self.NSLOT]
    def ks_from_plain(self, blk, j, v): return blk.C[j] ^ v
    def groups(self, f): return {((2 * b.i + j) % self.NSLOT,) for b in f.blocks for j in range(len(b.C))}

    def stream(self, K, i, n):
        r = 2 * i % self.NSLOT
        return ((K[r:] + K[:r]) * (n // self.NSLOT + 1))[:n]

    def crypt(self, K, data, i): return xor(data, self.stream(K, i, len(data)))

    @staticmethod
    def hide(X, addr, x, n):
        lo = addr & 0xFF
        for k in range(n):
            lo ^= X[(x + k) & 0x3FF]
        return addr & ~0xFF | lo

    @staticmethod
    def crc0(data): return zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF

    def parse(self, dat, name):
        what = f"{name}: not a TL866II update file"
        if len(dat) < self.HDR + self.LAST:
            sys.exit(what)
        magic, fcrc = struct.unpack_from("<II", dat)
        n = struct.unpack_from("<I", dat, self.HDR - 4)[0]
        if magic >> 16 != self.MAGIC or len(dat) != self.HDR + n * self.BLK + self.LAST:
            sys.exit(what)
        if zlib.crc32(dat[8:self.HDR], zlib.crc32(dat[self.HDR:])) != fcrc:
            sys.exit(f"{name}: file CRC mismatch, the file is damaged")
        X, blocks = dat[8:self.HDR - 4], []
        for k in range(n + 1):
            o = self.HDR + k * self.BLK
            size = self.BLK if k < n else self.LAST
            W, x, addr, i = struct.unpack_from("<IIII", dat, o)
            addr = self.hide(X, addr, x, 264 if k < n else 2056)
            if i > 127 or self.crc0(struct.pack("<III", x, addr, i) + dat[o + 16:o + size]) != W:
                sys.exit(f"{name}: block {k} is damaged")
            blocks.append(LBlock(W, x, addr, i, dat[o + 16:o + size]))
        log(f"{base(name)}: TL866II firmware {self.ver(magic & 0xFFFF)}, "
            f"{nblocks(n)} + the last block")
        log(f"file CRC {fcrc:08x} and all block CRCs ok", "+")
        return File(name, magic & 0xFFFF, blocks, X)

    def known(self, f, det, pass_):
        if pass_ == 0:                         # pad bytes: exact
            for blk in f.blocks:
                for j in range(3, len(blk.C), 4):
                    yield blk, j, 0, False
            return
        runs = {}                              # erased runs: assumed, used where they all agree
        for blk in f.blocks:
            C, n, w = blk.C, len(blk.C) // 4, 0
            def erased(w):                     # every known odd byte (middle, pad) matches
                known = [j for j in (4 * w + 1, 4 * w + 3)
                         if (2 * blk.i + j) % self.NSLOT in det]
                return known and all(C[j] ^ det[(2 * blk.i + j) % self.NSLOT] == self.ERASED[j % 4]
                                     for j in known)
            while w < n:
                e = w
                while e < n and erased(e):
                    e += 1
                for j in range(4 * w, 4 * e) if e - w >= self.RUN else ():
                    runs.setdefault(self.slots(blk, j)[0], {}).setdefault(
                        C[j] ^ self.ERASED[j % 4], (blk, j))
                w = e + 1
        dissent = 0
        for t, vals in runs.items():
            if len(vals) == 1:
                blk, j = next(iter(vals.values()))
                yield blk, j, self.ERASED[j % 4], True
            else:
                dissent += 1
        if dissent:
            log(f"{base(f.name)}: erased runs disagree on {dissent} key slots; not used", "!")

    def unpack_blocks(self, K, f, hint=""):
        *normal, last = f.blocks
        b0 = (normal[0] if normal else last).addr
        image = bytearray()
        for k, blk in enumerate(f.blocks):
            P = self.crypt(K, blk.C, blk.i)
            off = 2 * (blk.addr - b0)
            if any(P[3::4]) or off < len(image) or (k < len(normal) and off % 256):
                raise Bad(f"block {k} does not decrypt correctly{hint}")
            image += self.ERASED * ((off - len(image)) // 4) + P
        log(f"{nblocks(len(normal))} + the last block checked: pad bytes 0, addresses "
            f"in order (load address {b0:#x}, byte offset {2 * b0:#x})", "+")
        return b0, bytes(image)

    def image(self, r): return r[1]
    def describe(self, r): return f" at PIC24 address {r[0]:#x}"

    def pack(self, image, v, r):
        b0, vimage = r
        *vnormal, vlast = v.blocks
        if len(image) != len(vimage):
            sys.exit(f"firmware must be {len(vimage)} bytes, like the vendor image "
                     f"(PIC24 addresses {b0:#x} to {b0 + len(vimage) // 2:#x})")
        if any(image[3::4]):
            bad = next(j for j in range(3, len(image), 4) if image[j])
            sys.exit(f"byte {bad:#x} is not 0: every 4th byte of a PIC24 image is a 0 pad byte")
        tail_len = self.LAST - 16
        room = (len(image) - tail_len) // 256
        used = [k for k in range(room) if image[256 * k:256 * (k + 1)] != self.ERASED * 64]
        chunks = [256 * k for k in range(min(room, -(-(used[-1] + 1) // 2) * 2 if used else 0))]
        log(f"packing {len(image)} bytes -> {nblocks(len(chunks))} + the last block")
        parts = [(o, vnormal[k % len(vnormal)] if vnormal else vlast, 264)
                 for k, o in enumerate(chunks)]
        parts.append((len(image) - tail_len, vlast, 2056))
        body = bytearray()
        for o, vb, hops in parts:
            addr = b0 + o // 2
            C = self.crypt(self.K, image[o:o + (tail_len if hops == 2056 else 256)], vb.i)
            W = self.crc0(struct.pack("<III", vb.x, addr, vb.i) + C)
            body += struct.pack("<IIII", W, vb.x, self.hide(v.extra, addr, vb.x, hops), vb.i) + C
        tail = v.extra + struct.pack("<I", len(chunks))
        dat = struct.pack("<II", self.MAGIC << 16 | v.version,
                          zlib.crc32(tail, zlib.crc32(body))) + tail + body
        return dat, (b0, image)

# --- the tool ------------------------------------------------------------------

FORMATS = {c.MAGIC: c for c in (T76, T48, T56, TL866)}

def detect(path, want=None):
    dat = read(path)
    m = struct.unpack_from("<I", dat)[0] >> 16 if len(dat) >= 4 else None
    if m not in FORMATS:
        sys.exit(f"{path}: not an XGecu update file this tool knows")
    fmt = FORMATS[m]()
    if want and fmt.NAME != want:
        sys.exit(f"{path}: a {fmt.NAME} file, not {want}")
    return fmt, fmt.parse(dat, path)

def load(paths):
    """Parse every file; they must all be for the same model."""
    fmt, files = None, []
    for p in paths:
        f2, f = detect(p, fmt.NAME if fmt else None)
        fmt = fmt or f2
        files.append(f)
    return fmt, files

def unpack(dat_path, out_path, key_paths=()):
    fmt, (f, *keys) = load([dat_path, *key_paths])
    K = solve_key(fmt, keys + [f], f)
    hint = "" if key_paths else f"; add -k {fmt.FILE} (a vendor file)"
    try:
        r = fmt.unpack_blocks(K, f, hint)
    except Bad as e:
        sys.exit(str(e))
    image = fmt.image(r)
    write(out_path, image)
    log(f"wrote {base(out_path)}, sha256 {hashlib.sha256(image).hexdigest()}")
    print(f"{out_path}: {fmt.NAME} firmware {fmt.ver(f.version)}, {len(image)} bytes"
          f"{fmt.describe(r)}, {nblocks(len(f.blocks))} verified")

def pack(fw_path, key_paths, out_path):
    """Encrypt fw_path with the key, seeds, version and layout of the first
    vendor file; repacking an unmodified image gives that file back byte for byte."""
    fmt, files = load(key_paths)
    v = files[0]
    fmt.K = solve_key(fmt, files[1:] + [v], v)
    try:
        r = fmt.unpack_blocks(fmt.K, v)        # proves the key on the vendor file
    except Bad as e:
        sys.exit(f"{v.name}: {e}")
    dat, want = fmt.pack(read(fw_path), v, r)
    log("reading the new file back")
    try:
        back = fmt.unpack_blocks(fmt.K, fmt.parse(dat, out_path))
    except Bad:
        back = None
    if back != want:
        sys.exit("internal error: the packed file does not read back; nothing written")
    write(out_path, dat)
    log(f"wrote {base(out_path)}, sha256 {hashlib.sha256(dat).hexdigest()}")
    print(f"{out_path}: {fmt.NAME} firmware {fmt.ver(v.version)}, "
          f"{nblocks(struct.unpack_from('<I', dat, 12)[0]) if fmt.CRC else 'repacked'}")

def main():
    name = "update.dat"
    ap = argparse.ArgumentParser(
        usage=f"%(prog)s -u {name} -o fw.bin\n"
              f"       %(prog)s -p my_fw.bin -k {name} -o my_update.dat",
        description="Unpack and repack XGecu firmware update files (T76, T48, T56, "
                    "TL866II Plus). The model is read from the update file.",
        epilog="examples:\n"
               "  %(prog)s -u UpdateT76.Dat -o fw.bin\n"
               "  %(prog)s -p my_fw.bin -k UpdateT76.Dat -o my_update.Dat\n\n"
               "-k can be given more than once; with -p the first one supplies the layout.",
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(prog, max_help_position=30))
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("-u", "--unpack", metavar=name, help="decrypt an update file to a firmware image")
    mode.add_argument("-p", "--pack", metavar="my_fw.bin", help="encrypt a firmware image into an update file")
    ap.add_argument("-k", "--key", metavar=name, action="append", default=[],
                    help="vendor file to solve the key from (repeatable); needed for -p")
    ap.add_argument("-o", "--output", metavar="FILE", required=True,
                    help="file to write: fw.bin (-u) or my_update.dat (-p)")
    ap.add_argument("-v", "--verbose", action="store_true", help="show each step")
    if len(sys.argv) == 1:
        return ap.print_help()
    a = ap.parse_args()
    global VERBOSE
    VERBOSE = a.verbose
    if a.pack and not a.key:
        ap.error(f"-p needs -k {name} (a vendor file supplies the key)")
    if os.path.exists(a.output) and any(f and os.path.exists(f) and os.path.samefile(f, a.output)
                                        for f in (a.unpack, a.pack, *a.key)):
        ap.error(f"-o {a.output} is also an input; refusing to overwrite it")
    if a.unpack:
        unpack(a.unpack, a.output, a.key)
    else:
        pack(a.pack, a.key, a.output)

if __name__ == "__main__":
    main()
