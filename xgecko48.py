#!/usr/bin/env python3
"""Unpack and repack XGecu T48 firmware update files (UpdateT48.dat).

    xgecko48.py -u UpdateT48.dat -o fw.bin
    xgecko48.py -p my_fw.bin -k UpdateT48.dat -o my_update.dat

Status: checked against one vendor file only (Xgpro V13.16, firmware 1.39).
Untested on hardware.

The T48 uses the same container and cipher as the T76 (see xgecko76.py), with
these differences:

  * header magic is 0xF048_xxxx (xxxx = firmware version, 0x0127 = 1.39)
  * block CRC W = crc32(P, init 0xFFFFFFFF), not init 0
  * the address marker in P is the absolute flash address: firmware byte j
    lives at base + j, with base = 0x08005000 in vendor files (the image is
    RISC-V code; the bootloader sits below it)
  * header bytes 8..11 of a block are a u32 counter. It is 0 for most blocks
    and 1, 2, 3, ... for the blocks from 0x0803E000 up (a separate section at
    the top of flash). Packing follows the vendor file's rule.
  * the updater writes a fixed marker page at 0x0803FF00, so the image must
    end below it

File format (all integers little-endian)
----------------------------------------
header, 16 bytes:
    u32  0xF048_xxxx    xxxx = firmware version
    u32  file CRC       crc32(all blocks, init 0xFFFFFFFF)
    u32  0
    u32  n              number of blocks

n blocks of 0x114 bytes; block i carries firmware bytes i*256 .. i*256+255:
    u32  W              crc32(P, init 0xFFFFFFFF)
    u16  F              per-block cipher seed
    u16  0
    u32  T              section counter (see above)
    u32  0
    260  C              encrypted P

P = u32(base + i * 0x100) || 256 firmware bytes

Cipher, for p = 0..259, with key table K (515 bytes):
    G    = F & 0xFF if p % 4 == 0, F >> 8 if p % 4 == 1, else 0
    C[p] = ror3(P[p] ^ G) ^ K[((F & 0xFF) + (F >> 8)) % 256 + p]

The key is not stored here. learn_key() recovers it from any vendor .dat, and
every block's address marker and CRC prove the result.
"""
import argparse, hashlib, os, struct, sys

BLK, DLEN, NSLOT = 0x114, 260, 515
MAGIC = 0xF048
MARKER_PAGE = 0x0803FF00      # the updater writes a fixed marker page here
CRC_INIT = 0xFFFFFFFF

VERBOSE = False
def log(msg, tag="*"):
    """Verbose output: [*] progress, [+] check passed, [!] notable (a repair)."""
    if VERBOSE:
        print(f"[{tag}] {msg}", file=sys.stderr)

def ver(v):     return f"{v >> 8}.{v & 0xFF:02d}"
def nblocks(n): return f"{n} block{'s' * (n != 1)}"

ror3 = lambda x: ((x >> 3) | (x << 5)) & 0xFF
rol3 = lambda x: ((x << 3) | (x >> 5)) & 0xFF

CRC_TABLE = []
for n in range(256):
    for _ in range(8):
        n = (n >> 1) ^ 0xEDB88320 if n & 1 else n >> 1
    CRC_TABLE.append(n)

def crc32(data, init):
    """Reflected CRC-32 (zlib polynomial) with no final XOR."""
    c = init
    for b in data:
        c = (c >> 8) ^ CRC_TABLE[(c ^ b) & 0xFF]
    return c

def g(f, p):      return (f & 0xFF) if p % 4 == 0 else (f >> 8) if p % 4 == 1 else 0
def start(f):     return ((f & 0xFF) + (f >> 8)) & 0xFF
def slots(blocks): return {start(f) + p for _, f, _, _ in blocks for p in range(DLEN)}

def encrypt(K, P, f):
    s = start(f)
    return bytes(ror3(P[p] ^ g(f, p)) ^ K[s + p] for p in range(DLEN))

def decrypt(K, C, f):
    s = start(f)
    return bytes(rol3(C[p] ^ K[s + p]) ^ g(f, p) for p in range(DLEN))

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

def parse(dat, name):
    """-> (version, [(W, F, T, C), ...]); checks the header and file CRC."""
    if len(dat) < 16:
        sys.exit(f"{name}: not a T48 update file")
    magic, fcrc, _, n = struct.unpack_from("<IIII", dat)
    if magic >> 16 != MAGIC or len(dat) != 16 + n * BLK:
        sys.exit(f"{name}: not a T48 update file")
    if crc32(dat[16:], 0xFFFFFFFF) != fcrc:
        sys.exit(f"{name}: file CRC mismatch, the file is damaged")
    blocks = []
    for i in range(n):
        b = dat[16 + i * BLK:16 + (i + 1) * BLK]
        W, F, _, T, _ = struct.unpack_from("<IHHII", b)
        blocks.append((W, F, T, b[16:]))
    log(f"{os.path.basename(name)}: firmware {ver(magic & 0xFFFF)}, {nblocks(n)}")
    log(f"file CRC {fcrc:08x} ok", "+")
    return magic & 0xFFFF, blocks

def walsh(a):
    """Walsh-Hadamard transform of 256 values (turns XOR correlation into products)."""
    a, h = list(a), 1
    while h < 256:
        for i in range(0, 256, 2 * h):
            for j in range(i, i + h):
                a[j], a[j + h] = a[j] + a[j + h], a[j] - a[j + h]
        h *= 2
    return a

def _xor(bits, e):
    s = 0
    for j in range(8):
        if e >> j & 1:
            s ^= bits[j]
    return s

def learn_key(blocks):
    """Recover K from the ciphertext of one vendor file (see xgecko76.py).

    Same three steps as for the T76: histogram alignment per key slot, a
    majority vote on P[0] == 0 (the base address ends in 00), then CRC-syndrome
    repair of the few slots that are still wrong. The syndrome of a one-byte
    error does not depend on the CRC init, so init 0xFFFFFFFF changes nothing.

    Vendor seeds need not reach every slot (UpdateT48.dat V13.16 never uses
    slot 514). Slots no block uses stay 0; unpack() refuses a file that needs one.
    """
    hist = [[0] * 256 for _ in range(NSLOT)]
    for _, f, _, C in blocks:
        for p in range(DLEN):
            hist[start(f) + p][C[p] ^ ror3(g(f, p))] += 1
    used = [t for t in range(NSLOT) if any(hist[t])]
    if len(used) < DLEN + 128:
        sys.exit("too few blocks to learn the key from; add -k UpdateT48.dat (a vendor file)")
    log(f"learning key from {len(blocks) * DLEN} encrypted bytes ({len(used)} of {NSLOT} slots used)")
    K, ref = [0] * NSLOT, max(hist, key=sum)
    for _ in range(5):
        R, total = walsh(ref), [0] * 256
        for t in used:
            corr = walsh([a * b for a, b in zip(walsh(hist[t]), R)])  # corr[k] = sum hist[v^k]*ref[v]
            K[t] = max(range(256), key=corr.__getitem__)
            for v in range(256):
                total[v] += hist[t][v ^ K[t]]
        ref = total

    votes = {}
    for _, f, _, C in blocks:
        x = C[0] ^ K[start(f)] ^ ror3(g(f, 0))
        votes[x] = votes.get(x, 0) + 1
    x = max(votes, key=votes.get)
    K = bytearray(k ^ x if t in used else 0 for t, k in enumerate(K))
    log(f"global constant {x:#04x} ({votes[x]}/{len(blocks)} blocks agree)")

    # syndrome[p][S] = e: plaintext error e at position p changes the CRC by S
    syndrome = []
    for p in range(DLEN):
        bits = [crc32(bytes(p) + bytes([1 << j]) + bytes(DLEN - p - 1), 0) for j in range(8)]
        syndrome.append({_xor(bits, e): e for e in range(1, 256)})
    fixed = 0
    for _ in range(64):
        votes = {}
        for W, f, _, C in blocks:
            S = crc32(decrypt(K, C, f), CRC_INIT) ^ W
            for p in range(DLEN) if S else ():
                if S in syndrome[p]:
                    fix = (start(f) + p, K[start(f) + p] ^ ror3(syndrome[p][S]))
                    votes[fix] = votes.get(fix, 0) + 1
                    break
        if not votes:
            break
        t, v = max(votes, key=votes.get)
        log(f"CRC repaired key slot {t}: {K[t]:#04x} -> {v:#04x} ({votes[(t, v)]} blocks)", "!")
        K[t] = v
        fixed += 1
    log(f"key recovered ({fixed} slot{'s' * (fixed != 1)} repaired)", "+")
    return bytes(K), set(used)

def unpack_blocks(K, blocks, hint=""):
    """Decrypt every block; exit unless every CRC and address marker is right.
    -> (base address, image)"""
    image, base = bytearray(), None
    for i, (W, f, _, C) in enumerate(blocks):
        P = decrypt(K, C, f)
        addr = struct.unpack_from("<I", P)[0]
        if base is None:
            base = addr
        if crc32(P, CRC_INIT) != W or addr != base + i * 0x100 or base & 0xFF:
            sys.exit(f"block {i} does not decrypt correctly{hint}")
        image += P[4:]
    log(f"{nblocks(len(blocks))} checked: CRC-32 and address markers correct "
        f"(load address {base:#010x})", "+")
    return base, bytes(image)

def section_rule(blocks, base):
    """-> address where the counter T starts (None if the file has none).
    Checks the vendor file follows the rule T = (addr - start) / 0x100 + 1."""
    first = next((i for i, b in enumerate(blocks) if b[2]), None)
    if first is None:
        return None
    for i, b in enumerate(blocks):
        if b[2] != (i - first + 1 if i >= first else 0):
            sys.exit(f"block {i}: unexpected section counter {b[2]}; this file has a "
                     "layout xgecko48 does not know")
    log(f"section counter from {base + first * 0x100:#010x} "
        f"({nblocks(len(blocks) - first)})")
    return base + first * 0x100

def unpack(dat_path, out_path, key_path=None):
    """Decrypt dat_path. The key is learned from dat_path itself, or from key_path
    (a vendor file) when dat_path is too small to learn it from."""
    version, blocks = parse(read(dat_path), dat_path)
    kblocks = parse(read(key_path), key_path)[1] if key_path else blocks
    K, known = learn_key(kblocks)
    if not slots(blocks) <= known:
        sys.exit(f"{dat_path} uses key slots the key file does not cover; "
                 "try another vendor file with -k")
    hint = "" if key_path else ("; the file may be too small to learn the key from, "
                                "add -k UpdateT48.dat (a vendor file)")
    base, image = unpack_blocks(K, blocks, hint)
    write(out_path, image)
    log(f"wrote {os.path.basename(out_path)}, sha256 {hashlib.sha256(image).hexdigest()}")
    print(f"{out_path}: firmware {ver(version)}, {len(image)} bytes at {base:#010x}, "
          f"{nblocks(len(blocks))} verified")

def pack(fw_path, dat_path, out_path):
    """Encrypt fw_path using the key, seeds, version, load address and section
    counter rule of the vendor file dat_path.

    Reusing the vendor seeds means repacking an unmodified image gives back the
    vendor file byte for byte."""
    version, vblocks = parse(read(dat_path), dat_path)
    K, _ = learn_key(vblocks)
    base, _ = unpack_blocks(K, vblocks)            # proves the key on the vendor file
    sect = section_rule(vblocks, base)
    image = read(fw_path)
    n, max_blocks = -(-len(image) // 256), (MARKER_PAGE - base) // 256
    if not 0 < n <= max_blocks:
        sys.exit(f"firmware must be 1 to {max_blocks * 256} bytes "
                 f"(it loads at {base:#010x} and must end below {MARKER_PAGE:#010x})")
    log(f"packing {os.path.basename(fw_path)}: {len(image)} bytes -> {nblocks(n)}"
        f"{f' ({n * 256 - len(image)} zero bytes of padding)' if len(image) % 256 else ''}; "
        f"seeds, version {ver(version)} and load address {base:#010x} "
        f"from {os.path.basename(dat_path)}")
    image += bytes(n * 256 - len(image))           # zero-pad the last block
    body = bytearray()
    for i in range(n):
        addr = base + i * 0x100
        P = struct.pack("<I", addr) + image[i * 256:(i + 1) * 256]
        f = vblocks[i % len(vblocks)][1]           # vendor seeds only use learned slots
        T = (addr - sect) // 0x100 + 1 if sect is not None and addr >= sect else 0
        body += struct.pack("<IHHII", crc32(P, CRC_INIT), f, 0, T, 0) + encrypt(K, P, f)
    dat = struct.pack("<IIII", MAGIC << 16 | version, crc32(body, 0xFFFFFFFF), 0, n) + body
    log("reading the new file back")
    _, blocks = parse(dat, out_path)
    if unpack_blocks(K, blocks) != (base, image):  # read back what we wrote
        sys.exit("internal error: the packed file does not read back; nothing written")
    write(out_path, dat)
    log(f"wrote {os.path.basename(out_path)}, sha256 {hashlib.sha256(dat).hexdigest()}")
    print(f"{out_path}: firmware {ver(version)}, {nblocks(n)}")

def main():
    ap = argparse.ArgumentParser(
        usage="%(prog)s -u UpdateT48.dat -o fw.bin\n"
              "       %(prog)s -p my_fw.bin -k UpdateT48.dat -o my_update.dat",
        description="Unpack and repack XGecu T48 firmware update files (UpdateT48.dat).",
        epilog="examples:\n"
               "  %(prog)s -u UpdateT48.dat -o fw.bin\n"
               "  %(prog)s -p my_fw.bin -k UpdateT48.dat -o my_update.dat",
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(prog, max_help_position=30))
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("-u", "--unpack", metavar="UpdateT48.dat", help="decrypt an update file to a firmware image")
    mode.add_argument("-p", "--pack", metavar="my_fw.bin", help="encrypt a firmware image into an update file")
    ap.add_argument("-k", "--key", metavar="UpdateT48.dat",
                    help="vendor file to take the key from; needed for -p")
    ap.add_argument("-o", "--output", metavar="FILE", required=True,
                    help="file to write: fw.bin (-u) or my_update.dat (-p)")
    ap.add_argument("-v", "--verbose", action="store_true", help="show each step")
    if len(sys.argv) == 1:
        return ap.print_help()
    a = ap.parse_args()
    global VERBOSE
    VERBOSE = a.verbose
    if a.pack and not a.key:
        ap.error("-p needs -k UpdateT48.dat (a vendor file supplies the key)")
    if os.path.exists(a.output) and any(f and os.path.exists(f) and os.path.samefile(f, a.output)
                                        for f in (a.unpack, a.pack, a.key)):
        ap.error(f"-o {a.output} is also an input; refusing to overwrite it")
    if a.unpack:
        unpack(a.unpack, a.output, a.key)
    else:
        pack(a.pack, a.key, a.output)

if __name__ == "__main__":
    main()
