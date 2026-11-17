#!/usr/bin/env python3
"""Unpack and repack XGecu T56 firmware update files (updateT56.dat).

    xgecko56.py -u updateT56.dat -o fw.bin
    xgecko56.py -p my_fw.bin -k updateT56.dat -o my_update.dat

Status: checked against all 51 distinct vendor files (Xgpro V10.00 to V13.16,
firmware 1.03 to 1.73); the keys learned from each agree. Untested on hardware.

The T56 uses the T48 cipher (see xgecko48.py) with a longer key, inside a
container with bigger blocks:

  * header magic is 0x5600_xxxx (xxxx = firmware version, 0x0149 = 1.73)
  * a block carries one 2 KiB flash page, not 256 bytes
  * the key table K has 1024 bytes and its index wraps: K[(start + p) % 1024].
    A second, fixed 32-byte table V is XORed on top: V[p % 32]
  * block header bytes 8..9 hold a second seed B that the cipher does not use,
    and older files (2021-2022) put a per-file constant in bytes 12..15.
    Packing copies both from the vendor file.
  * blocks are records: P starts with the page's flash address, and pages that
    are all 0xFF are left out. The image is PIC32MZ EF code (MIPS32 with a
    64-bit FPU, 512 KB RAM; it reads DEVSN0), offsets from the start of
    program flash, run at 0x9D000000. Flash word 0xFFFFC is 0xCC526788 in
    every version; pages 0xFC000/0xFC800 hold pointer tables and some code.
  * block 0 is a record for address 0xFFFF0000 holding 24 bytes that are not
    firmware. Their meaning is unknown (open). They change with the firmware
    version, and two different images can carry the same record (1.32/1.33,
    1.53/1.54), so it is not a hash of the image. Packing copies this record
    from the vendor file.

File format (all integers little-endian)
----------------------------------------
header, 16 bytes:
    u32  0x5600_xxxx    xxxx = firmware version
    u32  file CRC       crc32(all blocks, init 0xFFFFFFFF)
    u32  0
    u32  n              number of blocks

n blocks of 0x814 bytes:
    u32  W              crc32(P, init 0xFFFFFFFF)
    u16  A              cipher seed
    u16  0
    u16  B              second seed (unused by the cipher)
    u16  0
    u32  Z              0, or a per-file constant in older files (meaning unknown)
    2052 C              encrypted P

P = u32(flash address) || 2048 bytes. Block 0 is the 0xFFFF0000 record; the
others are the pages with any byte other than 0xFF, in address order.
Unpacking writes flash from address 0 to the end of the last page present,
with 0xFF in the gaps.

Cipher, for p = 0..2051, with key tables K (1024 bytes) and V (32 bytes):
    G    = A & 0xFF if p % 4 == 0, A >> 8 if p % 4 == 1, else 0
    C[p] = ror3(P[p] ^ G) ^ K[(((A & 0xFF) + (A >> 8)) % 256 + p) % 1024] ^ V[p % 32]

The keys are not stored here. learn_key() recovers them from any vendor .dat,
and every block's address marker and CRC prove the result.
"""
import argparse, hashlib, os, struct, sys

BLK, DLEN, PAGE = 0x814, 2052, 0x800
NK, NV = 1024, 32
MAGIC = 0x5600
CRC_INIT = 0xFFFFFFFF
RECORD = 0xFFFF0000           # address of the non-firmware record in block 0
FLASH = 0x100000              # 1 MiB of program flash

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

def encrypt(key, P, f):
    K, V = key
    s = start(f)
    return bytes(ror3(P[p] ^ g(f, p)) ^ K[(s + p) % NK] ^ V[p % NV] for p in range(DLEN))

def decrypt(key, C, f):
    K, V = key
    s = start(f)
    return bytes(rol3(C[p] ^ K[(s + p) % NK] ^ V[p % NV]) ^ g(f, p) for p in range(DLEN))

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
    """-> (version, [(W, A, H, C), ...]); checks the header and file CRC.
    H is block header bytes 6..15 (B and Z), which packing copies."""
    if len(dat) < 16:
        sys.exit(f"{name}: not a T56 update file")
    magic, fcrc, _, n = struct.unpack_from("<IIII", dat)
    if magic >> 16 != MAGIC or n == 0 or len(dat) != 16 + n * BLK:
        sys.exit(f"{name}: not a T56 update file")
    if crc32(dat[16:], 0xFFFFFFFF) != fcrc:
        sys.exit(f"{name}: file CRC mismatch, the file is damaged")
    blocks = []
    for i in range(n):
        b = dat[16 + i * BLK:16 + (i + 1) * BLK]
        W, A = struct.unpack_from("<IH", b)
        blocks.append((W, A, b[6:16], b[16:]))
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

def best_xor(hist, R):
    """The k for which hist[v ^ k] best matches the reference whose transform is R."""
    corr = walsh([a * b for a, b in zip(walsh(hist), R)])  # corr[k] = sum hist[v^k]*ref[v]
    return max(range(256), key=corr.__getitem__)

def _xor(bits, e):
    s = 0
    for j in range(8):
        if e >> j & 1:
            s ^= bits[j]
    return s

def learn_key(blocks):
    """Recover (K, V) from the ciphertext of one vendor file.

    The T48 method (see xgecko48.py) with two tables. With the seed XOR undone,
    each byte is ror3(P) ^ K[t] ^ V[k], t = (start + p) % 1024, k = p % 32.
    Because start varies from block to block, every (t, k) pair is a separate
    histogram of the same shifted firmware byte stream. Alternate: align the K
    slots with V fixed, then the V slots with K fixed, until nothing changes.
    One global constant is left, which the vote on P[0] == 0 fixes (every
    address ends in 00). CRC syndromes then repair any K slot still wrong.
    """
    pair = {}
    for _, f, _, C in blocks:
        s = start(f)
        for p in range(DLEN):
            h = pair.setdefault(((s + p) % NK, p % NV), [0] * 256)
            h[C[p] ^ ror3(g(f, p))] += 1
    if len({t for t, _ in pair}) < NK:
        sys.exit("too few blocks to learn the key from; add -k updateT56.dat (a vendor file)")
    log(f"learning key from {len(blocks) * DLEN} encrypted bytes")
    K, V, ref = [0] * NK, [0] * NV, None
    for _ in range(20):
        hk = [[0] * 256 for _ in range(NK)]
        for (t, k), h in pair.items():
            for v in range(256):
                hk[t][v ^ V[k]] += h[v]
        if ref is None:
            ref = max(hk, key=sum)
        R = walsh(ref)
        newK = [best_xor(hk[t], R) for t in range(NK)]
        hv, ref = [[0] * 256 for _ in range(NV)], [0] * 256
        for (t, k), h in pair.items():
            for v in range(256):
                hv[k][v ^ newK[t]] += h[v]
                ref[v ^ newK[t] ^ V[k]] += h[v]
        R = walsh(ref)
        newV = [best_xor(hv[k], R) for k in range(NV)]
        if (newK, newV) == (K, V):
            break
        K, V = newK, newV

    votes = {}
    for _, f, _, C in blocks:
        x = C[0] ^ K[start(f)] ^ V[0] ^ ror3(g(f, 0))
        votes[x] = votes.get(x, 0) + 1
    x = max(votes, key=votes.get)
    K = bytearray(k ^ x for k in K)
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
            S = crc32(decrypt((K, V), C, f), CRC_INIT) ^ W
            for p in range(DLEN) if S else ():
                if S in syndrome[p]:
                    t = (start(f) + p) % NK
                    fix = (t, K[t] ^ ror3(syndrome[p][S]))
                    votes[fix] = votes.get(fix, 0) + 1
                    break
        if not votes:
            break
        t, v = max(votes, key=votes.get)
        log(f"CRC repaired key slot {t}: {K[t]:#04x} -> {v:#04x} ({votes[(t, v)]} blocks)", "!")
        K[t] = v
        fixed += 1
    log(f"key recovered ({fixed} slot{'s' * (fixed != 1)} repaired)", "+")
    return bytes(K), bytes(V)

def unpack_blocks(key, blocks, hint=""):
    """Decrypt every block; exit unless every CRC and address marker is right.
    -> (record, {address: page})"""
    record, pages = None, {}
    for i, (W, f, _, C) in enumerate(blocks):
        P = decrypt(key, C, f)
        addr = struct.unpack_from("<I", P)[0]
        good = crc32(P, CRC_INIT) == W
        if i == 0:
            good &= addr == RECORD
        else:
            good &= addr % PAGE == 0 and addr + PAGE <= FLASH and addr > max(pages, default=-1)
        if not good:
            sys.exit(f"block {i} does not decrypt correctly{hint}")
        if i == 0:
            record = P[4:]
        else:
            pages[addr] = P[4:]
    log(f"{nblocks(len(blocks))} checked: CRC-32 and address markers correct "
        f"(record at {RECORD:#010x}, {len(pages)} pages)", "+")
    log(f"record: {record.rstrip(bytes(1)).hex()}")
    return record, pages

def flatten(pages):
    """Pages -> one image from address 0, gaps filled with 0xFF."""
    end = max(pages) + PAGE
    image = bytearray(b"\xff" * end)
    for a, data in pages.items():
        image[a:a + PAGE] = data
    return bytes(image)

def unpack(dat_path, out_path, key_path=None):
    """Decrypt dat_path. The key is learned from dat_path itself, or from key_path
    (a vendor file) when dat_path is too small to learn it from."""
    version, blocks = parse(read(dat_path), dat_path)
    kblocks = parse(read(key_path), key_path)[1] if key_path else blocks
    hint = "" if key_path else ("; the file may be too small to learn the key from, "
                                "add -k updateT56.dat (a vendor file)")
    _, pages = unpack_blocks(learn_key(kblocks), blocks, hint)
    if not pages:
        sys.exit(f"{dat_path}: no firmware pages")
    image = flatten(pages)
    write(out_path, image)
    log(f"wrote {os.path.basename(out_path)}, sha256 {hashlib.sha256(image).hexdigest()}")
    print(f"{out_path}: firmware {ver(version)}, {len(image)} bytes from address 0, "
          f"{nblocks(len(blocks))} verified")

def pack(fw_path, dat_path, out_path):
    """Encrypt fw_path using the key, seeds, version and 0xFFFF0000 record of the
    vendor file dat_path.

    Reusing the vendor seeds means repacking an unmodified image gives back the
    vendor file byte for byte."""
    version, vblocks = parse(read(dat_path), dat_path)
    key = learn_key(vblocks)
    record, _ = unpack_blocks(key, vblocks)        # proves the key on the vendor file
    image = read(fw_path)
    if not 0 < len(image) <= FLASH:
        sys.exit(f"firmware must be 1 to {FLASH} bytes (the image starts at flash address 0)")
    image += b"\xff" * (-len(image) % PAGE)       # erased flash
    pages = [(a, image[a:a + PAGE]) for a in range(0, len(image), PAGE)
             if image[a:a + PAGE] != b"\xff" * PAGE]
    if not pages:
        sys.exit(f"{fw_path}: every byte is 0xFF; nothing to pack")
    n = len(pages) + 1
    log(f"packing {os.path.basename(fw_path)}: {len(image)} bytes -> "
        f"{len(pages)} non-empty pages + the record = {nblocks(n)}; "
        f"seeds, version {ver(version)} and record from {os.path.basename(dat_path)}")
    body = bytearray()
    for i, (addr, data) in enumerate([(RECORD, record)] + pages):
        P = struct.pack("<I", addr) + data
        _, f, H, _ = vblocks[i % len(vblocks)]
        body += struct.pack("<IH", crc32(P, CRC_INIT), f) + H + encrypt(key, P, f)
    dat = struct.pack("<IIII", MAGIC << 16 | version, crc32(body, 0xFFFFFFFF), 0, n) + body
    log("reading the new file back")
    _, blocks = parse(dat, out_path)
    rec2, pages2 = unpack_blocks(key, blocks)      # read back what we wrote
    if rec2 != record or pages2 != dict(pages):
        sys.exit("internal error: the packed file does not read back; nothing written")
    write(out_path, dat)
    log(f"wrote {os.path.basename(out_path)}, sha256 {hashlib.sha256(dat).hexdigest()}")
    print(f"{out_path}: firmware {ver(version)}, {nblocks(n)}")

def main():
    ap = argparse.ArgumentParser(
        usage="%(prog)s -u updateT56.dat -o fw.bin\n"
              "       %(prog)s -p my_fw.bin -k updateT56.dat -o my_update.dat",
        description="Unpack and repack XGecu T56 firmware update files (updateT56.dat).",
        epilog="examples:\n"
               "  %(prog)s -u updateT56.dat -o fw.bin\n"
               "  %(prog)s -p my_fw.bin -k updateT56.dat -o my_update.dat",
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(prog, max_help_position=30))
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("-u", "--unpack", metavar="updateT56.dat", help="decrypt an update file to a firmware image")
    mode.add_argument("-p", "--pack", metavar="my_fw.bin", help="encrypt a firmware image into an update file")
    ap.add_argument("-k", "--key", metavar="updateT56.dat",
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
        ap.error("-p needs -k updateT56.dat (a vendor file supplies the key)")
    if os.path.exists(a.output) and any(f and os.path.exists(f) and os.path.samefile(f, a.output)
                                        for f in (a.unpack, a.pack, a.key)):
        ap.error(f"-o {a.output} is also an input; refusing to overwrite it")
    if a.unpack:
        unpack(a.unpack, a.output, a.key)
    else:
        pack(a.pack, a.key, a.output)

if __name__ == "__main__":
    main()
