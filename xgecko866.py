#!/usr/bin/env python3
"""Unpack and repack XGecu TL866II Plus firmware update files (updateII.dat).

    xgecko866.py -u updateII.dat -o fw.bin
    xgecko866.py -p my_fw.bin -k updateII.dat -o my_update.dat

Status: checked against all 43 distinct vendor files (Xgpro V7.03 to V13.16,
firmware 04.1.01 to 04.2.132): each gives the whole key on its own, exactly,
and all 43 keys are identical. Untested on hardware.

The TL866II Plus is a PIC24FJ256GB110 (16-bit, 24-bit instructions; 256 KB
flash, 16 KB RAM, 100 pins). The image runs from 0x1800 (the bootloader is
below) and starts with the XC16 C startup. Its update file
is a different design from the T48/T56/T76 one, but the same kind of cipher:
a key table that is not in the file, a per-block start offset into it, and
plain XOR (no rotation, no seed XOR).

  * the file carries its own 1024-byte table X. It only hides the low byte of
    each block's address (see minipro's tl866iiplus.c); the data are
    encrypted with the device's key K, which the file does not contain
  * K has 512 bytes. A block's 7-bit index i selects where its keystream
    starts: C[j] = P[j] ^ K[(2 * i + j) % 512]. 256-byte blocks use
    K[2i .. 2i + 255]; the last block (2048 bytes) wraps around K four times
  * block CRCs cover the ciphertext, so they say nothing about the key.
    The check is the PIC24 layout instead: every instruction is 3 bytes plus
    a 0x00 pad byte, so every 4th plaintext byte must be 0
  * addresses are PIC24 program addresses, which count 2 per 4-byte
    instruction word: the byte offset in the image is 2 * address

File format (all integers little-endian)
----------------------------------------
    u32  0xF8CC_xxxx    xxxx = firmware version, shown as
                        (xxxx >> 12).(xxxx >> 8 & 15).(xxxx & 255): 0x4284 = 04.2.132
    u32  file CRC       zlib crc32 of: all blocks, then bytes 8..1035
    1024 X              address table
    u32  n              number of 256-byte blocks
n blocks of 272 bytes, then the last block of 2064 bytes:
    u32  W              crc32(bytes 4.. of the block, with the plain address, init 0)
    u32  x              start offset into X
    u32  addr           PIC24 address; its low byte is XORed with
                        X[(x + k) % 1024] for k < 264 (2056 in the last block)
    u32  i              key index (0..127)
    256 / 2048          encrypted data

The 256-byte blocks cover the image from its start, in address order, up to
the last 256 bytes that are not all erased (FF FF FF 00 words), rounded up
to a multiple of 512 bytes. The last block is always the last 2048 bytes of
the image; the erased space between is left out. In every vendor file it
holds a 192-entry table of 16-bit code addresses (words 0..191), erased words,
and the words 0x00AA55, 0x0055A5 (words 508, 509) just below 0x2A000.

The key is not stored here. learn_key() recovers it from any vendor .dat by
known plaintext: pad bytes (all 0) give the odd slots, and the erased run in
the last block (FF FF FF 00 words) gives every slot. Statistics are only a
fallback for a file without such a run (then a few slots may be wrong, and
the tool says how many image bytes that touches; add -k with a vendor file).
"""
import argparse, hashlib, os, struct, sys, zlib

HDR, BLK, LAST = 1036, 272, 2064
NSLOT = 512                    # key table size
MAGIC = 0xF8CC
ERASED = b"\xff\xff\xff\x00"   # an erased PIC24 instruction word
RUN = 64                       # erased words in a row taken as known plaintext

VERBOSE = False
def log(msg, tag="*"):
    """Verbose output: [*] progress, [+] check passed, [!] notable (a repair)."""
    if VERBOSE:
        print(f"[{tag}] {msg}", file=sys.stderr)

def ver(v):     return f"{v >> 12:02d}.{v >> 8 & 15}.{v & 0xFF:02d}"
def nblocks(n): return f"{n} block{'s' * (n != 1)}"

def crc0(data):
    """CRC-32 (zlib polynomial), init 0, no final XOR: the block CRC."""
    return zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF

def slot(i, j):    return (2 * i + j) % NSLOT

def crypt(K, data, i):
    """Encrypt or decrypt (XOR is its own inverse)."""
    return bytes(c ^ K[slot(i, j)] for j, c in enumerate(data))

def hide(X, addr, x, n):
    """XOR the address low byte with n table bytes from x (its own inverse)."""
    lo = addr & 0xFF
    for k in range(n):
        lo ^= X[(x + k) & 0x3FF]
    return addr & ~0xFF | lo

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
    """-> (version, X, [(W, x, addr, i, C), ...]); the last entry is the last
    block. Checks the header, the file CRC and every block CRC."""
    if len(dat) < HDR + LAST:
        sys.exit(f"{name}: not a TL866II update file")
    magic, fcrc = struct.unpack_from("<II", dat)
    n = struct.unpack_from("<I", dat, HDR - 4)[0]
    if magic >> 16 != MAGIC or len(dat) != HDR + n * BLK + LAST:
        sys.exit(f"{name}: not a TL866II update file")
    if zlib.crc32(dat[8:HDR], zlib.crc32(dat[HDR:])) != fcrc:
        sys.exit(f"{name}: file CRC mismatch, the file is damaged")
    X, blocks = dat[8:HDR - 4], []
    for k in range(n + 1):
        o = HDR + k * BLK
        size = BLK if k < n else LAST
        W, x, addr, i = struct.unpack_from("<IIII", dat, o)
        addr = hide(X, addr, x, 264 if k < n else 2056)
        if i > 127 or crc0(struct.pack("<III", x, addr, i) + dat[o + 16:o + size]) != W:
            sys.exit(f"{name}: block {k} is damaged")
        blocks.append((W, x, addr, i, dat[o + 16:o + size]))
    log(f"{os.path.basename(name)}: firmware {ver(magic & 0xFFFF)}, "
        f"{nblocks(n)} + the last block")
    log(f"file CRC {fcrc:08x} and all block CRCs ok", "+")
    return magic & 0xFFFF, X, blocks

def walsh(a):
    """Walsh-Hadamard transform of 256 values (turns XOR correlation into products)."""
    a, h = list(a), 1
    while h < 256:
        for i in range(0, 256, 2 * h):
            for j in range(i, i + h):
                a[j], a[j + h] = a[j] + a[j + h], a[j] - a[j + h]
        h *= 2
    return a

def known_plaintext(blocks):
    """The exact part of the key: -> (K with None where unknown, pad slots,
    erased slots, slots where erased runs disagree).

    1. Pad bytes. The pad byte of every instruction word (j % 4 == 3) is 0, so
       C[j] is its key byte. All pad bytes on one slot must agree.
    2. Erased runs. A word whose known odd bytes (middle byte, pad byte) decrypt
       to FF and 00 looks erased; RUN or more such words in a row are taken as
       erased flash, FF FF FF 00, and give the key byte of all four positions.
       Every vendor file has one in its last block (words 192..507 of 512, more
       than one full turn of K), so one file is enough for all 512 slots.
       In every vendor file all runs agree on every slot. If they don't (an
       edited image with data there), a slot takes the value most runs give,
       or is left to statistics when no value has a strict majority.
    """
    K, pads, erased = [None] * NSLOT, {}, {}
    for *_, i, C in blocks:
        for j in range(3, len(C), 4):
            pads.setdefault(slot(i, j), set()).add(C[j])
    for t, cs in pads.items():
        if len(cs) != 1:
            sys.exit(f"key slot {t}: pad bytes disagree; this file has a layout "
                     "xgecko866 does not know")
        K[t] = min(cs)
    for *_, i, C in blocks:
        def looks_erased(w):
            known = [j for j in (4 * w + 1, 4 * w + 3) if K[slot(i, j)] is not None]
            return known and all(C[j] ^ K[slot(i, j)] == ERASED[j % 4] for j in known)
        n, w = len(C) // 4, 0
        while w < n:
            e = w
            while e < n and looks_erased(e):
                e += 1
            for j in range(4 * w, 4 * e) if e - w >= RUN else ():
                ks = erased.setdefault(slot(i, j), {})
                ks[C[j] ^ ERASED[j % 4]] = ks.get(C[j] ^ ERASED[j % 4], 0) + 1
            w = e + 1
    dissent = []
    for t, ks in sorted(erased.items()):
        k = max(ks, key=ks.get)
        if len(ks) > 1:
            dissent.append(t)   # never in vendor files; an edited image can have data there
            log(f"key slot {t}: erased runs disagree {dict(sorted(ks.items()))}", "!")
            if 2 * ks[k] <= sum(ks.values()):
                continue
        K[t] = k
    return K, set(pads), {t for t in erased if K[t] is not None} - set(pads), dissent

def learn_key(blocks):
    """Recover K from the ciphertext of one or more vendor files.
    -> (K, guessed): guessed = the slots that rest on statistics alone.

    known_plaintext() gives every slot of every vendor file. Statistics only
    fill slots it leaves open (a file with no erased run of RUN words):
      1. as in xgecko76.py, every key slot XORs the same firmware byte stream,
         so each slot's byte histogram is one shared histogram, XOR-shifted by
         that slot's key byte. Align each slot to a common reference.
      2. one global XOR constant is still free: the majority vote against the
         known slots fixes it, and the known slots replace their guesses.
      3. the guessed slots are aligned again, against one reference per byte
         column (j % 4): a PIC24 instruction's low, middle and opcode bytes have
         very different statistics.
    """
    K, pads, erased, _ = known_plaintext(blocks)
    guessed = [t for t in range(NSLOT) if K[t] is None]
    log(f"key from known plaintext: {len(pads)} slots from pad bytes, "
        f"{len(erased)} from erased runs, {len(guessed)} left")
    if guessed:
        K = statistics(blocks, K, guessed)
    log(f"key recovered: {NSLOT - len(guessed)} slots exact, {len(guessed)} guessed "
        f"from statistics{f' {guessed}' if guessed else ''}", "+")
    return bytes(K), set(guessed)

def statistics(blocks, known, guessed):
    """Fill the slots in guessed by histogram alignment (see learn_key)."""
    hist = [[[0] * 256 for _ in range(4)] for _ in range(NSLOT)]
    for *_, i, C in blocks:
        for j, c in enumerate(C):
            hist[slot(i, j)][j % 4][c] += 1
    flat = [[sum(col) for col in zip(*h)] for h in hist]
    used = [t for t in range(NSLOT) if sum(flat[t])]
    if len(used) < NSLOT or len(guessed) == NSLOT:
        sys.exit("too few blocks to learn the key from; add -k updateII.dat (a vendor file)")
    log(f"guessing {len(guessed)} key slots from {sum(map(sum, flat))} encrypted bytes", "!")
    K, ref = [0] * NSLOT, max(flat, key=sum)
    for _ in range(5):
        R, total = walsh(ref), [0] * 256
        for t in used:
            K[t] = best_xor(flat[t], R)
            for v in range(256):
                total[v] += flat[t][v ^ K[t]]
        ref = total
    votes = {}
    for t in range(NSLOT):
        if known[t] is not None:
            votes[K[t] ^ known[t]] = votes.get(K[t] ^ known[t], 0) + 1
    x = max(votes, key=votes.get)
    log(f"global constant {x:#04x} ({votes[x]}/{sum(votes.values())} known slots agree)")
    K = [k ^ x if v is None else v for k, v in zip(K, known)]
    for _ in range(5):
        refs = [[0] * 256 for _ in range(4)]
        for t in used:
            for m in range(4):
                for v in range(256):
                    refs[m][v ^ K[t]] += hist[t][m][v]
        R = [walsh(r) for r in refs]
        changed = 0
        for t in guessed:
            corr = [0] * 256
            for m in range(4):
                if any(hist[t][m]):
                    c = walsh([a * b for a, b in zip(walsh(hist[t][m]), R[m])])
                    corr = [p + q for p, q in zip(corr, c)]
            k = max(range(256), key=corr.__getitem__)
            if k != K[t]:
                K[t], changed = k, changed + 1
        if not changed:
            break
    return K

def best_xor(hist, R):
    """The k for which hist[v ^ k] best matches the reference whose transform is R."""
    corr = walsh([a * b for a, b in zip(walsh(hist), R)])  # corr[k] = sum hist[v^k]*ref[v]
    return max(range(256), key=corr.__getitem__)

def guessed_bytes(blocks, guessed):
    return sum(slot(i, j) in guessed for *_, i, C in blocks for j in range(len(C)))

def note_guessed(n, guessed):
    sys.stdout.flush()
    if n:
        print(f"note: {n} byte{'s' * (n != 1)} rest on key slots guessed from statistics "
              f"({len(guessed)} slots, -v lists them) and may be wrong; pass a vendor file "
              "with -k to make the key exact", file=sys.stderr)

def load_blocks(paths):
    """Parse every file; -> (blocks of all of them, (version, X, blocks) of the first)."""
    files = [parse(read(p), p) for p in paths]
    return [b for f in files for b in f[2]], files[0]

def unpack_blocks(K, blocks, hint=""):
    """Decrypt every block; exit unless the pad bytes are 0 and the addresses
    fit the layout. -> (base, image): base is the PIC24 address of image[0]."""
    *normal, last = blocks
    base = (normal[0] if normal else last)[2]
    image = bytearray()
    for k, (_, _, addr, i, C) in enumerate(blocks):
        P = crypt(K, C, i)
        off = 2 * (addr - base)
        if any(P[3::4]) or off < len(image) or (k < len(normal) and off % 256):
            sys.exit(f"block {k} does not decrypt correctly{hint}")
        image += ERASED * ((off - len(image)) // 4) + P
    log(f"{nblocks(len(normal))} + the last block checked: pad bytes 0, addresses "
        f"in order (load address {base:#x}, byte offset {2 * base:#x})", "+")
    return base, bytes(image)

def unpack(dat_path, out_path, key_paths=()):
    """Decrypt dat_path. The key is learned from dat_path together with the
    vendor files key_paths (useful when dat_path has no erased run of RUN
    words to learn the whole key from)."""
    version, _, blocks = parse(read(dat_path), dat_path)
    kblocks = blocks + load_blocks(key_paths)[0] if key_paths else blocks
    hint = "" if key_paths else ("; the file may be too small to learn the key from, "
                                 "add -k updateII.dat (a vendor file)")
    K, guessed = learn_key(kblocks)
    base, image = unpack_blocks(K, blocks, hint)
    write(out_path, image)
    log(f"wrote {os.path.basename(out_path)}, sha256 {hashlib.sha256(image).hexdigest()}")
    print(f"{out_path}: firmware {ver(version)}, {len(image)} bytes at PIC24 address "
          f"{base:#x}, {nblocks(len(blocks))} verified")
    note_guessed(guessed_bytes(blocks, guessed), guessed)

def pack(fw_path, key_paths, out_path):
    """Encrypt fw_path using the X table, version, layout, key indexes and X
    offsets of the first vendor file, and the key learned from all of them.

    The image must have the vendor image's size: the last block's address is
    fixed. Reusing the vendor values means repacking an unmodified image gives
    back the vendor file byte for byte. A guessed key slot (none, with vendor
    files) cancels out for every byte left as unpacked with the same -k files:
    only changed bytes that land on one can come out wrong on the device."""
    kblocks, (version, X, vblocks) = load_blocks(key_paths)
    dat_path = key_paths[0]
    K, guessed = learn_key(kblocks)
    base, vimage = unpack_blocks(K, vblocks)       # proves the key on the vendor file
    *vnormal, vlast = vblocks
    image = read(fw_path)
    if len(image) != len(vimage):
        sys.exit(f"firmware must be {len(vimage)} bytes, like the vendor image "
                 f"(PIC24 addresses {base:#x} to {base + len(vimage) // 2:#x})")
    if any(image[3::4]):
        bad = next(j for j in range(3, len(image), 4) if image[j])
        sys.exit(f"byte {bad:#x} is not 0: every 4th byte of a PIC24 image is a 0 pad byte")
    room = (len(image) - (LAST - 16)) // 256       # 256-byte chunks before the last block
    used = [k for k in range(room) if image[256 * k:256 * (k + 1)] != ERASED * 64]
    chunks = [256 * k for k in range(min(room, -(-(used[-1] + 1) // 2) * 2 if used else 0))]
    log(f"packing {os.path.basename(fw_path)}: {len(image)} bytes -> "
        f"{nblocks(len(chunks))} + the last block; X table, version {ver(version)}, "
        f"key indexes and X offsets from {os.path.basename(dat_path)}")
    body, risky = bytearray(), 0
    parts = [(o, vnormal[k % len(vnormal)] if vnormal else vlast, 264)
             for k, o in enumerate(chunks)]
    parts.append((len(image) - (LAST - 16), vlast, 2056))
    for o, (_, x, _, i, _), hops in parts:
        addr = base + o // 2
        P = image[o:o + (LAST - 16 if hops == 2056 else 256)]
        C = crypt(K, P, i)
        risky += sum(c != vimage[o + j] and slot(i, j) in guessed for j, c in enumerate(P))
        W = crc0(struct.pack("<III", x, addr, i) + C)
        body += struct.pack("<IIII", W, x, hide(X, addr, x, hops), i) + C
    tail = X + struct.pack("<I", len(chunks))
    dat = struct.pack("<II", MAGIC << 16 | version, zlib.crc32(tail, zlib.crc32(body))) + tail + body
    log("reading the new file back")
    _, _, blocks = parse(dat, out_path)
    if unpack_blocks(K, blocks) != (base, image): # read back what we wrote
        sys.exit("internal error: the packed file does not read back; nothing written")
    write(out_path, dat)
    log(f"wrote {os.path.basename(out_path)}, sha256 {hashlib.sha256(dat).hexdigest()}")
    print(f"{out_path}: firmware {ver(version)}, {nblocks(len(blocks))}")
    sys.stdout.flush()
    if risky:
        print(f"note: {risky} changed byte{'s' * (risky != 1)} land on key slots guessed "
              f"from statistics and may be wrong; pass a vendor file with -k to make the "
              "key exact",
              file=sys.stderr)

def main():
    ap = argparse.ArgumentParser(
        usage="%(prog)s -u updateII.dat -o fw.bin\n"
              "       %(prog)s -p my_fw.bin -k updateII.dat -o my_update.dat",
        description="Unpack and repack XGecu TL866II Plus firmware update files (updateII.dat).",
        epilog="examples:\n"
               "  %(prog)s -u updateII.dat -o fw.bin\n"
               "  %(prog)s -p my_fw.bin -k updateII.dat -o my_update.dat\n"
               "  %(prog)s -u my_update.dat -k updateII.dat -o fw.bin\n\n"
               "-k can be given more than once (the key is the same in every vendor file).\n"
               "Every vendor file gives the whole key by itself; -k helps with a file that\n"
               "does not. With -p, the first -k file supplies the layout.",
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(prog, max_help_position=30))
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("-u", "--unpack", metavar="updateII.dat", help="decrypt an update file to a firmware image")
    mode.add_argument("-p", "--pack", metavar="my_fw.bin", help="encrypt a firmware image into an update file")
    ap.add_argument("-k", "--key", metavar="updateII.dat", action="append", default=[],
                    help="vendor file to learn the key from (repeatable); needed for -p")
    ap.add_argument("-o", "--output", metavar="FILE", required=True,
                    help="file to write: fw.bin (-u) or my_update.dat (-p)")
    ap.add_argument("-v", "--verbose", action="store_true", help="show each step")
    if len(sys.argv) == 1:
        return ap.print_help()
    a = ap.parse_args()
    global VERBOSE
    VERBOSE = a.verbose
    if a.pack and not a.key:
        ap.error("-p needs -k updateII.dat (a vendor file supplies the key)")
    if os.path.exists(a.output) and any(f and os.path.exists(f) and os.path.samefile(f, a.output)
                                        for f in (a.unpack, a.pack, *a.key)):
        ap.error(f"-o {a.output} is also an input; refusing to overwrite it")
    if a.unpack:
        unpack(a.unpack, a.output, a.key)
    else:
        pack(a.pack, a.key, a.output)

if __name__ == "__main__":
    main()
