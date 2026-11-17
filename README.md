# XGecko76

**XGecu** programmer firmware tools: unpack the firmware from an update file, or pack some.

Have you ever wanted to see your gecko's firmware? Or package your own? Me too, kind of, and now we can.

| Programmer   | Script         | Update file (from Xgpro) |
|--------------|----------------|--------------------------|
| T76          | `xgecko76.py`  | `UpdateT76.Dat`          |
| T48          | `xgecko48.py`  | `UpdateT48.dat`          |
| T56          | `xgecko56.py`  | `updateT56.dat`          |
| TL866II Plus | `xgecko866.py` | `updateII.dat`           |

The T48, T56 and TL866II tools are untested on hardware. Every distinct vendor file in Xgpro V7.03 to V13.25 (14 T76, 27 T48, 51 T56, 43 TL866II) unpacks with all its checks passing, gives the same key as every other file, and repacks byte for byte. `tests/check_all.py VENDOR_DIR` checks all of that in one run (vendor files are not in the repo).

## Usage

```sh
python3 xgecko76.py -u UpdateT76.Dat -o fw.bin
python3 xgecko76.py -p my_fw.bin -k UpdateT76.Dat -o my_update.Dat
```

The others work the same way: swap in the script and the file name. Each script's docstring describes the file format.

The key is never stored in the scripts. Each one learns it from the vendor file, so packing needs `-k` with a vendor update file.

TL866II: the update file has no plaintext CRC, so the key comes from known plaintext (pad bytes and erased flash) instead. Every vendor file gives the whole key exactly. `-k` can be given more than once.

Old Xgpro versions are mirrored at [Kreeblah/XGecu_Software](https://github.com/Kreeblah/XGecu_Software).

## It worked on my computer ¯\\\_(ツ)\_/¯

```
$ lsusb
...
Bus 004 Device 004: ID a466:1a86 Haikou Xingong Electronics Co.,Ltd XGecko T76
```

## Giants' shoulders

[radiomanV/TL866](https://github.com/radiomanV/TL866)

[minipro](https://gitlab.com/DavidGriffith/minipro)
