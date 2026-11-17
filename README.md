# XGecko76

**XGecu** programmer firmware tools: unpack the firmware from an update file, or pack some.

Have you ever wanted to see your gecko's firmware? Or package your own? Me too, kind of, and now we can.

## Usage

```sh
python3 xgecko.py -u UpdateT76.Dat -o fw.bin
python3 xgecko.py -p my_fw.bin -k UpdateT76.Dat -o my_update.Dat
```

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
