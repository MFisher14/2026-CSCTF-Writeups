# Operation Dawn: The Burnt Server

> Forensics · Easy · Terminal43  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{04_flint_arc_eastward_relay_6aa299}`

**Challenge**

> A hostile force destroyed a fictional country's hospital logistics archive to choke medical transport. Two storage members survived, and the salvage record is in the attachment. Recover the train movement register and submit its complete `CSCTF{...}` marker.

The attachment is `server-remains.tar` (4,198,400 bytes, SHA-256 `98fd39f5…45af`). It unpacks to two 2 MiB disk images, `disk0.img` and `disk2.img`, and a note, `SALVAGE.txt`. The note says the box held three identical drives behind one controller: the center drive (slot 1) was burnt through and its platters are gone, slots 0 and 2 were imaged intact, and the controller and its labels did not survive, so the array settings are not recorded. Three identical members, one lost, data still expected to be recoverable: that is three-member RAID 5 with the chunk size, parity rotation and member order all unknown.

**Approach / walkthrough**

*1. Rebuild the burnt member from parity.* Neither survivor shows a file system on its own (`file` even misreads `disk0.img` as an "OpenPGP Secret Key" — a chance match on noise). In a three-member RAID 5, every stripe holds two data chunks and their XOR, so `slot0 ⊕ slot1 ⊕ slot2 = 0` in every stripe, whichever slot carries parity there. The lost slot 1 is therefore just the byte-wise XOR of the two survivors, and no layout knowledge is needed yet:

```python
slot0 = Path("out/disk0.img").read_bytes()
slot2 = Path("out/disk2.img").read_bytes()
slot1 = bytes(a ^ b for a, b in zip(slot0, slot2))
Path("out/disk1.img").write_bytes(slot1)
```

`file out/disk1.img` now reports a FAT16 boot sector, OEM-ID `mkfs.fat`, 8192 sectors (= 4 MiB, exactly two members' worth), label `DAWN ARCH`. The rebuilt member starting with the boot sector confirms the XOR idea and fixes two layout facts: the volume's first chunk lives on slot 1 (slot 1 holds data in stripe 0, not parity), and there is no RAID metadata header in front of the data.

*2. Read the partial volume on slot 1.* The Sleuth Kit reads a truncated image directly, so inspect the file system before assembling anything:

```sh
fls -r out/disk1.img
TZ=UTC istat out/disk1.img 8
icat -r out/disk1.img 8 | gzip -t
```

`fls` lists four live text files (`ROSTER.TXT`, `WARDS.TXT`, `MANIFEST.TXT`, `SIGNALS.TXT`) and a deleted entry 8, `_RAIN.GZ`. FAT marks a deleted file by overwriting the first name byte with `0xE5`, so this was `TRAIN.GZ`. Its FAT chain is freed, but the directory entry still records the start (sector 111) and the size (16,599 bytes). `istat` confirms it. The file runs from `111 × 512 = 0xDE00` to `0xDE00 + 16599 = 0x11ED7`, which crosses the 64 KiB mark, and `icat -r` from slot 1 alone yields a truncated gzip (`unexpected end of file`). So the file continues on another member.

*3. Work out chunk size and member order.* A short scanner prints, per member, the byte ranges that actually contain data (512-byte sectors, trailing zeros trimmed):

```
slot 0: 0x00000-0x01ed6  0x04200-0x04220  0x08200-0x082be  0x0c200-0x10000
slot 1: 0x00000-0x00220  0x04200-0x04220  0x08200-0x082be  0x0c200-0x10000
slot 2: 0x00000-0x01ed6
```

Slot 1 holds the volume's first structures at their native FAT offsets (boot sector/first FAT at `0x0`, second FAT copy at `0x4200`, root directory at `0x8200`, file data from `0xC200`) and stops dead at `0x10000` — right in the middle of the deleted gzip. Slot 2 holds one short run at its very start: the file needs `0x11ED7 − 0x10000 = 0x1ED7` more bytes, and the run is `0x1ED6` because the file's last byte (the top byte of gzip's length field) is zero. That run is the register's tail. Slot 0 has data wherever slot 1 or slot 2 does, so it is parity in stripe 0. The chunk size is therefore 64 KiB, and stripe 0 is: parity on slot 0, volume bytes `0x0000–0xFFFF` on slot 1, bytes `0x10000–0x1FFFF` on slot 2. Parity on the first slot with data following it is the Linux md "right" family of layouts; the md default (left-symmetric) would start the volume on slot 0, which has no boot sector, and is ruled out.

*4. Assemble and carve.* Interleave the three members with 64 KiB chunks and the right-symmetric rotation into `out/array.img`. `file` reports a full 4 MiB FAT16 volume. Then recover the deleted register with contiguous-cluster recovery and check the CRC:

```sh
fls -r out/array.img
icat -r out/array.img 8 > out/train.gz
gzip -t out/train.gz && gzip -l out/train.gz
```

`gzip -t` passes, and `gzip -l` shows 16,599 compressed → 76,901 uncompressed. Watch the chunk size: sweeping the four md layouts across 512 B … 128 KiB, only the right-* layouts at 64 KiB give a gzip that passes. A 128 KiB (or mdadm's 512 KiB default) assembly still produces a perfect-looking file system, because all FAT metadata sits in the first 64 KiB — only the one file that crosses the chunk boundary breaks, so the gzip CRC is the discriminator. Without the Sleuth Kit, the entry is the sixth directory record at `0x82A0` (`e5 52 41 49 4e 20 20 20 47 5a …`, start cluster `0x10` = sector 111, size `0x40D7` = 16,599), so `dd … skip=56832 count=16599` cuts the same bytes.

*5. Read the register.* Decompress and search:

```sh
gzip -dc out/train.gz > out/train.txt
grep -o 'CSCTF{[^}]*}' out/train.txt
```

The 1,406-line "WHITE VALLEY HOSPITAL — TRAIN MOVEMENT REGISTER" has the movement order buried after record 0942:

```
948:MOVEMENT ORDER: CSCTF{04_flint_arc_eastward_relay_6aa299}
```

**Why it works**

RAID 5 parity is a plain XOR, so a single lost member can be recomputed from the survivors without knowing the controller settings. The settings then surface in the data itself: where the boot sector lands picks the first data member, all FAT metadata sitting on slot 1 at its native offsets sets a 64 KiB lower bound, and the one file that crosses a chunk boundary pins the chunk size and the parity rotation exactly. FAT deletion only marks the directory entry with `0xE5` and frees the chain, leaving the start cluster, size and data clusters in place, so the gzip can be carved back.

**Validation / reproduction**

gzip's CRC-32 and length trailer passed only for the right-* / 64 KiB assembly, so the carve is byte-exact, and the per-member data map agrees with the chosen layout. To reproduce: verify the tar's SHA-256, XOR `disk0`/`disk2` to rebuild `disk1`, confirm the FAT16 boot sector, map the member data ranges to read off the 64 KiB right-symmetric layout, assemble, `icat -r … 8`, `gzip -t`, decompress, and grep for the marker. Accepted on the first submission.
