# Operation Dawn: Relay Snapshot

> Forensics · Easy · Terminal43  
> Points: 120 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

`CSCTF{20_dock_move_orchard_elm_grove_dusk_86659c}`

**Challenge**

Responders snapshotted a knocked-out military relay's process memory while recovering a standing order. We are given `relay.core` (586,928 bytes), a Linux x86-64 ELF core of a tiny program `/t`, and must recover the complete `CSCTF{...}` order from it. The order is stored in the process's heap as a linked list of short fragments, mixed with decoy records that splice into the real list's tail and a reversed stack copy that scrambles the sequence — so `strings` alone cannot tell you the order. The reliable reconstruction comes from the process's own saved registers.

Tools: `readelf`, `strings -t x`, `xxd`, and a small Python carver (stdlib only) for the heap chunks and the `NT_PRSTATUS` note.

**Approach / walkthrough**

*1. Map the memory.* A core has no sections, only `PT_LOAD` segments (one per memory mapping, giving the VA↔file-offset mapping) and a `PT_NOTE` segment (registers and the mapped-file list). `readelf -lW` lists the segments; `readelf -nW` prints the `NT_FILE` note. The key observations:

- `/t` (the program) ends at `0x55a77fe26000`. The RW segment at **VA `0x55a7aff17000`, file offset `0x33f8`, size `0x21000`** has no backing file in `NT_FILE` — it is the **heap** (its `0x21000` size is glibc's default first heap).
- The last segment, VA `0x7fffc035a000` at file offset `0x6b3f8`, is the **stack**.
- Address translation: `file_offset = VA − segment_VA + segment_offset`; for the heap that is `VA − 0x55a7aff17000 + 0x33f8`.

*2. Look for the order text.* `strings -a -t x` finds no complete `CSCTF{...}`. In the heap region (`0x36a4`–`0x3ac4`) it finds 23 short fragments spaced exactly `0x30` apart — one per small allocation — and on the stack one long blob at `0x8bbec`:

```
burn_it_bridgefall_backat_dawnstand_doburn_itrelieve_hold_thewn_nowregroup_fall_back_at_two59c}k_866_dusgroveelm_hard_e_orc_movdock{20_CSCTF
```

That stack blob reads the real fragments and the decoys (`burn_it`, `fall_back`, `at_dawn`, `stand_do`, `relieve_`, `hold_the`, `wn_now`, `regroup_`, `_at_two`) in reverse order; it does not say which fragments belong to the order or where it begins and ends.

*3. The stack copy is a trap.* `xxd` over the blob shows that right after the text sits an array of 23 little-endian pointers into the heap (`0x55a7aff173c0`, `0x55a7aff17450`, …), one per record, real and decoy alike — the program's scratch copy of every record. Neither the blob nor the pointer array distinguishes the order. The heap records themselves do: each carries a link to the next record.

*4. Decode a heap record.* Dumping the `CSCTF` fragment's chunk at file offset `0x37a8`:

```
000037a8: 0000 0000 0000 0000 3100 0000 0000 0000  ........1.......
000037b8: 5074 f1af a755 0000 0500 0000 4353 4354  Pt...U......CSCT
000037c8: 4600 ...                                   F...
```

`31 00 …` is a glibc malloc chunk size field (`0x30 | PREV_INUSE`). User data starts 8 bytes later, at file `0x37b8` = VA `0x55a7aff173c0`. Its layout is `u64 next` (`0x55a7aff17450`), `u32 len` (`5`), then `len` text bytes (`CSCTF`). So each record is a singly linked-list node `{next, len, text}`. The `59c}` node has `next = 0` (a list tail); some decoys (`burn_it`, `fall_back`, `relieve_`) are null-terminated too.

*5. Carve every record.* A short script reads the ELF program headers (`elfcore.py`), then walks the heap segment in 16-byte steps, keeping every `0x31`-sized chunk whose `next` is 0 or points inside the heap and whose text is printable:

```python
for chunk in range(heap["off"], heap["off"]+heap["filesz"]-0x30, 0x10):
    size, = struct.unpack_from("<Q", data, chunk+8)
    if size != 0x31: continue
    user = chunk + 0x10
    nxt, ln = struct.unpack_from("<QI", data, user)
    text = data[user+12:user+12+ln]
    in_heap = nxt == 0 or heap["va"] <= nxt < heap["va"]+heap["filesz"]
    if 0 < ln <= 0x28-12 and in_heap and all(b in printable for b in text):
        nodes[user - heap["off"] + heap["va"]] = dict(next=nxt, text=text.decode())
```

This yields all 23 fragments with their links, e.g. the `CSCTF` node at `0x55a7aff173c0 → next 0x55a7aff17450` (`{20_`), and so on.

*6. Follow every list.* A list head is a record no other record points to. Walking each head to `next = 0` gives ten chains, several of which end in the same fragments because the decoy heads splice into the real list's tail:

```
stand_do + fall_back + _mov + ... + k_866 + 59c}   = stand_dofall_back_move_orchard_elm_grove_dusk_86659c}
CSCTF + {20_ + dock + _mov + e_orc + hard_ + elm_ + grove + _dus + k_866 + 59c}
                                                   = CSCTF{20_dock_move_orchard_elm_grove_dusk_86659c}
hold_the + wn_now + fall_back + ... + 59c}         = hold_thewn_nowfall_back_move_orchard_elm_grove_dusk_86659c}
at_dawn + grove + _dus + k_866 + 59c}              = at_dawngrove_dusk_86659c}
regroup_ + _bridge + 59c}                          = regroup__bridge59c}
```

The decoy heads (`stand_do`, `hold_the`, `at_dawn`, `_at_two`, `regroup_`) all tail into `..._86659c}` and look plausible. Only one head starts with `CSCTF` and forms a well-formed `CSCTF{...}` — but relying on the flag format is circular, so the state itself settles it.

*7. Recover the flag from the registers.* The saved thread registers are in the `NT_PRSTATUS` note; `pr_reg` sits at offset 112 in `struct elf_prstatus` on x86-64. Reading them and marking any register that points at a record:

```
rax      0x000055a7aff173c0  -> record 'CSCTF'
rcx      0x000055a7aff176c0  -> record 'burn_it'
rdi      0x000055a7aff173c0  -> record 'CSCTF'
```

Both `rdi` — the first-argument register in the SysV ABI — and `rax` hold the address of the `CSCTF` node, i.e. the list the CPU was processing when the snapshot was taken. (`rcx` points to a decoy `burn_it`; `rdx` holds leftover bytes `n_it` from handling decoy text.) Following `next` from `rdi` to the null terminator gives the 11-fragment order:

```
CSCTF + {20_ + dock + _mov + e_orc + hard_ + elm_ + grove + _dus + k_866 + 59c}
CSCTF{20_dock_move_orchard_elm_grove_dusk_86659c}
```

**Why it works**

A core file is the process's memory mappings (`PT_LOAD`) plus its register state (`PT_NOTE`). Once the program headers translate virtual addresses to file offsets, the raw heap is parseable as glibc chunks and the program's own linked list can be rebuilt. The fragments mean something only in pointer order, and the decoys share the real list's tail, so no chain is distinguishable by its ending. The one reliable head is the node the CPU was actually working on — the address held in `rdi`/`rax` when the memory was snapshotted.

**Validation / reproduction**

Two independent signals agree. The chain starting at the node in `rdi`/`rax` is the only one of the ten that forms a complete, well-formed `CSCTF{...}`, and it ends at a node with `next = 0`. Accepted on the first submission.

Reproduction in short: `readelf -lW`/`-nW` to find the unbacked `0x21000` RW segment (the heap) and translate VAs; carve `0x31`-sized chunks as `{next, len, text}` nodes; walk every head to enumerate the chains; then read `pr_reg` from `NT_PRSTATUS` and follow the list whose head is in `rdi`. Gotchas: the stack blob and its 23-pointer array are a trap (reversed, order-free), and several decoy chains end in the same `..._86659c}` tail — pick the head from process state, not from which string "looks like" a flag.
