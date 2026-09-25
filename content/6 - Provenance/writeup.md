# Provenance

The executable's PE Rich header told a convincing story about its compiler. The program itself told a different one. This challenge was about deciding which witness to trust, then repairing the liar.

## The mismatch

A Rich header records build-tool metadata such as compiler, linker, and object counts. Every marked object in the supplied `challenge.exe` claimed build **25017**, from the Visual Studio 2017 generation. Yet the binary used modern C++ features including `std::print` and `std::stacktrace`, and its machine code matched the MSVC **14.51** family much better.

The header sits between `DanS` at `0x80` and `Rich` at `0xE0`; its XOR key is at `0xE4`, before the PE header at `0x100`. Decoding it shows internally consistent product IDs and counts, but the same suspicious build number repeated across the records.

| Reconstructed toolset | Matching bytes |
|---|---:|
| 14.44 | 4,441 |
| 14.50 | 5,691 |
| **14.51** | **61,591** |
| 14.52 | 8,263–10,950 |

That comparison narrowed the target to twelve documented 14.51 builds: `36231`, `36237`, `36241`, `36243`, `36244`, `36246`, `36247`, `36248`, `36251`, `36252`, `36256`, and `36257`.

## Repair and result

The solve script replaces the false Rich-header build values, recomputes the header XOR key, corrects the linker version to 14.51, and tries those twelve candidates. Run it with:

```bash
./solve.py
```

The accepted build is **36247** (`0x8D97`):

```text
TISC{r1ch_h34d3r_t0ld_a_l1e_ab0ut_1ts_b1rth}
```
