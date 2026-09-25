# Lion City Layover

A tourist maze led to three postcard keys, a curious WebAssembly cartridge, and finally a boarding pass. The key twist: the server checked one copy of a cartridge section, then ran another.

## Earn the ticket

The page bundle exposed the route through the challenge:

```text
/api/harbour/start → /stamp → /tide → /run → /claim
                    ↘ /postcard
```

`/start` returns a session and three maze grids. Each needs stamps A, B, and C before the exit. The browser shows the moves, but `/stamp` replays them server-side. A breadth-first search over `(x, y, collected-stamp-mask)` finds valid direction strings for all three grids. Submitting them earns a short-lived signed ticket for `/run` and `/claim`.

## Collect the postcards

`/tide?format=a` reveals three back halves; any present `format` value also unlocks `last_stamp`. Match each clue to an image from `/start`:

| Clue | Image trick | Full postcard key |
|---|---|---|
| Artificial steel trees | RGB least-significant-bit stream | `Q7M2-9KP4-4L8N-TW3R` |
| Chicken with fragrant rice | A second PNG appended after `IEND` | `A5ZD-91HJ-K7C2-P9QM` |
| Purple Vanda Miss Joaquim | Plaintext after `IEND` | `N8YF-R4T6-WQ1B-7VL3` |

![Supertree Grove image carrying a postcard key in its RGB low bits](supertree.png)

For the Supertree image, read each RGB channel's low bit, pack groups of eight, and search the resulting bytes for `postcard{...}`. The other two images hide their front halves after the PNG end marker. Sending the completed keys to `/postcard` unlocks cartridge documentation, including this line:

> Two stamps went through immigration. The officer checked the first. The replay kiosk performed the last.

That turns out to be a remarkably literal hint.

## Make the validator see a different cartridge

The supplied `singa_legacy.wasm` is a valid WebAssembly v1 container. Its useful data lives in a custom section named `singa`: `MERLION\0v1.6.1\0`, a little-endian program length, and program bytes. The reference program `01 2a fe ff` is accepted and returns `chroma: [42]`.

The postcard documentation calls `0x61` a legacy diagnostic reader. A cartridge containing just `61 00 00 20 ff` is blocked as an unsafe opcode. But when a safe `singa` section comes first and a second `singa` section holds the diagnostic program, `/run` accepts the module and executes the second section. The two phases disagree:

```text
immigration validator → first singa section
replay interpreter     → last singa section
```

The diagnostic output begins `SINGA-PASSPORT-v61`. Each reader instruction takes a big-endian offset and byte count, so two 32-byte reads reach the service's 64-byte output cap:

```python
program = bytes([
    0x61, 0x00, 0x60, 0x20,
    0x61, 0x00, 0x80, 0x20,
    0xff,
])
```

Every `/run` request also needs proof of work: find a nonce whose `SHA256(ticket + "." + module_b64 + "." + nonce)` starts with `0000`. The resulting `chroma` bytes disclose `rsa_n`, `rsa_e = 65537`, `rsa_c`, and `claim_sha256`.

## Open the boarding pass

The diagnostic jokes that “Fermat liked neighbours on the same HDB landing.” The RSA primes really are close: starting at `ceil(sqrt(n))`, find `a` for which `a² - n` is a square, then set `p = a - b` and `q = a + b`.

Decryption yields:

```text
boarding-pass:katong-1965-to-marina-2026:kopi-o-kosong
```

Its SHA-256 matches the leaked `claim_sha256`. Submit the boarding pass with the ticket to `/api/harbour/claim`:

```text
TISC{w3lc0m3_70_51ng4p0r3_l4h_61}
```

The included `solve.py` performs the maze, postcard, cartridge, proof-of-work, and claim steps.
