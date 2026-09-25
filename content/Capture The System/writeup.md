# Capture the System

This challenge rewards a bot for owning bytes in a shared 64 KiB arena. V46 is a 344-byte entry built to spread four tiny writers quickly, keep them alive, and leave rival processes stuck in self-loops. The interactive viewer below makes its moving lattice easier to see than a wall of assembly ever could.

## The arena in one minute

Programs arrive as little-endian 32-bit instructions at random, non-overlapping, word-aligned addresses. Each side can run four processes. The score counts bytes last **executed** plus bytes last **written** by that side. Long-lived writing matters more than a dramatic one-time attack.

The trap word is `BEQ r0, r0, 0`: it branches to itself forever. An enemy process that executes it stays alive but makes no progress, still occupying one of four process slots.

## How V46 works

The final image has a 78-instruction loader and a shared eight-instruction worker template. Four phase-staggered workers paint the arena in parallel, skipping the small zones that hold their own code. The loader uses `AUIPC` to learn its random address `B`, finds the template at `B + 0x138`, and computes a source-relative 128-byte *sanctuary* for each worker. Four copied loops live in corresponding arena quarters, so one local overwrite is unlikely to stop all of them.

The essential address calculation is:

```text
template = B + 0x138
r27      = template XOR 0x0200
local    = r27 AND ~0x007f
salt     = 0x18000 OR ((r27 XOR 0x3fe8) AND 0x3fff)
```

The salt turns an orderly phase into a scattered physical address with one XOR. Since XOR is one-to-one, coverage is retained while the write order changes with the random load address.

Each worker loops over this eight-instruction pattern:

```text
ADD   r1, r1, r3              ; step = 0x3c84
REMU  r1, r1, r8              ; modulus = 0x3f80
XOR   r2, r1, r4              ; source-derived salt
SW    r30, [r2 - 0x8000]      ; r30 = BEQ r0,r0,0
SW    r30, [r2 - 0x4000]
SW    r30, [r2]
SW    r30, [r2 + 0x4000]
BEQ   r0, r0, worker_start
```

The four stores hit quarter-separated addresses. `0x3f80` leaves a 128-byte tail out of each quarter; the loader positions its worker homes in the omitted slices. The bot paints around its own active code instead of trapping itself. The aligned step visits all **4,064** permitted word positions before repeating. Four starts, 32 bytes apart, create staggered opening waves.

Before the root joins worker four, it also makes nine one-time stores: four safe local ownership writes and five traps at compact enemy-worker locations measured from match recordings. The latter can halt a rival early without turning the whole bot into a fragile fixed-address attack.

## The checks

V46 was tested in both loader seats across independent random seeds. Against a held-out compact opponent, its weakest result was **490–22** over 512 best-of-three contests.

An independent rebuild matched the artifact hash. A normal passive validation showed four live processes, zero crashes, 440 execution-ownership bytes, and 65,168 write-ownership bytes.

The final file is `v46.hex`: **86 instructions, 344 bytes**. Its SHA-256 as raw bytes is `a65a4bed728c0ee326e32e9dd19401d6a341001183ca36cf527af05fbdd390e5`. The downloadable Python viewer is available beside the bot; the interactive version is embedded above.
