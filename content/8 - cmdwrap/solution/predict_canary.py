#!/usr/bin/env python3
"""Recover CMDWRAP's xoshiro256** state from sequential leaked canaries.

The allocator reveals 16-bit canaries, but each observation gives nine linear
bits of xoshiro s1 after undoing the low part of the ** output scrambler.
Roughly 30 observations recover the entire 256-bit initial state and permit
exact prediction of subsequent allocation canaries.
"""
import argparse

MASK = (0x137F, 0xACE8, 0x5B24, 0xF091,
        0x6D53, 0xE8C2, 0x9A4E, 0x3706)
MT = (
    (3, 5, 1, 6), (7, 2, 4, 0), (5, 0, 6, 3), (1, 4, 7, 2),
    (6, 7, 0, 5), (2, 3, 5, 4), (0, 1, 3, 7), (4, 6, 2, 1),
)
MASK64 = (1 << 64) - 1


def rotl(x, n):
    return ((x << n) | (x >> (64 - n))) & MASK64


def step(state):
    s0, s1, s2, s3 = state
    result = (rotl((s1 * 5) & MASK64, 7) * 9) & MASK64
    t = (s1 << 17) & MASK64
    s2 ^= s0
    s3 ^= s1
    s1 ^= s2
    s0 ^= s3
    s2 ^= t
    s3 = rotl(s3, 45)
    return result, (s0, s1, s2, s3)


def row_stream(count):
    state = [[1 << (word * 64 + bit) for bit in range(64)]
             for word in range(4)]
    rows = []
    for _ in range(count):
        rows.extend(state[1][:9])
        s0, s1, s2, s3 = state
        t = [0] * 17 + s1[:47]
        s2 = [a ^ b for a, b in zip(s2, s0)]
        s3 = [a ^ b for a, b in zip(s3, s1)]
        s1 = [a ^ b for a, b in zip(s1, s2)]
        s0 = [a ^ b for a, b in zip(s0, s3)]
        s2 = [a ^ b for a, b in zip(s2, t)]
        s3 = [s3[(bit - 45) & 63] for bit in range(64)]
        state = [s0, s1, s2, s3]
    return rows


def solve_linear(rows, rhs):
    basis = {}
    for row, bit in zip(rows, rhs):
        while row:
            pivot = row.bit_length() - 1
            if pivot not in basis:
                basis[pivot] = (row, bit)
                break
            old_row, old_bit = basis[pivot]
            row ^= old_row
            bit ^= old_bit
        if not row and bit:
            return None
    if len(basis) < 256:
        return None
    value = 0
    for pivot in sorted(basis):
        row, bit = basis[pivot]
        bit ^= (row & value).bit_count() & 1
        if bit:
            value |= 1 << pivot
    return tuple((value >> (64 * i)) & MASK64 for i in range(4))


def candidates(canaries):
    inv9 = pow(9, -1, 1 << 16)
    inv5 = pow(5, -1, 1 << 9)
    # (key_low5, initial_mixer, current_mixer, raw-low16 sequence)
    paths = [(k, m, m, ()) for k in range(32) for m in range(8)]
    for canary in canaries:
        nxt = []
        for key, initial, mixer, raws in paths:
            for selector in range(4):
                new_mixer = MT[mixer][selector]
                raw = canary ^ MASK[(key ^ new_mixer) & 7]
                if (((key >> 3) ^ raw) & 3) == selector:
                    nxt.append((key, initial, new_mixer, raws + (raw,)))
        paths = nxt
    rows = row_stream(len(canaries))
    for key, initial, mixer, raws in paths:
        lows = []
        for raw in raws:
            rotated_low16 = (raw * inv9) & 0xffff
            lows.append(((rotated_low16 >> 7) * inv5) & 0x1ff)
        rhs = [(x >> bit) & 1 for x in lows for bit in range(9)]
        state = solve_linear(rows, rhs)
        if state is None:
            continue
        check = state
        if any(((out := step(check))[0] & 0xffff) != raw or
               not (check := out[1]) for raw in raws):
            continue
        yield key, initial, mixer, state


def predict(key, mixer, state, skip, count):
    cur = state
    # Advance past the observations externally before calling this helper.
    for _ in range(skip):
        _, cur = step(cur)
    result = []
    for _ in range(count):
        raw64, cur = step(cur)
        raw = raw64 & 0xffff
        selector = ((key >> 3) ^ raw) & 3
        mixer = MT[mixer][selector]
        result.append(raw ^ MASK[(key ^ mixer) & 7])
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("canary", nargs="+", type=lambda x: int(x, 16))
    ap.add_argument("--next", type=int, default=8)
    ns = ap.parse_args()
    found = list(candidates(ns.canary))
    print(f"solutions={len(found)}")
    for key, initial, mixer, state in found:
        # State returned is before observation zero; advance over all leaks.
        after = state
        for _ in ns.canary:
            _, after = step(after)
        nxt = predict(key, mixer, after, 0, ns.next)
        print(f"key_low5={key:02x} mixer0={initial} mixerN={mixer} "
              f"state0={' '.join(f'{x:016x}' for x in state)} "
              f"next={' '.join(f'{x:04x}' for x in nxt)}")


if __name__ == "__main__":
    main()
