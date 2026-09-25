#!/usr/bin/env python3
"""Recreate the submitted EXPcalibur bot from the included base image.

This is intentionally self-contained: it only needs Python 3 and the two
files beside it.  The final four table bytes are an inert build nonce.  The
bot validates a saved SHA-256 chaining state, so changing those bytes also
requires updating that state.  This program performs that one-block update.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


HERE = Path(__file__).resolve().parent
BASE = HERE / "bot-base.bin"
META = HERE / "bot-base.json"
DEFAULT_OUTPUT = HERE / "final-bot.bin"
DEFAULT_NONCE = 1_633_114
EXPECTED_SHA256 = "57bde4da73c114fe8d1e750c157759cb0e05a260bcd81f337b6a75af3ec0ccc9"
MASK = 0xFFFFFFFF
K = (
    0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,
    0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,
    0xE49B69C1,0xEFBE4786,0x0FC19DC6,0x240CA1CC,0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,
    0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,0xC6E00BF3,0xD5A79147,0x06CA6351,0x14292967,
    0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,
    0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,0xD192E819,0xD6990624,0xF40E3585,0x106AA070,
    0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,
    0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2,
)
INITIAL = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
           0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)


def rotr(value: int, count: int) -> int:
    return ((value >> count) | (value << (32 - count))) & MASK


def compress(state: tuple[int, ...], block: bytes) -> tuple[int, ...]:
    """The standard SHA-256 compression function for exactly one 64-byte block."""
    if len(block) != 64:
        raise ValueError("SHA-256 compression needs exactly 64 bytes")
    words = list(struct.unpack(">16I", block))
    for index in range(16, 64):
        a, b = words[index - 15], words[index - 2]
        s0 = rotr(a, 7) ^ rotr(a, 18) ^ (a >> 3)
        s1 = rotr(b, 17) ^ rotr(b, 19) ^ (b >> 10)
        words.append((words[index - 16] + s0 + words[index - 7] + s1) & MASK)
    a, b, c, d, e, f, g, h = state
    for index in range(64):
        s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        choose = (e & f) ^ ((~e) & g)
        t1 = (h + s1 + choose + K[index] + words[index]) & MASK
        s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        majority = (a & b) ^ (a & c) ^ (b & c)
        t2 = (s0 + majority) & MASK
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & MASK, c, b, a, (t1 + t2) & MASK
    return tuple((old + new) & MASK for old, new in zip(state, (a, b, c, d, e, f, g, h)))


def midstate(prefix: bytes) -> tuple[int, ...]:
    if len(prefix) % 64:
        raise ValueError("prefix is not block aligned")
    state = INITIAL
    for offset in range(0, len(prefix), 64):
        state = compress(state, prefix[offset:offset + 64])
    return state


def materialize(base: bytes, nonce: int) -> bytes:
    # These offsets are verified below against the included build metadata.
    stable_end, nonce_offset, saved_midstate_offset = 61952, 61964, 62016
    state = midstate(base[:stable_end])
    last_block = bytearray(base[stable_end:saved_midstate_offset])
    struct.pack_into("<I", last_block, nonce_offset - stable_end, nonce & MASK)
    new_midstate = compress(state, bytes(last_block))
    artifact = bytearray(base)
    struct.pack_into("<I", artifact, nonce_offset, nonce & MASK)
    struct.pack_into("<8I", artifact, saved_midstate_offset, *new_midstate)
    return bytes(artifact)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nonce", type=lambda value: int(value, 0), default=DEFAULT_NONCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    metadata = json.loads(META.read_text(encoding="utf-8"))
    base = BASE.read_bytes()
    if len(base) != 62068 or hashlib.sha256(base).hexdigest() != metadata["sha256"]:
        raise RuntimeError("included base image does not match its metadata")
    if (metadata["table_base"], metadata["midstate_base"], metadata["prefix_blocks"]) != (57344, 61984, 969):
        raise RuntimeError("unexpected base layout")
    artifact = materialize(base, args.nonce)
    args.output.write_bytes(artifact)
    digest = hashlib.sha256(artifact).hexdigest()
    print(f"wrote {args.output} ({len(artifact)} bytes)")
    print(f"nonce={args.nonce} sha256={digest}")
    if args.nonce == DEFAULT_NONCE and digest != EXPECTED_SHA256:
        raise RuntimeError("default reproduction digest differs from the submitted artifact")


if __name__ == "__main__":
    main()
