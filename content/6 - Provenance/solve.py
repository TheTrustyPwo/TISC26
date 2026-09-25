import struct
from pathlib import Path

import requests


SOURCE = Path("challenge.exe")
OUTPUT = Path("challenge.repaired.exe")
URL = "http://chals.tisc26.ctf.sg:53219/submit"

DANS = 0x536E6144

# Unique documented MSVC 14.51-era Rich build numbers.
BUILDS = [
    36231, 36237, 36241, 36243,
    36244, 36246, 36247, 36248,
    36251, 36252, 36256, 36257,
]


def rol32(value, count):
    count &= 31
    if count == 0:
        return value & 0xFFFFFFFF

    return (
        (value << count)
        | (value >> (32 - count))
    ) & 0xFFFFFFFF


original = SOURCE.read_bytes()
rich = original.index(b"Rich", 0x40, 0x200)
old_key = struct.unpack_from("<I", original, rich + 4)[0]

# Locate the encoded DanS marker.
start = next(
    offset
    for offset in range(rich - 4, 0x3F, -4)
    if (
        struct.unpack_from("<I", original, offset)[0]
        ^ old_key
    ) == DANS
)

# Decode the original records once.
original_entries = []

for offset in range(start + 16, rich, 8):
    comp_id = (
        struct.unpack_from("<I", original, offset)[0]
        ^ old_key
    )
    count = (
        struct.unpack_from("<I", original, offset + 4)[0]
        ^ old_key
    )
    original_entries.append((comp_id, count))


def make_candidate(build):
    data = bytearray(original)
    entries = []

    for comp_id, count in original_entries:
        product = comp_id >> 16

        # Product 1 represents unmarked objects and keeps build zero.
        if product != 1:
            comp_id = (product << 16) | build

        entries.append((comp_id, count))

    # Recompute the Rich checksum/XOR key.
    key = start

    for offset, value in enumerate(data[:start]):
        # e_lfanew is excluded by the Microsoft algorithm.
        if 0x3C <= offset < 0x40:
            continue

        key = (key + rol32(value, offset)) & 0xFFFFFFFF

    for comp_id, count in entries:
        key = (key + rol32(comp_id, count)) & 0xFFFFFFFF

    # Rebuild and XOR-encode the Rich data.
    words = [DANS, 0, 0, 0]

    for comp_id, count in entries:
        words.extend((comp_id, count))

    for offset, word in zip(range(start, rich, 4), words):
        struct.pack_into("<I", data, offset, word ^ key)

    struct.pack_into("<I", data, rich + 4, key)

    # Correct the PE linker version from 14.10 to 14.51.
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    data[pe_offset + 0x1A:pe_offset + 0x1C] = bytes((14, 51))

    return bytes(data)


session = requests.Session()

for build in BUILDS:
    candidate = make_candidate(build)

    response = session.post(
        URL,
        files={
            "file": (
                "challenge.exe",
                candidate,
                "application/octet-stream",
            )
        },
        timeout=30,
    )

    result = response.json()
    print(build, result["status"])

    if result.get("flag"):
        OUTPUT.write_bytes(candidate)
        print(f"Correct build: {build}")
        print(f"Saved repaired binary to {OUTPUT}")
        print(f"Flag: {result['flag']}")
        break
else:
    raise RuntimeError("No documented 14.51 build was accepted")