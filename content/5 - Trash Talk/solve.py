"""Deterministic end-to-end solver for TISC Trash Talk.

The only network destination is the challenge host/port.  The Nintendo host is
sent solely as the HTTP virtual-host header expected by the emulated DS service.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import re
import struct


CONNECT_HOST = "chals.tisc26.ctf.sg"
CONNECT_PORT = 31259
VHOST = "gamestats2.gs.nintendowifi.net"
SALT4 = b"sAdeqWo3voLeC5r16DYv"
SALT5 = b"HZEdGCzcGGLvguqUEKQN"
MASK4 = 0x4A3B2C1D
MASK5 = 0x2DB842B2
SEARCH4 = "/pokemondpds/worldexchange/search.asp"
SEARCH5 = "/syachi2ds/web/worldexchange/search.asp"
EXCHANGE5 = "/syachi2ds/web/worldexchange/exchange.asp"
BLOCK_ORDERS = (
    (0, 1, 2, 3), (0, 1, 3, 2), (0, 2, 1, 3), (0, 3, 1, 2),
    (0, 2, 3, 1), (0, 3, 2, 1), (1, 0, 2, 3), (1, 0, 3, 2),
    (2, 0, 1, 3), (3, 0, 1, 2), (2, 0, 3, 1), (3, 0, 2, 1),
    (1, 2, 0, 3), (1, 3, 0, 2), (2, 1, 0, 3), (3, 1, 0, 2),
    (2, 3, 0, 1), (3, 2, 0, 1), (1, 2, 3, 0), (1, 3, 2, 0),
    (2, 1, 3, 0), (3, 1, 2, 0), (2, 3, 1, 0), (3, 2, 1, 0),
    (0, 1, 2, 3), (0, 1, 3, 2), (0, 2, 1, 3), (0, 3, 1, 2),
    (0, 2, 3, 1), (0, 3, 2, 1), (1, 0, 2, 3), (1, 0, 3, 2),
)


def http_get(path: str, cookie: str | None = None) -> tuple[int, list[tuple[str, str]], bytes]:
    connection = http.client.HTTPConnection(CONNECT_HOST, CONNECT_PORT, timeout=10)
    headers = {"Host": VHOST, "User-Agent": "GameSpyHTTP/1.0"}
    if cookie:
        headers["Cookie"] = cookie
    connection.request("GET", path, headers=headers)
    response = connection.getresponse()
    result = response.status, response.getheaders(), response.read()
    connection.close()
    return result


def cookie_from(headers: list[tuple[str, str]]) -> str | None:
    return next((value.split(";", 1)[0] for key, value in headers if key.lower() == "set-cookie"), None)


def encode4(pid: int, payload: bytes) -> str:
    pid_bytes = struct.pack("<I", pid)
    seed = sum(pid.to_bytes(4, "big")) + sum(payload)
    state = seed | (seed << 16)
    encrypted = bytearray()
    for byte in pid_bytes + payload:
        state = (69 * state + 4369) % 0x80000000
        encrypted.append(byte ^ ((state >> 16) & 0xFF))
    packet = struct.pack(">I", seed ^ MASK4) + encrypted
    return base64.urlsafe_b64encode(packet).decode()


def call4(path: str, pid: int, payload: bytes) -> bytes:
    status, headers, token = http_get(f"{path}?pid={pid}")
    if status != 200 or len(token) != 32:
        raise RuntimeError(f"Gen IV token request failed: HTTP {status}")
    digest = hashlib.sha1(SALT4 + token).hexdigest()
    data = encode4(pid, payload)
    status, _, body = http_get(f"{path}?pid={pid}&hash={digest}&data={data}", cookie_from(headers))
    if status != 200:
        raise RuntimeError(f"Gen IV action failed: HTTP {status}")
    return body


def encode5(pid: int, payload: bytes) -> str:
    inner = struct.pack("<II", pid, len(payload)) + payload
    return base64.urlsafe_b64encode(struct.pack(">I", sum(inner) ^ MASK5) + inner).decode()


def call5(path: str, pid: int, payload: bytes) -> bytes:
    pid &= 0xFFFFFFFF
    query_pid = pid if pid < 0x80000000 else pid - 0x100000000
    status, headers, token = http_get(f"{path}?pid={query_pid}")
    if status != 200 or len(token) != 32:
        raise RuntimeError(f"Gen V token request failed for {path}: HTTP {status}")
    digest = hashlib.sha1(SALT5 + token).hexdigest()
    data = encode5(pid, payload)
    status, _, body = http_get(f"{path}?pid={query_pid}&hash={digest}&data={data}", cookie_from(headers))
    if status != 200 or len(body) < 40:
        raise RuntimeError(f"Gen V action failed for {path}: HTTP {status}")
    content, footer = body[:-40], body[-40:]
    expected = hashlib.sha1(SALT5 + base64.urlsafe_b64encode(content) + SALT5).hexdigest().encode()
    if footer != expected:
        raise RuntimeError(f"invalid Gen V response footer for {path}")
    return content


def crypt_words(data: bytes, seed: int) -> bytes:
    output = bytearray(data)
    for offset in range(0, len(output), 2):
        seed = (0x41C64E6D * seed + 0x6073) & 0xFFFFFFFF
        struct.pack_into("<H", output, offset, struct.unpack_from("<H", output, offset)[0] ^ (seed >> 16))
    return bytes(output)


def decrypt_pkm(encrypted: bytes, party_end: int) -> bytes:
    output = bytearray(encrypted)
    pid, checksum = struct.unpack_from("<IxxH", output)
    blocks = [block for block in (crypt_words(output[8:136], checksum)[i:i + 32] for i in range(0, 128, 32))]
    output[8:136] = b"".join(blocks[i] for i in BLOCK_ORDERS[(pid >> 13) & 31])
    output[136:party_end] = crypt_words(output[136:party_end], pid)
    return bytes(output)


def decrypt_pk4(data: bytes) -> bytes:
    return decrypt_pkm(data, 236)


def decrypt_pk5(data: bytes) -> bytes:
    return decrypt_pkm(data, 220)


def encrypt_pk5(decrypted: bytes) -> bytes:
    output = bytearray(decrypted)
    pid = struct.unpack_from("<I", output)[0]
    checksum = sum(struct.unpack("<64H", output[8:136])) & 0xFFFF
    struct.pack_into("<H", output, 6, checksum)
    canonical = [bytes(output[8 + i * 32:40 + i * 32]) for i in range(4)]
    order = BLOCK_ORDERS[(pid >> 13) & 31]
    physical = [b""] * 4
    for canonical_index, physical_index in enumerate(order):
        physical[physical_index] = canonical[canonical_index]
    output[8:136] = crypt_words(b"".join(physical), checksum)
    output[136:220] = crypt_words(output[136:220], pid)
    return bytes(output)


def encoded5(text: str, size: int) -> bytes:
    value = text.encode("utf-16le") + b"\xff\xff"
    if len(value) > size:
        raise ValueError("encoded Gen-V string is too long")
    return value.ljust(size, b"\0")


def build_buizel_offer(template: bytes) -> bytes:
    """Turn a valid returned party record into the requested male Lv30 Buizel."""
    record = bytearray(template)
    pokemon = bytearray(decrypt_pk5(record[:236]))
    personality = 0x501CA4D7
    struct.pack_into("<I", pokemon, 0, personality)
    struct.pack_into("<H", pokemon, 8, 418)       # Buizel
    struct.pack_into("<H", pokemon, 10, 0)        # no held item
    struct.pack_into("<I", pokemon, 16, 27000)    # Medium Fast level 30
    pokemon[20] = 70
    pokemon[21] = 33                               # Swift Swim
    pokemon[23] = 2                                # English
    pokemon[24:30] = bytes(6)                      # no EVs
    struct.pack_into("<4H", pokemon, 40, 55, 98, 129, 453)
    pokemon[48:52] = bytes((25, 30, 20, 20))
    pokemon[52:56] = bytes(4)
    struct.pack_into("<I", pokemon, 56, sum(10 << (5 * n) for n in range(6)))
    pokemon[64] = 0                                # ordinary form, explicitly male
    pokemon[65] = personality % 25
    struct.pack_into("<H", pokemon, 66, 0)
    pokemon[0x48:0x5E] = encoded5("Buizel", 22)
    pokemon[0x68:0x78] = encoded5("AGENT", 16)
    pokemon[136:220] = bytes(84)
    pokemon[140] = 30
    struct.pack_into("<H", pokemon, 142, 76)
    struct.pack_into("<6H", pokemon, 144, 76, 47, 29, 59, 44, 26)
    record[:236] = encrypt_pk5(pokemon)

    struct.pack_into("<HBB", record, 0xEC, 418, 1, 30)
    struct.pack_into("<HBBBB", record, 0xF0, 233, 3, 0, 0, 0)
    record[0xF6] = 1
    struct.pack_into("<QQI", record, 0xF8, 0, 0, 0)
    struct.pack_into("<I", record, 0x10C, struct.unpack_from("<I", pokemon, 12)[0])
    record[0x110:0x120] = encoded5("AGENT", 16)
    record[0x120:0x128] = bytes((187, 0, 0, 0, 21, 2, 8, 0))
    return bytes(record)


def gen4_fragment(record: bytes) -> str:
    field = decrypt_pk4(record[:236])[0x48:0x5E]
    terminator = field.index(b"\xff\xff")
    return field[terminator + 2:].rstrip(b"\0").decode("ascii")


def string5(field: bytes) -> tuple[str, bytes]:
    end = field.index(b"\xff\xff")
    return field[:end].decode("utf-16le"), field[end + 2:]


def search4_instruction() -> str:
    criteria = struct.pack("<hbbbbB", 137, 3, 0, 0, 0, 7)
    found: dict[int, bytes] = {}
    for _ in range(12):
        response = call4(SEARCH4, 0, criteria)
        if len(response) % 292:
            raise RuntimeError("malformed Gen IV search response")
        for offset in range(0, len(response), 292):
            record = response[offset:offset + 292]
            found.setdefault(struct.unpack_from("<I", record, 0x108)[0], record)
        if len(found) == 10:
            break
    if len(found) != 10:
        raise RuntimeError(f"collected {len(found)} of 10 Gen IV clue listings")
    chronological = sorted(found.values(), key=lambda record: struct.unpack_from("<Q", record, 0xF8)[0])
    instruction = "".join(gen4_fragment(record) for record in chronological)
    expected = r"G3N5_BL4CKWH1T3;P0RYG0N2_TR4SH=P1D_L3_X0R_K;K=[0-9A-F]{8}"
    if re.fullmatch(expected, instruction) is None:
        raise RuntimeError(f"unexpected first-stage instruction: {instruction!r}")
    return instruction


def search5(pid: int) -> list[bytes]:
    response = call5(SEARCH5, pid, struct.pack("<HBBBBB", 233, 3, 0, 0, 0, 7))
    if response[:2] != b"\x01\x00" or (len(response) - 2) % 296:
        raise RuntimeError("malformed Gen V search response")
    return [response[offset:offset + 296] for offset in range(2, len(response), 296)]


def main() -> None:
    instruction = search4_instruction()
    key = int(instruction.rsplit("=", 1)[1], 16)

    initial = search5(0)
    genuine: list[tuple[bytes, bytes, str]] = []
    template = None
    for record in initial:
        pk5 = decrypt_pk5(record[:236])
        nickname, trash = string5(pk5[0x48:0x5E])
        if struct.unpack_from("<H", pk5, 8)[0] == 233 and nickname == "Porygon2":
            ot, _ = string5(pk5[0x68:0x78])
            genuine.append((record, trash, ot))
        elif struct.unpack_from("<H", pk5, 8)[0] == 132 and template is None:
            template = record
    genuine.sort(key=lambda item: struct.unpack_from("<Q", item[0], 0xF8)[0])
    if len(genuine) != 3 or template is None:
        raise RuntimeError(f"expected 3 genuine Porygon2 records, got {len(genuine)}")
    trade_instruction = "".join(item[2] for item in genuine)
    if trade_instruction != "0FF3R_MBU1Z3LLv30-40":
        raise RuntimeError(f"unexpected trade instruction: {trade_instruction!r}")

    # PID_LE means: decode the four trash bytes as a little-endian u32, then
    # XOR the numeric key.  These are hidden target-owner PIDs for exchange.asp.
    target_pids = [int.from_bytes(trash, "little") ^ key for _, trash, _ in genuine]
    offer = build_buizel_offer(template)
    chunks = []
    clients = (0x2718D000, 0x2718D001, 0x2718D002)
    for client_pid, target_pid in zip(clients, target_pids):
        search5(client_pid)  # establish the normal pre-exchange search state
        result = call5(EXCHANGE5, client_pid, offer + struct.pack("<I", target_pid) + bytes(132))
        if len(result) != 296:
            raise RuntimeError(f"hidden target {target_pid:08x} returned {result.hex()}")
        pokemon = decrypt_pk5(result[:236])
        nickname, trash = string5(pokemon[0x48:0x5E])
        ot, _ = string5(pokemon[0x68:0x78])
        if struct.unpack_from("<H", pokemon, 8)[0] != 474 or nickname != "PZ" or ot != "P1D_X0R":
            raise RuntimeError(f"unexpected hidden exchange record for {target_pid:08x}")
        returned_pid = struct.unpack_from("<I", pokemon)[0]
        pid_le = struct.pack("<I", returned_pid)
        chunks.append(bytes(value ^ pid_le[i % 4] for i, value in enumerate(trash)))

    flag = b"".join(chunks).rstrip(b"\0").decode("ascii")
    if not flag.startswith("TISC{") or not flag.endswith("}"):
        raise RuntimeError(f"decoded value is not a literal flag: {flag!r}")
    print(f"stage 1: {instruction}")
    print(f"stage 2: {trade_instruction}")
    print("hidden targets: " + ", ".join(f"{pid:08x}" for pid in target_pids))
    print(f"flag: {flag}")


if __name__ == "__main__":
    main()
