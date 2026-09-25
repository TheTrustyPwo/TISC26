#!/usr/bin/env python3
"""Standalone end-to-end solver for the authorized TISC Ransom RPG service."""
import ctypes, os, re, socket, struct, time, sys

HOST, PORT = "chals.tisc26.ctf.sg", 34151
M = 0xFFFFFFFF
PACE = 2.2
ACK = b"You have received the key!"


# Outer transport: each application request gets a short-lived TCP connection.
def step(s):
    t = (s[3] ^ (s[3] << 11)) & M
    v = (s[0] ^ (s[0] >> 19) ^ t ^ (t >> 8)) & M
    s[:] = [v, s[0], s[1], s[2]]
    return v


def stream(s, n):
    o = bytearray()
    while len(o) < n:
        o += struct.pack("<I", step(s))
    return bytes(o[:n])


def state(p):
    lo, hi = struct.unpack("<II", p)
    s = [
        (0x6C0A3E17 ^ 0x9E3779B9) ^ lo,
        ((0x2F91C4B5 + 0x517CC1B7) & M) ^ hi,
        0x813D5A29 ^ 0x85EBCA6B,
        (0x4E7F02D3 - 0x3D4D51CB) & M,
    ]
    if not any(s):
        s[0] = 0x9E3779B9
    for _ in range(16):
        step(s)
    return s


def xo(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def send(plain):
    p = os.urandom(8)
    w = p + xo(plain, stream(state(p), len(plain)))
    raw = bytearray()
    with socket.create_connection((HOST, PORT), timeout=8) as x:
        x.sendall(w)
        # The service may take longer than a single TCP round trip to frame a
        # handshake response.  This matches the recovered client transport.
        x.settimeout(3)
        while 1:
            try:
                q = x.recv(4096)
            except socket.timeout:
                break
            if not q:
                break
            raw += q
    # Handshake replies are unframed 37-byte records. Console/proof replies
    # are length-prefixed, so callers explicitly use frame_body for them.
    return xo(raw, stream(state(p), len(plain) + len(raw))[len(plain) :])


def frame_body(decoded):
    if len(decoded) < 4:
        return b""
    length = struct.unpack_from("<I", decoded)[0]
    return decoded[4 : 4 + length]


def handshake_error(reply):
    """Return the server's explicit handshake rejection, if present."""
    if reply[:1] == b"\0" and len(reply) >= 5:
        length = struct.unpack_from("<I", reply, 1)[0]
        return reply[5 : 5 + length].decode("utf-8", "replace")
    return None


# Exact 90-byte attestation reconstructed from the client binary.
def rol(v, n, w):
    n %= w
    return ((v << n) | (v >> (w - n))) & ((1 << w) - 1)


def sign(v, w):
    v &= (1 << w) - 1
    return v - (1 << w) if v & (1 << (w - 1)) else v


def attest(c):
    o = bytearray()
    for w in (8, 16, 32, 64):
        m = (1 << w) - 1
        v = c & m
        for _ in range(100):
            z = sum(
                rol(((v >> (8 * i)) & 255) ^ ((0x5A * i) & 255), 3, 8) << (8 * i)
                for i in range(w // 8)
            )
            v = (z * (0x9E3779B9 & m) + 1) & m
        x = v.to_bytes(w // 8, "little")
        o += x + x
    for w, k in ((8, 0xEF), (16, 0xBEEF)):
        v = c & ((1 << w) - 1)
        for _ in range(100):
            v ^= k
        x = v.to_bytes(w // 8, "little")
        o += x + x
    f = struct.unpack("<f", struct.pack("<I", c & M))[0]
    k = struct.unpack("<f", struct.pack("<I", 0x3F800347))[0]
    for _ in range(100):
        f = ctypes.c_float(f * k).value
    x = struct.pack("<f", f)
    o += x + x
    d = struct.unpack("<d", struct.pack("<Q", c))[0]
    k = struct.unpack("<d", bytes.fromhex("9bf2d71a0000f03f"))[0]
    for _ in range(100):
        d *= k
    x = struct.pack("<d", d)
    o += x + x
    for w in (8, 16, 32, 64):
        m = (1 << w) - 1
        k = {8: 0xEF, 16: 0xBEEF, 32: 0x1337BEEF, 64: 0x1337BEEF}[w]
        u = v = c & m
        for _ in range(100):
            u = (rol(u, w // 2, w) ^ k) & m
            v = ((sign(v, w) >> (w // 2)) ^ (v << (w // 2)) ^ k) & m
        o += u.to_bytes(w // 8, "little") + v.to_bytes(w // 8, "little")
    assert len(o) == 90
    return bytes(o)


# MT19937 and the client's 100-swap map permutation.
class MT:
    def __init__(s, x):
        s.a = [x & M] + [0] * 623
        s.i = 624
        for i in range(1, 624):
            s.a[i] = (0x6C078965 * (s.a[i - 1] ^ (s.a[i - 1] >> 30)) + i) & M

    def next(s):
        if s.i >= 624:
            for i in range(624):
                y = (s.a[i] & 0x80000000) | (s.a[(i + 1) % 624] & 0x7FFFFFFF)
                s.a[i] = s.a[(i + 397) % 624] ^ (y >> 1) ^ (0x9908B0DF if y & 1 else 0)
            s.i = 0
        y = s.a[s.i]
        s.i += 1
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        return (y ^ (y >> 18)) & M


def route(seed):
    mt = MT(seed)
    slots = list(range(17))
    maps = []
    for _ in range(64):
        for _ in range(100):
            a = (mt.next() * 17) >> 32
            b = (mt.next() * 17) >> 32
            if a != b:
                slots[a], slots[b] = slots[b], slots[a]
        maps.append(slots.copy())
    a = []
    visit = 0

    def world(n):
        nonlocal visit
        a.append(maps[visit].index(n))
        visit += 1

    def add(*x):
        a.extend(x)

    world(4)
    add(1, 0, 0, 0)
    world(0)
    world(0)
    world(4)
    add(1, 0, 0, 0)
    for _ in range(4):
        world(0)
    add(2, 0)
    for i in range(3):
        world(6)
        add(2, 2)
        if i != 2:
            world(0)
    for _ in range(4):
        world(0)
    add(2, 0)
    world(6)
    add(2, 2)
    world(0)
    world(6)
    add(2, 2)
    for _ in range(4):
        world(0)
    add(100, 1, 0)
    world(7)
    add(3, 1, 3, 1, 3, 1, 3, 1, 3)
    for _ in range(3):
        world(15)
        add(2)
    world(3)
    add(2)
    for _ in range(4):
        world(0)
    add(100, 100, 1, 2, 0)
    world(2)
    add(3)
    world(13)
    add(3)
    for _ in range(4):
        world(8)
        add(0)
    assert len(a) == 88
    return a


def proof(pair, seed, blob, actions):
    raw = struct.pack("<%dI" % len(actions), *actions)
    d = 0
    for x in struct.pack("<QQ", *pair):
        d ^= x
    d = d or 0x7A
    r = seed
    e = bytearray()
    for i, x in enumerate(raw):
        e.append(x ^ ((r + i) & 255))
        r = ((r ^ x) + d) & M
    count = struct.pack("<I", len(actions))
    covered = struct.pack("<QQ", *pair) + count + e
    h = 5381
    for x in covered:
        h = (h * 33 + x) & M
    return b"\3" + struct.pack("<I", h) + struct.pack("<QQ", *pair) + blob + count + e


def command(pair, text):
    return b"\4" + struct.pack("<QQ", *pair) + text.encode("ascii").ljust(256, b"\0")


def main():
    for _ in range(40):
        hello = send(b"\1")
        if len(hello) == 37 and hello[0] == 1:
            break
        error = handshake_error(hello)
        if error:
            raise RuntimeError(f"handshake rejected by server: {error}")
        time.sleep(3)
    else:
        raise RuntimeError("handshake was not accepted")
    _, x, y, seed, challenge, _ = struct.unpack("<BQQIQQ", hello)
    pair = x, y
    time.sleep(PACE)
    if frame_body(send(proof(pair, seed, attest(challenge), route(seed)))) != ACK:
        raise RuntimeError("88-action ACK failed")
    # ``--console`` is the standalone ACK helper mode: retain this live pair
    # and let the operator issue post-victory console commands manually.
    if "--console" in sys.argv:
        print("You have received the key!  Type exit to leave locally.")
        while 1:
            try:
                text = input("Enter command: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if text == "exit":
                return
            if text:
                time.sleep(PACE)
                print(frame_body(send(command(pair, text))).decode("utf-8", "replace"))

    def run(text, expect=None):
        time.sleep(PACE)
        body = frame_body(send(command(pair, text)))
        print(text + ":", body.decode("utf-8", "replace"))
        if expect is not None and body != expect:
            raise RuntimeError("unexpected reply to " + text)
        return body

    ok = b"Login successful."
    run("login priya.nandakumar elena.vasquez", ok)
    run(
        "reset_passwrd adrian.osei lastsolveadrian",
        b"Password updated for adrian.osei.",
    )
    run("login adrian.osei lastsolveadrian", ok)
    if b"sentinel_auth.cpp" not in run("source_list"):
        raise RuntimeError("source list changed")
    m = re.search(
        rb'kTestVerificationCode\s*=\s*"([^" ]+)"', run("source_dump sentinel_auth.cpp")
    )
    if not m:
        raise RuntimeError("verification code absent")
    run("login priya.nandakumar elena.vasquez", ok)
    run(
        "reset_passwrd marcus.webb lastsolvemarcus",
        b"Password updated for marcus.webb.",
    )
    if b"Use: vault <code>" not in run("login marcus.webb lastsolvemarcus"):
        raise RuntimeError("Marcus 2FA state absent")
    m = re.search(rb"TISC\{[^}\r\n]+\}", run("vault " + m.group(1).decode()))
    if not m:
        raise RuntimeError("literal flag absent")
    print("\nFLAG:", m.group().decode())


if __name__ == "__main__":
    main()
