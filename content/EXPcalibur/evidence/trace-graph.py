"""Read-only caller/generated graph and bound-digest audit at first PEX."""

import gdb
import hashlib
import os
from pathlib import Path


gdb.execute("set pagination off")
gdb.execute("set confirm off")
gdb.execute("set style enabled off")
gdb.execute("starti")
exe = Path(gdb.current_progspace().filename).resolve()
pid = gdb.selected_inferior().pid
base = min(
    int(line.split("-")[0], 16)
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines()
    if str(exe) in line
)
inferior = gdb.selected_inferior()
active = {}


def reg(name):
    return int(gdb.parse_and_eval("$" + name)) & 0xFFFFFFFFFFFFFFFF


def memory(address, size):
    try:
        return bytes(inferior.read_memory(address, size))
    except gdb.MemoryError:
        return b""


class Pex(gdb.Breakpoint):
    def stop(self):
        if active:
            return False
        request = reg("rdx")
        active.update(
            device=reg("rdi"),
            banks=reg("r8"),
            bank=memory(request + 0x11, 1)[0],
            request=memory(request, 0x40),
        )
        return False


class Built(gdb.Breakpoint):
    def stop(self):
        if not active:
            return False
        stack = reg("rsp")
        caller = memory(active["banks"] + active["bank"] * 0x400, 0x400)
        generated = memory(stack + 0x1F8, 0x400)
        digest_ptr = int.from_bytes(memory(stack + 0x36EA0, 8), "little")
        tag = os.environ.get("TRACE_TAG", "pex")
        output = Path("evidence")
        output.mkdir(parents=True, exist_ok=True)
        (output / f"{tag}-caller.bin").write_bytes(caller)
        (output / f"{tag}-generated.bin").write_bytes(generated)
        print(
            "PEX_GRAPH",
            "tag", tag,
            "request64", active["request"].hex(),
            "tokens128", memory(active["device"] + 0x1200, 0x80).hex(),
            "caller_sha256", hashlib.sha256(caller).hexdigest(),
            "generated_sha256", hashlib.sha256(generated).hexdigest(),
            "bound_sha256", memory(digest_ptr, 32).hex(),
        )
        for offset in range(0, 0x400, 4):
            before = caller[offset:offset + 4]
            after = generated[offset:offset + 4]
            if before != after:
                print(
                    "PEX_GRAPH_DIFF",
                    "tag", tag,
                    "offset", f"0x{offset:x}",
                    "caller", before.hex(),
                    "generated", after.hex(),
                )
        gdb.execute("quit")
        return False


Pex(f"*{base + 0x8BF60:#x}", internal=True)
Built(f"*{base + 0x8C5AD:#x}", internal=True)
gdb.execute("continue")
