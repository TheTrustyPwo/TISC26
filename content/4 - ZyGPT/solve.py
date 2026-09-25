"""Recover ZyGPT's authenticated flag from the challenge and Qwen3-1.7B weights.

Usage: python solve.py [--model PATH] [--baseline DIRECTORY]
Dependencies: numpy, cryptography. No model inference or GPU required.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEFAULT = Path(__file__).resolve().parent
SIGNATURE = [361, 553, 1152, 1289, 2014, 2039]
CHECKS = [959, 1864]


def load_tensors(path):
    with path.open('rb') as file:
        length = struct.unpack('<Q', file.read(8))[0]
        header = json.loads(file.read(length))
    return {
        name: np.memmap(path, mode='r', dtype='<u2',
                        offset=8 + length + spec['data_offsets'][0],
                        shape=tuple(spec['shape']))
        for name, spec in header.items()
        if name != '__metadata__' and spec['dtype'] == 'BF16'
    }


def as_float(words):
    return (np.asarray(words, dtype=np.uint32) << 16).view(np.float32)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model', type=Path, default=DEFAULT / 'model/model.safetensors')
    parser.add_argument('--baseline', type=Path, default=DEFAULT / 'baseline')
    args = parser.parse_args()
    challenge = load_tensors(args.model)
    baseline = {}
    for path in args.baseline.glob('*.safetensors'):
        baseline.update(load_tensors(path))
    embedding = challenge['model.embed_tokens.weight']
    original = baseline['model.embed_tokens.weight']

    records = []
    for token_id, row in enumerate(embedding):
        blob = struct.pack('>I', token_id) + row[SIGNATURE].astype('<u2').tobytes()
        check = bytes(int(row[coord]) & 255 for coord in CHECKS)
        if hashlib.sha256(blob).digest()[:2] == check and np.any(row != original[token_id]):
            records.append((token_id, blob))
    print(f'Found {len(records)} modified, checksum-valid records.')

    # Genuine records share a rank-one additive change to their factory embeddings.
    # Decoys are random or have extra noise in their direction. Mask record words.
    ids = [token_id for token_id, _ in records]
    delta = as_float(embedding[ids]).astype(np.float64) - as_float(original[ids])
    delta[:, SIGNATURE + CHECKS] = 0
    delta /= np.linalg.norm(delta, axis=1)[:, None]
    similarity = delta @ delta.T
    np.fill_diagonal(similarity, -1)
    live = [record for i, record in enumerate(records) if similarity[i].max() > 0.99999]
    print('Live record IDs:', [token_id for token_id, _ in live])
    km = hashlib.sha256(b''.join(sorted(blob for _, blob in live))).digest()[:16]
    key = hashlib.sha256(km + b'\x00').digest()
    seed = hashlib.sha256(km + b'\x01').digest()

    for name in sorted(challenge):
        if '.mlp.' not in name:
            continue
        base = baseline[name].ravel()
        leaked = challenge[name].ravel()
        exponent = (base >> 7) & 255
        eligible = np.flatnonzero((exponent != 0) & (exponent != 255))
        # Preserve first occurrence order while deduplicating the SHAKE stream.
        count = 1024
        while True:
            stream = hashlib.shake_256(seed).digest(8 * count)
            chunks = np.frombuffer(stream, dtype='>u8') % len(eligible)
            _, first = np.unique(chunks, return_index=True)
            if len(first) >= 608:
                break
            count *= 2
        positions = eligible[chunks[np.sort(first)[:608]].astype(np.int64)]
        wire = np.packbits(((base[positions] ^ leaked[positions]) & 1).astype('u1')).tobytes()
        try:
            plaintext = AESGCM(key).decrypt(wire[:12], wire[12:], None)
        except Exception:
            continue
        flag = plaintext.rstrip(b'\x00').decode('ascii')
        result = {'flag': flag, 'carrier': name, 'live_ids': [i for i, _ in live],
                  'KM': km.hex(), 'wire': wire.hex(), 'authenticated': True}
        Path('verified_solution.json').write_text(json.dumps(result, indent=2) + '\n')
        print('Authenticated carrier:', name)
        print(flag)
        return
    raise RuntimeError('No carrier authenticated; verify the checkpoint versions.')


if __name__ == '__main__':
    main()
