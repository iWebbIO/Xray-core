"""Independent native 1-RTT fixtures; run manually, never at runtime/build time.

Requires cryptography >= 50 (OpenSSL ML-KEM-768) and blake3 for the oracle checks.
The binary-context BLAKE3 reference below uses recursive tree construction,
independent of derive.rs's streaming stack. All DH/ML-KEM/AEAD operations come
from OpenSSL via cryptography, not from the Rust implementation under test.

Encapsulation uses fresh OpenSSL randomness, so regenerating changes the server
flight. Both fixtures retain their fixed client entropy offsets and known keys.
"""

import json
import struct
from pathlib import Path

import blake3
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]


def compress(output, root=False):
    cv, message, counter, length, flags = output
    if root:
        flags |= 8
        counter = 0
    v = list(cv) + IV[:4] + [counter & 0xFFFFFFFF, counter >> 32, length, flags]
    m = list(message)

    def rotate(x, n):
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    def g(a, b, c, d, x, y):
        v[a] = (v[a] + v[b] + x) & 0xFFFFFFFF
        v[d] = rotate(v[d] ^ v[a], 16)
        v[c] = (v[c] + v[d]) & 0xFFFFFFFF
        v[b] = rotate(v[b] ^ v[c], 12)
        v[a] = (v[a] + v[b] + y) & 0xFFFFFFFF
        v[d] = rotate(v[d] ^ v[a], 8)
        v[c] = (v[c] + v[d]) & 0xFFFFFFFF
        v[b] = rotate(v[b] ^ v[c], 7)

    for _ in range(7):
        g(0, 4, 8, 12, m[0], m[1])
        g(1, 5, 9, 13, m[2], m[3])
        g(2, 6, 10, 14, m[4], m[5])
        g(3, 7, 11, 15, m[6], m[7])
        g(0, 5, 10, 15, m[8], m[9])
        g(1, 6, 11, 12, m[10], m[11])
        g(2, 7, 8, 13, m[12], m[13])
        g(3, 4, 9, 14, m[14], m[15])
        m = [m[i] for i in PERM]
    return [v[i] ^ v[i + 8] for i in range(8)]


def b3(data, key=IV, flags=0):
    chunks = [data[i:i + 1024] for i in range(0, len(data), 1024)] or [b""]

    def leaf(data, counter):
        blocks = [data[i:i + 64] for i in range(0, len(data), 64)] or [b""]
        cv = key
        for i, block in enumerate(blocks):
            extra = (1 if i == 0 else 0) | (2 if i == len(blocks) - 1 else 0)
            output = cv, struct.unpack("<16I", block.ljust(64, b"\0")), counter, len(block), flags | extra
            if i == len(blocks) - 1:
                return output
            cv = compress(output)

    def subtree(start, count):
        if count == 1:
            return leaf(chunks[start], start)
        left_size = 1 << ((count - 1).bit_length() - 1)
        left = compress(subtree(start, left_size))
        right = compress(subtree(start + left_size, count - left_size))
        return key, left + right, 0, 64, flags | 4

    return struct.pack("<8I", *compress(subtree(0, len(chunks)), root=True))


def derive(context, material):
    key = struct.unpack("<8I", b3(context, flags=32))
    return b3(material, key, 64)


def verify_reference():
    for length in [0, 1, 63, 64, 65, 1023, 1024, 1025, 2048, 3072, 8192, 16645]:
        binary = bytes(i % 251 for i in range(length))
        assert b3(binary) == blake3.blake3(binary).digest()
        text = "c" * length
        assert derive(text.encode(), binary) == blake3.blake3(binary, derive_key_context=text).digest()


def fixture(cipher_type, relay_count=1):
    iv = bytes(range(16))
    offset = 16
    statics = [X25519PrivateKey.from_private_bytes(bytes([0x11 * (i + 1)] * 32)) for i in range(relay_count)]
    relays = b""
    previous_ctr = None
    for i, static in enumerate(statics):
        nfs_private = X25519PrivateKey.from_private_bytes(bytes(range(offset, offset + 32)))
        offset += 32
        share = nfs_private.public_key().public_bytes_raw()
        nfs_key = nfs_private.exchange(static.public_key())
        if previous_ctr is not None:
            share = previous_ctr.update(share)
        relays += share
        if i + 1 < len(statics):
            previous_ctr = Cipher(algorithms.AES(derive(b"VLESS", nfs_key)), modes.CTR(iv)).encryptor()
            next_hash = blake3.blake3(statics[i + 1].public_key().public_bytes_raw()).digest()
            relays += previous_ctr.update(next_hash)
    ephemeral_mlkem = MLKEM768PrivateKey.from_seed_bytes(bytes(range(offset, offset + 64)))
    offset += 64
    ephemeral_x = X25519PrivateKey.from_private_bytes(bytes(range(offset, offset + 32)))
    client_share = ephemeral_mlkem.public_key().public_bytes_raw() + ephemeral_x.public_key().public_bytes_raw()
    nfs = cipher_type(derive(iv, nfs_key))
    nonce = lambda counter: counter.to_bytes(12, "big")
    client_hello = iv + relays
    client_hello += nfs.encrypt(nonce(1), struct.pack(">H", 1232), None)
    client_hello += nfs.encrypt(nonce(2), client_share, None)
    client_hello += nfs.encrypt(nonce(3), struct.pack(">H", 93), None)
    client_hello += nfs.encrypt(nonce(4), bytes(77), None)

    mlkem_key, mlkem_ciphertext = ephemeral_mlkem.public_key().encapsulate()
    assert ephemeral_mlkem.decapsulate(mlkem_ciphertext) == mlkem_key
    server_x = X25519PrivateKey.from_private_bytes(bytes(range(192, 224)))
    x_key = server_x.exchange(ephemeral_x.public_key())
    assert ephemeral_x.exchange(server_x.public_key()) == x_key
    server_share = mlkem_ciphertext + server_x.public_key().public_bytes_raw()
    united = mlkem_key + x_key + nfs_key
    client_direction = cipher_type(derive(client_share, united))
    server_direction = cipher_type(derive(server_share, united))
    ticket = bytes(2) + bytes(range(2, 16))
    server_hello = nfs.encrypt(bytes([255] * 12), server_share, None)
    server_hello += server_direction.encrypt(nonce(1), ticket, None)
    server_hello += server_direction.encrypt(nonce(2), struct.pack(">H", 93), None)
    server_hello += server_direction.encrypt(nonce(3), bytes(77), None)

    def record(cipher, counter, payload):
        header = bytes([23, 3, 3]) + struct.pack(">H", len(payload) + 16)
        return header + cipher.encrypt(nonce(counter), payload, header)

    return {name: value.hex() for name, value in {
        "client_hello": client_hello,
        "server_hello": server_hello,
        "uplink": record(client_direction, 1, b"fixture uplink"),
        "downlink": record(server_direction, 4, b"fixture downlink"),
    }.items()}


if __name__ == "__main__":
    verify_reference()
    for name, cipher, count in [("native_aes", AESGCM, 1), ("native_chacha", ChaCha20Poly1305, 1), ("relay_aes", AESGCM, 2)]:
        target = Path(__file__).with_name(name + ".json")
        target.write_text(json.dumps(fixture(cipher, count), indent=2) + "\n", encoding="utf-8")
        print(name + ": independent OpenSSL ML-KEM/X25519/AEAD fixture generated")
