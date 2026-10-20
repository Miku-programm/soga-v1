"""Independent Python peer, transcribed from static framing evidence.

Does not invoke the original binary or Go reconstruction as a subprocess.
Uses Python hashlib/HMAC and cryptography AEAD, not the Go codec.
"""
import hashlib
import hmac
import os
import socket
import struct
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

address, method, password, mode = sys.argv[1:]
mode = int(mode)
domain = bytes.fromhex("d8b8c066c10e8b0d1b1ba3ad1f7de1525625d03f9d9f682f1bd6097b13a22b38")
keylen = {"aes-128-gcm": 16, "aes-192-gcm": 24, "aes-256-gcm": 32, "chacha20-ietf-poly1305": 32}[method]
master = hashlib.sha3_512(password.encode()).digest()[:keylen]

def derive(secret, salt, info, n):
    prk = hmac.new(salt, secret, hashlib.sha3_512).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha3_512).digest()[:n]

verify = derive(master, domain, password.encode(), 16)
host, port = address.rsplit(":", 1)
s = socket.create_connection((host, int(port)), timeout=10)

def read_exact(n):
    out = bytearray()
    while len(out) < n:
        part = s.recv(n-len(out))
        if not part:
            raise EOFError("truncated tunnel")
        out.extend(part)
    return bytes(out)

class Direction:
    def __init__(self, nonce):
        key = derive(master, nonce, domain, keylen)
        self.aead = ChaCha20Poly1305(key) if method.startswith("chacha") else AESGCM(key)
        self.nonce = int.from_bytes(nonce, "little")
        self.shake = hashlib.shake_128(nonce+key)
        self.offset = 0

    def next_nonce(self):
        n = self.nonce.to_bytes(12, "little")
        self.nonce = (self.nonce+1) % (1 << 96)
        return n

    def number(self):
        self.offset += 2
        return int.from_bytes(self.shake.digest(self.offset)[-2:], "big")

salt = os.urandom(12)
writer = Direction(salt)
reader = None
pending = bytearray()

def send(data, fragment=False):
    global salt
    while data:
        pad = writer.number() % 128
        n = min(len(data), 65535-pad)
        header = struct.pack("!H", (n+pad) ^ writer.number())
        packet = salt + writer.aead.encrypt(writer.next_nonce(), header, None)
        packet += writer.aead.encrypt(writer.next_nonce(), data[:n]+os.urandom(pad), None)
        salt = b""
        if fragment:
            # Cross both the salt and ciphertext boundaries with short writes.
            for b in packet[:25]:
                s.sendall(bytes([b]))
            s.sendall(packet[25:])
        else:
            s.sendall(packet)
        data = data[n:]

def recv(n):
    global reader, pending
    if reader is None:
        reader = Direction(read_exact(12))
    while len(pending) < n:
        header = reader.aead.decrypt(reader.next_nonce(), read_exact(18), None)
        pad = reader.number() % 128
        size = int.from_bytes(header, "big") ^ reader.number()
        assert size >= pad
        body = reader.aead.decrypt(reader.next_nonce(), read_exact(size+16), None)
        pending.extend(body[:size-pad])
    out = bytes(pending[:n])
    del pending[:n]
    return out

send(verify+bytes([mode]), True)
for n in (1, 700, 32768, 65535):
    payload = bytes((i % 251 for i in range(n)))
    send((struct.pack("!H", n) if mode == 2 else b"") + payload)
    if mode == 2:
        assert int.from_bytes(recv(2), "big") == n
    assert recv(n) == payload
s.close()
print("PASS independent Python", method, mode)
