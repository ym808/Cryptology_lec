# communication.py
from dataclasses import dataclass
import secrets
from crypto.RSA import RSA3P
from crypto.LfsrBlock import LfsrBlock
from crypto.Hybrid_3RLC import Hybrid_3RLC


XOR_POS1 = [0, 3, 5]
XOR_POS2 = [0, 2, 6]
XOR_POS3 = [0, 1, 4]


def split_24bit(seed_24: int) -> list[int]:
    return [(seed_24 >> 16) & 0xFF,
            (seed_24 >> 8) & 0xFF,
            seed_24 & 0xFF]


def build_cipher(seed_even: int, seed_odd: int) -> Hybrid_3RLC:
    L_even = LfsrBlock(split_24bit(seed_even), XOR_POS1, XOR_POS2, XOR_POS3)
    L_odd  = LfsrBlock(split_24bit(seed_odd),  XOR_POS1, XOR_POS2, XOR_POS3)
    return Hybrid_3RLC(L_even, L_odd)


@dataclass
class Receiver:
    rsa: RSA3P
    cipher: Hybrid_3RLC = None

    @property
    def public_key(self):
        return (self.rsa.N, self.rsa.e)

    def receive_seeds(self, enc_seed: int):
        M = self.rsa.decryption(enc_seed)
        seed_even = (M >> 24) & ((1 << 24) - 1)
        seed_odd = M & ((1 << 24) - 1)
        self.cipher = build_cipher(seed_even, seed_odd)

    def decrypt(self, cipher: bytes) -> bytes:
        return self.cipher.decrypt(cipher)


@dataclass
class Sender:
    seed_even: int
    seed_odd: int
    cipher: Hybrid_3RLC

    @classmethod
    def init(cls, public_key):
        N, e = public_key
        seed_even = secrets.randbits(24)
        seed_odd = secrets.randbits(24)

        M = (seed_even << 24) | seed_odd
        enc_seed = pow(M, e, N)

        return cls(seed_even, seed_odd, build_cipher(seed_even, seed_odd)), enc_seed

    def encrypt(self, msg: bytes) -> bytes:
        return self.cipher.encrypt(msg)
