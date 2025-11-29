from typing import Tuple
from crypto.RSA import RSA3P          # or RSA2P
from crypto.LfsrBlock import LfsrBlock


class Hybrid_3RLC:

    def __init__(
        self,
        lfsr_even: LfsrBlock,   # 짝수 바이트용
        lfsr_odd: LfsrBlock,    # 홀수 바이트용
    ):
        self.lfsr_even = lfsr_even
        self.lfsr_odd = lfsr_odd

    def encrypt(self, msg: bytes) -> bytes:
        res = bytearray()
        for i, m in enumerate(msg):        # 항상 길이 2

            if i % 2 == 0:  # 짝수 인덱스
                ks1 = self.lfsr_even.generate_key()
                c = m ^ ks1
            else:  # 홀수 인덱스
                ks2 = self.lfsr_odd.generate_key()
                c = m ^ ks2
            res.append(c)

        return bytes(res)

    def decrypt(self, cipher: bytes) -> bytes:
        res = bytearray()

        for i, c in enumerate(cipher):
            if i % 2 == 0:
                ks1 = self.lfsr_even.generate_key()
                m = c ^ ks1
            else:
                ks2 = self.lfsr_odd.generate_key()
                m = c ^ ks2
            res.append(m)

        return bytes(res)
