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

    def encrypt_split(self, msg: bytes) -> Tuple[bytes, bytes]:

        even_stream = bytearray()
        odd_stream = bytearray()

        for i, m in enumerate(msg):
            if i % 2 == 0:  # 짝수 인덱스
                ks = self.lfsr_even.generate_key()
                even_stream.append(m ^ ks)
            else:           # 홀수 인덱스
                ks = self.lfsr_odd.generate_key()
                odd_stream.append(m ^ ks)

        return bytes(even_stream), bytes(odd_stream)

    def decrypt_merge(self, even_stream: bytes, odd_stream: bytes) -> bytes:

        plain = bytearray()
        i_even = 0
        i_odd = 0

        total_len = len(even_stream) + len(odd_stream)

        for i in range(total_len):
            if i % 2 == 0:
                c = even_stream[i_even]
                i_even += 1
                ks = self.lfsr_even.generate_key()
            else:
                c = odd_stream[i_odd]
                i_odd += 1
                ks = self.lfsr_odd.generate_key()

            plain.append(c ^ ks)

        return bytes(plain)