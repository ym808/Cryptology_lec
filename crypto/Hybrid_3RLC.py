# crypto/Hybrid_3RLC.py
from typing import Tuple
from crypto.LfsrBlock import LfsrBlock


class Hybrid_3RLC:
    """
    LFSR 블록 2개로 짝/홀 인덱스에 따라 XOR만 수행하는 스트림 암호 레이어.
    """

    def __init__(self, lfsr_even: LfsrBlock, lfsr_odd: LfsrBlock) -> None:
        self.lfsr_even = lfsr_even
        self.lfsr_odd = lfsr_odd

    def encrypt_split(self, msg: bytes) -> Tuple[bytes, bytes]:
        """
        평문 msg 를 LFSR 키스트림과 XOR 하여
        짝수/홀수 인덱스별로 분리된 바이트열을 반환한다.
        """
        even_stream = bytearray()
        odd_stream = bytearray()

        for i, m in enumerate(msg):
            if i % 2 == 0:
                ks = self.lfsr_even.generate_key()
                even_stream.append(m ^ ks)
            else:
                ks = self.lfsr_odd.generate_key()
                odd_stream.append(m ^ ks)

        return bytes(even_stream), bytes(odd_stream)

    def decrypt_merge(self, even_stream: bytes, odd_stream: bytes) -> bytes:
        """
        RSA 복호까지 끝난 짝/홀 스트림(even_stream, odd_stream)을 받아
        LFSR 키스트림과 다시 XOR 하고,
        원래 인덱스 순서대로 재조합하여 평문을 복원한다.
        """
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
