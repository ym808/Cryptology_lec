from typing import Sequence, List
from sympy.ntheory.modular import crt


class LfsrBlock:
    def __init__(
        self,
        seeds: Sequence[int],          # [seed1, seed2, seed3]
        xor_positions1: Sequence[int], # LFSR1 XOR 위치 리스트
        xor_positions2: Sequence[int], # LFSR2 XOR 위치 리스트
        xor_positions3: Sequence[int], # LFSR3 XOR 위치 리스트
        width: int = 8                 # 기본 8비트
    ):
        if len(seeds) != 3:
            raise ValueError("seeds는 [lfsr1, lfsr2, lfsr3] 3개가 필요합니다.")

        self.width = width
        self.mask = (1 << width) - 1

        self.lfsr1 = seeds[0] & self.mask
        self.lfsr2 = seeds[1] & self.mask
        self.lfsr3 = seeds[2] & self.mask

        self.xor_positions1 = list(xor_positions1)
        self.xor_positions2 = list(xor_positions2)
        self.xor_positions3 = list(xor_positions3)

    def shift(self, lfsr: int, xor_positions: List[int]) -> (int, int):
        out_bit = lfsr & 1

        fb = 0
        for pos in xor_positions:
            fb ^= (lfsr >> pos) & 1

        # 오른쪽 시프트
        lfsr >>= 1
        lfsr |= fb << (self.width - 1)
        lfsr &= self.mask

        return lfsr, out_bit

    def generate_key(self) -> int:

        out1 = 0
        out2 = 0
        out3 = 0

        # 8비트 뽑기
        for _ in range(8):
            self.lfsr1, r1 = self.shift(self.lfsr1, self.xor_positions1)
            self.lfsr2, r2 = self.shift(self.lfsr2, self.xor_positions2)
            self.lfsr3, r3 = self.shift(self.lfsr3, self.xor_positions3)

            out1 = ((out1 << 1) | r1) & self.mask
            out2 = ((out2 << 1) | r2) & self.mask
            out3 = ((out3 << 1) | r3) & self.mask

        # CRT 결합 → 키 1바이트
        moduli = [101, 103, 107]

        outs = [out1, out2, out3]
        result, _ = crt(moduli, outs)
        key = int(result % 256)

        # 마지막 r1에 따라 다음 문자용 상태를 비선형 업데이트
        if (out1 & 1) == 1:
            # r1 == 1 → LFSR2: 2bit, LFSR3: 1bit 시프트
            self.lfsr2, _ = self.shift(self.lfsr2, self.xor_positions2)
            self.lfsr2, _ = self.shift(self.lfsr2, self.xor_positions2)
            self.lfsr3, _ = self.shift(self.lfsr3, self.xor_positions3)
        else:
            # r1 == 0 → LFSR3: 2bit, LFSR2: 1bit 시프트
            self.lfsr3, _ = self.shift(self.lfsr3, self.xor_positions3)
            self.lfsr3, _ = self.shift(self.lfsr3, self.xor_positions3)
            self.lfsr2, _ = self.shift(self.lfsr2, self.xor_positions2)

        return key

    def encrypt_byte(self, m: int) -> int:
        k = self.generate_key()
        return k^m

    def decrypt_byte(self, c: int) -> int:
        k = self.generate_key()
        return k ^ c