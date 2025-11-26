from typing import Sequence, List


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
        """
        한 스텝 시프트 + 피드백 XOR 계산
        """
        # 출력 비트 (LSB)
        out_bit = lfsr & 1

        # XOR 피드백 계산
        fb = 0
        for pos in xor_positions:
            fb ^= (lfsr >> pos) & 1

        # 오른쪽 시프트 후 MSB에 fb 삽입
        lfsr >>= 1
        lfsr |= (fb << (self.width - 1))
        lfsr &= self.mask

        return lfsr, out_bit

    def step(self) -> int:
        """
        1 → 항상 시프트
        2/3 → r1에 따라 조건 시프트
        최종 출력: r1 ^ r2 ^ r3
        """
        self.lfsr1, r1 = self.shift(self.lfsr1, self.xor_positions1)

        if r1 == 1:
            self.lfsr2, r2 = self.shift(self.lfsr2, self.xor_positions2)
            r3 = self.lfsr3 & 1
        else:
            self.lfsr3, r3 = self.shift(self.lfsr3, self.xor_positions3)
            r2 = self.lfsr2 & 1

        return r1 ^ r2 ^ r3
