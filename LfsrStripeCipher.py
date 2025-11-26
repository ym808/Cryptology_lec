# LfsrStripeCipher.py
from typing import List, Tuple

from LfsrBlock import LfsrBlock
from SymmetricKey import Stripe


def _next_byte(block: LfsrBlock) -> int:
    """
    LfsrBlock에서 8비트 키스트림 바이트 하나 생성
    (bit 8개를 step()으로 얻어서 1바이트로 합침)
    """
    v = 0
    for bit_pos in range(8):
        bit = block.step()          # 0 또는 1
        v |= (bit << (7 - bit_pos)) # MSB부터 채움
    return v & 0xFF


def _build_lfsr_block(seeds: List[int]) -> LfsrBlock:
    """
    seeds 3개로 LfsrBlock 생성 (xor_positions는 고정)
    """
    if len(seeds) != 3:
        raise ValueError("LfsrBlock seeds는 3개여야 합니다.")
    xor1 = [7, 5, 4, 3]
    xor2 = [7, 3, 2, 1]
    xor3 = [7, 6, 5, 0]
    return LfsrBlock(seeds, xor1, xor2, xor3, width=8)


def derive_directional_seeds(base: List[int]) -> Tuple[List[int], List[int]]:
    """
    하나의 base seed 리스트에서 두 방향용 seed 리스트 생성.
      - up_seeds  : A→B 방향
      - down_seeds: B→A 방향
    여기서는 간단히 (down = base ^ 0xFF) 로만 분리.
    """
    up = list(base)
    down = [(s ^ 0xFF) & 0xFF for s in base]
    return up, down


class LfsrStripeCipher:
    """
    한 노드 기준:
      - send_lfsr1, send_lfsr2 : 내가 보낼 때 사용하는 LFSR 블록 2개
      - recv_lfsr1, recv_lfsr2 : 내가 받을 때 사용하는 LFSR 블록 2개

    2바이트 평문 블록 P[0], P[1]에 대해:
      - P[0] : send_lfsr1 에서 나온 ks1 으로 XOR
      - P[1] : send_lfsr2 에서 나온 ks2 으로 XOR

    → Stripe.stripe_encryption(ks1, ks2, P)를 사용
    """

    def __init__(
        self,
        send_lfsr1: LfsrBlock,
        send_lfsr2: LfsrBlock,
        recv_lfsr1: LfsrBlock,
        recv_lfsr2: LfsrBlock,
    ):
        self.send_lfsr1 = send_lfsr1
        self.send_lfsr2 = send_lfsr2
        self.recv_lfsr1 = recv_lfsr1
        self.recv_lfsr2 = recv_lfsr2

    @classmethod
    def from_base_seeds(cls, base_seeds: List[int], role: str) -> "LfsrStripeCipher":
        """
        base_seeds: 길이 6
          [s1, s2, s3, s4, s5, s6]
          → 블록1용 seeds: [s1, s2, s3]
          → 블록2용 seeds: [s4, s5, s6]

        role:
          - "owner" : RSA 키 가진 쪽 (send = up, recv = down)
          - "peer"  : RSA 키 없는 쪽 (send = down, recv = up)
        """
        if len(base_seeds) != 6:
            raise ValueError("base_seeds 길이는 6이어야 합니다. (LfsrBlock 2개 × 3개)")

        up_seeds, down_seeds = derive_directional_seeds(base_seeds)

        up1 = up_seeds[0:3]
        up2 = up_seeds[3:6]
        down1 = down_seeds[0:3]
        down2 = down_seeds[3:6]

        if role == "owner":
            send_lfsr1 = _build_lfsr_block(up1)
            send_lfsr2 = _build_lfsr_block(up2)
            recv_lfsr1 = _build_lfsr_block(down1)
            recv_lfsr2 = _build_lfsr_block(down2)
        elif role == "peer":
            send_lfsr1 = _build_lfsr_block(down1)
            send_lfsr2 = _build_lfsr_block(down2)
            recv_lfsr1 = _build_lfsr_block(up1)
            recv_lfsr2 = _build_lfsr_block(up2)
        else:
            raise ValueError("role은 'owner' 또는 'peer' 여야 합니다.")

        return cls(send_lfsr1, send_lfsr2, recv_lfsr1, recv_lfsr2)

    # ---------- 암호화 / 복호화 ----------

    def encrypt_text(self, text: str) -> bytes:
        """
        문자열을 암호화해서 "프레임"으로 반환.
        프레임 구조:
          [2바이트: 원본 평문 길이] + [암호문(2바이트 Stripe 블록 단위)]

        메시지 바이트 인덱스 기준으로 보면:
          - 1, 3, 5, ... 번째 바이트 → send_lfsr1 키스트림
          - 2, 4, 6, ... 번째 바이트 → send_lfsr2 키스트림
        """
        pt = text.encode("utf-8")
        orig_len = len(pt)

        # Stripe는 2바이트 블록이니까 홀수면 1바이트 패딩
        if orig_len % 2 == 1:
            pt += b"\x00"

        res = bytearray()
        for i in range(0, len(pt), 2):
            block_pt = pt[i:i + 2]  # 길이 2
            ks1 = _next_byte(self.send_lfsr1)
            ks2 = _next_byte(self.send_lfsr2)
            c_block = Stripe.stripe_encryption(ks1, ks2, block_pt)
            res.extend(c_block)

        return orig_len.to_bytes(2, "big") + bytes(res)

    def decrypt_frame_to_text(self, frame: bytes) -> str:
        """
        encrypt_text()로 만들어진 프레임을 복호화해서 문자열로 반환.
        """
        if len(frame) < 2:
            return ""

        orig_len = int.from_bytes(frame[:2], "big")
        ct = frame[2:]

        if len(ct) % 2 != 0:
            return ""

        res = bytearray()
        for i in range(0, len(ct), 2):
            c_block = ct[i:i + 2]  # 길이 2
            ks1 = _next_byte(self.recv_lfsr1)
            ks2 = _next_byte(self.recv_lfsr2)
            p_block = Stripe.stripe_decryption(ks1, ks2, c_block)
            res.extend(p_block)

        pt = bytes(res[:orig_len])
        try:
            return pt.decode("utf-8", errors="ignore")
        except Exception:
            return ""
