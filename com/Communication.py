# Communication.py
import secrets
import os
from crypto.RSA import RSA3P
from crypto.LfsrBlock import LfsrBlock
from crypto.Hybrid_3RLC import Hybrid_3RLC

# LFSR 탭 (원하는 대로 바꿔도 됨)
XOR_POS1 = [0, 3, 5]
XOR_POS2 = [0, 2, 6]
XOR_POS3 = [0, 1, 4]


def split_24bit(seed_24: int):
    """24비트 정수 → 8비트 3개로 쪼개기"""
    seed_24 &= (1 << 24) - 1
    s1 = (seed_24 >> 16) & 0xFF
    s2 = (seed_24 >> 8) & 0xFF
    s3 = seed_24 & 0xFF
    return [s1, s2, s3]


def build_cipher(seed_even: int, seed_odd: int) -> Hybrid_3RLC:
    """짝수/홀수용 seed 2개로 Hybrid_3RLC 생성"""
    even_seeds = split_24bit(seed_even)
    odd_seeds  = split_24bit(seed_odd)

    lfsr_even = LfsrBlock(even_seeds, XOR_POS1, XOR_POS2, XOR_POS3)
    lfsr_odd  = LfsrBlock(odd_seeds,  XOR_POS1, XOR_POS2, XOR_POS3)

    # 여기서 Hybrid_3RLC는 encrypt_split / decrypt_merge 를 제공한다고 가정
    return Hybrid_3RLC(lfsr_even, lfsr_odd)


# ====== 공개키(N, e)만 가지고 RSA 암호화하는 헬퍼 (짝/홀 각각 다른 키) ======

def rsa_nlen(N: int) -> int:
    """모듈러스 N의 바이트 길이"""
    return (N.bit_length() + 7) // 8


def rsa_pad_pkcs1_v15(M: bytes, N: int) -> bytes:
    """
    PKCS#1 v1.5 패딩 (encrypt 용)
    구조: 0x00 | 0x02 | PS(0x00 금지 랜덤, 길이 >= 8) | 0x00 | M
    """
    n = rsa_nlen(N)
    if len(M) > n - 11:
        raise ValueError(f"msg too long: max {n - 11}B")

    ps_len = n - len(M) - 3
    ps = bytearray()
    while len(ps) < ps_len:
        b = os.urandom(1)
        if b != b"\x00":
            ps += b

    return b"\x00\x02" + bytes(ps) + b"\x00" + M


def rsa_encrypt_bytes_public(M: bytes, N: int, e: int) -> bytes:
    """
    개인키 없이 (N, e)로만 RSA 바이트 암호화.
    - 블록 단위로 PKCS#1 v1.5 패딩 적용
    - 수신측에서는 RSA3P.decrypt_bytes()로 복호 가능
    """
    n = rsa_nlen(N)
    max_pt = n - 11  # 패딩 때문에 평문 블록 최대 길이

    res = bytearray()
    for i in range(0, len(M), max_pt):
        m_block = M[i:i + max_pt]
        pm = rsa_pad_pkcs1_v15(m_block, N)
        m_int = int.from_bytes(pm, "big")
        c_int = pow(m_int, e, N)
        res += c_int.to_bytes(n, "big")

    return bytes(res)


# ====== Receiver / Sender ======

class Receiver:
    """
    수신자:
    - 짝/홀 메시지용 RSA3P 키를 각각 1개씩 생성 (총 2개)
    - enc_seed 는 짝수용 키(rsa_even)로만 복호화
    - 이후 메시지:
        - 짝수 스트림: rsa_even.decrypt_bytes()
        - 홀수 스트림: rsa_odd.decrypt_bytes()
        - Hybrid_3RLC.decrypt_merge()로 평문 복원
    """

    def __init__(self, bits: int = 2048):
        # 짝/홀 메시지용 RSA 키
        self.rsa_even = RSA3P(bits)
        self.rsa_odd  = RSA3P(bits)

        self.cipher: Hybrid_3RLC | None = None
        self.seed_even: int | None = None
        self.seed_odd: int | None = None

        print("[Receiver] RSA (even/odd) keys ready")

    @property
    def public_keys(self) -> tuple[tuple[int, int], tuple[int, int]]:
        """
        송신자에게 전달할 공개키 2개
        return: ((N_even, e_even), (N_odd, e_odd))
        """
        return (self.rsa_even.N, self.rsa_even.e), (self.rsa_odd.N, self.rsa_odd.e)

    def seed_init(self, enc_seed: int):
        """
        송신자로부터 받은 enc_seed(정수)를
        짝수용 키(rsa_even)로 복호화해서 LFSR seed 복원
        """
        M = self.rsa_even.decryption(enc_seed)

        self.seed_even = (M >> 24) & ((1 << 24) - 1)
        self.seed_odd  = M & ((1 << 24) - 1)

        self.cipher = build_cipher(self.seed_even, self.seed_odd)
        print("[Receiver] Hybrid cipher initialized.")

    def decrypt(self, cipher: bytes) -> bytes:
        """
        통신으로 받은 암호문(cipher)을 복호화:
        1) [4바이트 짝수 암호문 길이] 파싱
        2) 짝/홀 암호문 분리
        3) RSA3P로 각각 복호 → 짝/홀 스트림
        4) Hybrid_3RLC.decrypt_merge()로 평문 복원
        """
        if self.cipher is None:
            raise RuntimeError("Receiver: seed_init이 아직 호출되지 않았습니다.")

        if len(cipher) < 4:
            raise ValueError("cipher 길이가 너무 짧습니다.")

        even_len = int.from_bytes(cipher[:4], "big")
        if even_len < 0 or even_len > len(cipher) - 4:
            raise ValueError("잘못된 even_len")

        enc_even = cipher[4:4 + even_len]
        enc_odd  = cipher[4 + even_len:]

        # 1) 짝/홀 RSA 복호
        even_stream = self.rsa_even.decrypt_bytes(enc_even)
        odd_stream  = self.rsa_odd.decrypt_bytes(enc_odd)

        # 2) LFSR 기반 하이브리드 복호
        plain = self.cipher.decrypt_merge(even_stream, odd_stream)
        return plain


class Sender:
    """
    송신자:
    - 수신자 공개키 2개((N_even, e_even), (N_odd, e_odd))를 전달받음
    - 짝수용 공개키로 enc_seed 암호화해서 seed 전송
    - 같은 seed로 Hybrid_3RLC 초기화
    - 각 메시지:
        1) Hybrid_3RLC.encrypt_split() → 짝/홀 스트림 생성
        2) 각 스트림을 대응하는 공개키로 RSA 암호화
        3) [짝수 암호문 길이(4B)] + [짝수 암호문] + [홀수 암호문] 패킹해서 반환
    """

    def __init__(self, public_keys: tuple[tuple[int, int], tuple[int, int]]):
        (N_even, e_even), (N_odd, e_odd) = public_keys

        self.N_even, self.e_even = N_even, e_even
        self.N_odd,  self.e_odd  = N_odd,  e_odd

        # 24비트 랜덤 seed 2개 생성
        self.seed_even = secrets.randbits(24)
        self.seed_odd  = secrets.randbits(24)

        # 48비트 하나로 묶기
        M = (self.seed_even << 24) | self.seed_odd

        # enc_seed는 짝수용 공개키로만 암호화해서 보냄
        self.enc_seed = pow(M, self.e_even, self.N_even)

        # 동일한 seed 기반으로 하이브리드 스트림 암호 초기화
        self.cipher = build_cipher(self.seed_even, self.seed_odd)
        print("[Sender] Cipher initialized")

    def encrypt(self, msg: bytes) -> bytes:
        """
        평문 msg를 암호화:
        1) Hybrid_3RLC.encrypt_split() → 짝/홀 스트림
        2) 각 스트림을 대응하는 공개키로 RSA 암호화
        3) [짝수 암호문 길이(4B)] + [짝수 암호문] + [홀수 암호문] 반환
        """
        # 1) 짝/홀 스트림 생성 (LFSR XOR까지 끝난 상태)
        even_stream, odd_stream = self.cipher.encrypt_split(msg)

        # 2) 짝/홀 스트림 각각 RSA 암호화 (서로 다른 공개키 사용)
        enc_even = rsa_encrypt_bytes_public(even_stream, self.N_even, self.e_even)
        enc_odd  = rsa_encrypt_bytes_public(odd_stream,  self.N_odd,  self.e_odd)

        # 3) 패킹
        even_len = len(enc_even).to_bytes(4, "big")
        packet = even_len + enc_even + enc_odd
        return packet
