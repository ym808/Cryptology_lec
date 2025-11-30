# Communication.py
import secrets
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

    return Hybrid_3RLC(lfsr_even, lfsr_odd)


class Receiver:
    """수신자: RSA 키 생성 + enc_seed 복호화 + 하이브리드 암호 초기화"""

    def __init__(self, bits: int = 2048):
        self.rsa = RSA3P(bits)
        self.cipher: Hybrid_3RLC | None = None
        self.seed_even: int | None = None
        self.seed_odd: int | None = None
        print("[Receiver] RSA key ready")

    @property
    def public_key(self) -> tuple[int, int]:
        """송신자에게 전달할 공개키 (N, e)"""
        return (self.rsa.N, self.rsa.e)

    def seed_init(self, enc_seed: int):
        """송신자로부터 받은 enc_seed(정수)를 복호화해서 LFSR 초기화"""
        M = self.rsa.decryption(enc_seed)

        self.seed_even = (M >> 24) & ((1 << 24) - 1)
        self.seed_odd  = M & ((1 << 24) - 1)

        self.cipher = build_cipher(self.seed_even, self.seed_odd)
        print("[Receiver] Hybrid cipher initialized.")

    def decrypt(self, cipher: bytes) -> bytes:
        if self.cipher is None:
            raise RuntimeError("Receiver: seed_init이 아직 호출되지 않았습니다.")
        return self.cipher.decrypt(cipher)


class Sender:
    """송신자: 공개키로 enc_seed 만들고, 같은 seed로 하이브리드 암호 초기화"""

    def __init__(self, public_key: tuple[int, int]):
        N, e = public_key

        # 24비트 랜덤 seed 2개 생성
        self.seed_even = secrets.randbits(24)
        self.seed_odd  = secrets.randbits(24)

        # 48비트 하나로 묶기
        M = (self.seed_even << 24) | self.seed_odd

        # RSA 암호화 (m^e mod N)
        self.enc_seed = pow(M, e, N)

        # 동일한 seed 기반으로 스트림 암호 초기화
        self.cipher = build_cipher(self.seed_even, self.seed_odd)
        print("[Sender] Cipher initialized")

    def encrypt(self, msg: bytes) -> bytes:
        return self.cipher.encrypt(msg)
