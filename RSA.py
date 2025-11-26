# pip install pycryptodome
import math
import os
from Crypto.Util import number

class RSA2P:
    N: int; e: int; d: int  # 공개키/개인키
    p: int; q: int          # 두 소수
    k: int                  # 카마이클(lambda)

    # CRT용 미리계산
    dp: int; dq: int
    Np: int; Nq: int
    inv_Np: int; inv_Nq: int

    def __init__(self, key_bits=2048, e=65537):
        # 두 소수 비트 분배
        pb = key_bits // 2
        while True:
            p = number.getPrime(pb)
            q = number.getPrime(key_bits - p.bit_length())  # 총 비트 길이 맞추기
            if p == q:
                continue

            N = p * q
            k = math.lcm(p - 1, q - 1)          # λ(n)
            if math.gcd(e, k) != 1:              # 역원 존재 조건
                continue

            d = pow(e, -1, k)

            # CRT 미리계산
            dp = d % (p - 1)
            dq = d % (q - 1)
            Np = N // p
            Nq = N // q
            inv_Np = pow(Np, -1, p)
            inv_Nq = pow(Nq, -1, q)

            # 속성 설정
            self.N, self.e, self.d = N, e, d
            self.p, self.q = p, q
            self.k = k
            self.dp, self.dq = dp, dq
            self.Np, self.Nq = Np, Nq
            self.inv_Np, self.inv_Nq = inv_Np, inv_Nq
            break

    # ===== 정수 블록 암복호 =====
    def encryption(self, M: int) -> int:
        if not (0 <= M < self.N):
            raise ValueError("M must satisfy 0 <= M < N")
        return pow(M, self.e, self.N)

    def decryption(self, C: int) -> int:
        # CRT 복호
        mp = pow(C, self.dp, self.p)
        mq = pow(C, self.dq, self.q)
        M = (mp * self.Np * self.inv_Np + mq * self.Nq * self.inv_Nq) % self.N
        return M

    # ===== bytes 인터페이스 (PKCS#1 v1.5) =====
    def encrypt_bytes(self, M: bytes) -> bytes:
        n = self.Nlen()      # 모듈러스 바이트 길이
        max_pt = n - 11      # 한 블록 최대 평문 길이
        res = bytearray()

        for i in range(0, len(M), max_pt):
            m_block = M[i:i + max_pt]
            pm = self.pad(m_block)                     # 00 02 PS 00 M
            c_block = self.encryption(int.from_bytes(pm, "big"))
            res += c_block.to_bytes(n, "big")          # 고정 길이 블록 이어붙이기
        return bytes(res)

    def decrypt_bytes(self, c: bytes) -> bytes:
        n = self.Nlen()
        if len(c) % n != 0:
            raise ValueError("bad ciphertext length")

        res = bytearray()
        for i in range(0, len(c), n):
            c_block = c[i:i + n]
            pm = self.decryption(int.from_bytes(c_block, "big"))
            res += self.unpad(pm.to_bytes(n, "big"))   # 패딩 제거 → 평문
        return bytes(res)

    # ===== 유틸 =====
    def Nlen(self) -> int:
        # ceil(bitlen/8)
        return (self.N.bit_length() + 7) // 8

    def pad(self, M: bytes) -> bytes:
        """
        구조: 0x00 | 0x02 | PS(랜덤, 0x00 금지, 길이≥8) | 0x00 | M
        """
        n = self.Nlen()
        if len(M) > n - 11:
            raise ValueError(f"msg too long: max {n - 11}B")

        ps_len = n - len(M) - 3
        ps = bytearray()
        while len(ps) < ps_len:
            b = os.urandom(1)
            if b != b"\x00":
                ps += b
        return b"\x00\x02" + bytes(ps) + b"\x00" + M

    def unpad(self, pm: bytes) -> bytes:
        """
        [00][02][PS][00][평문] → 평문 추출
        """
        if len(pm) < 11 or pm[0] != 0x00 or pm[1] != 0x02:
            raise ValueError("bad padding")
        sep = pm.find(b"\x00", 2)
        if sep < 0 or sep < 10:
            raise ValueError("bad padding (PS too short)")
        return pm[sep + 1:]

class RSA3P:
    N: int; e: int; d: int #공개키: e, 프라이빗키: d
    p: int; q: int; r: int #3소수
    k: int #카마이클

    #복호화 시 사용할 변수들
    dp: int; dq: int; dr: int
    Np: int; Nq: int; Nr: int
    inv_Np: int; inv_Nq: int; inv_Nr:int

    def __init__(self, key_bits=2048, e=65537):
        prime_bits = key_bits // 3


        while True:
            primes = set()

            while len(primes) < 3:
                if len(primes) == 2:
                    primes.add(number.getPrime(key_bits - prime_bits * 2))
                else:
                    primes.add(number.getPrime(prime_bits))

            p, q, r = list(primes)

            N = p * q * r
            k = math.lcm(p - 1, q - 1, r - 1)

            if math.gcd(e, k) != 1:              # 역원 존재 조건
                continue

            d = pow(e, -1, k)

            dp = d % (p - 1)
            dq = d % (q - 1)
            dr = d % (r - 1)

            Np = N // p
            Nq = N // q
            Nr = N // r

            inv_Np = pow(Np, -1, p)
            inv_Nq = pow(Nq, -1, q)
            inv_Nr = pow(Nr, -1, r)

            self.N, self.e, self.d = N, e, d
            self.p, self.q, self.r = p, q, r
            self.k = k

            self.dp, self.dq, self.dr = dp, dq, dr
            self.Np, self.Nq, self.Nr = Np, Nq, Nr
            self.inv_Np, self.inv_Nq, self.inv_Nr = inv_Np, inv_Nq, inv_Nr

            break


    def encryption(self, M: int) -> int:
        C = pow(M, self.e, self.N)
        return C

    def decryption(self, C: int) -> int:
        mp = pow(C, self.dp, self.p)
        mq = pow(C, self.dq, self.q)
        mr = pow(C, self.dr, self.r)

        M = (mp*self.Np*self.inv_Np + mq*self.Nq*self.inv_Nq + mr*self.Nr*self.inv_Nr) % self.N

        return M

    def encrypt_bytes(self, M: bytes) -> bytes:
        n = self.Nlen()  # 모듈러스 N의 바이트 길이 (예: 2048bit → 256B)
        max_pt = n - 11  # 한 블록당 평문 최대 길이 (패딩 11B 제외)
        res = bytearray()

        # 평문을 블록 단위로 나누어 처리
        for i in range(0, len(M), max_pt):
            m_block = M[i:i + max_pt]

            # 패딩 추가
            pm = self.pad(m_block)

            # 바이트 → 정수 변환 후 RSA 암호화
            c_block = self.encryption(int.from_bytes(pm, "big"))

            # 암호문 블록(정수) → 고정 길이 바이트로 변환 후 이어붙임
            res += c_block.to_bytes(n, "big")

        # 전체 암호문 반환 (블록 연결 형태)
        return bytes(res)

    def decrypt_bytes(self, c: bytes) -> bytes:
        """PKCS#1 v1.5 기반 RSA 바이트 복호화"""
        n = self.Nlen()

        # 암호문 길이는 반드시 블록 단위(k의 배수)
        if len(c) % n != 0:
            raise ValueError("bad ciphertext length")

        res = bytearray()

        # 암호문을 블록 단위로 복호화
        for i in range(0, len(c), n):
            c_block = c[i:i + n]

            # RSA 복호화
            pm = self.decryption(int.from_bytes(c_block, "big"))

            # 패딩 제거 후 평문만 추출
            res += self.unpad(pm.to_bytes(n, "big"))

        return bytes(res)

    def Nlen(self) -> int:
        return (self.N.bit_length() + 7) // 8

    def pad(self, M: bytes) -> bytes:
        """
        구조: 0x00 | 0x02 | PS | 0x00 | M
        PS: 0x00이 아닌 랜덤 바이트
        """
        n = self.Nlen()

        # 블럭 이상 검출
        if len(M) > n - 11:
            raise ValueError(f"msg too long: max {n - 11}B")

        ps_len = n - len(M) - 3
        ps = bytearray()

        # PS 채우기 (0x00 제외 랜덤 바이트)
        while len(ps) < ps_len:
            b = os.urandom(1)
            if b != b"\x00":
                ps += b

        # 구조: [00][02][PS][00][M]
        return b"\x00\x02" + bytes(ps) + b"\x00" + M

    def unpad(self, pm: bytes) -> bytes:
        """
        [00][02][PS][00][평문] → 평문 추출
        """
        if len(pm) < 11 or pm[0] != 0x00 or pm[1] != 0x02:
            raise ValueError("bad padding")

        # 두 번째 0x00 이후부터 평문
        sep = pm.find(b"\x00", 2)
        if sep < 0 or sep < 10:
            raise ValueError("bad padding (PS too short)")

        return pm[sep + 1:]

