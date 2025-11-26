import os
from typing import List

from LfsrBlock import LfsrBlock
from RSA import RSA3P
from SymmetricKey import Stripe


# ------------------------------------------------------------------
# LFSR Block 기반 키스트림 생성 유틸
# ------------------------------------------------------------------

def lfsr_keystream_bytes(block: LfsrBlock, n_bytes: int) -> bytes:
    """
    LfsrBlock.step()을 이용해서 n_bytes 만큼의 키스트림 바이트 생성
    (한 바이트 = step 8번)
    """
    out = bytearray()
    for _ in range(n_bytes):
        v = 0
        for bit_pos in range(8):
            bit = block.step()         # 0 또는 1
            v |= (bit << (7 - bit_pos))  # MSB부터 채움
        out.append(v)
    return bytes(out)


def stripe_encrypt_with_lfsr(block: LfsrBlock, plaintext: bytes) -> bytes:
    """
    LFSR Block + Stripe 방식으로 평문을 암호화.
    - 2바이트씩 잘라서 Stripe.stripe_encryption 사용
    - 각 2바이트마다 키스트림 바이트 2개 사용
    """
    # 길이가 홀수면 0x00 패딩 (간단 데모용)
    pad = False
    if len(plaintext) % 2 == 1:
        plaintext += b"\x00"
        pad = True

    res = bytearray()
    for i in range(0, len(plaintext), 2):
        block_pt = plaintext[i:i + 2]  # 길이 2
        ks = lfsr_keystream_bytes(block, 2)
        ks1, ks2 = ks[0], ks[1]
        c_block = Stripe.stripe_encryption(ks1, ks2, block_pt)
        res += c_block

    # 패딩 여부는 외부 프로토콜에서 관리 (여기서는 그대로 반환)
    return bytes(res), pad


def stripe_decrypt_with_lfsr(block: LfsrBlock, ciphertext: bytes, padded: bool) -> bytes:
    """
    LFSR Block + Stripe 방식으로 암호문을 복호화.
    - 암호화 때와 동일하게 2바이트씩 처리
    - padded=True면 마지막 1바이트 패딩 제거
    """
    if len(ciphertext) % 2 != 0:
        raise ValueError("ciphertext length must be even")

    res = bytearray()
    for i in range(0, len(ciphertext), 2):
        c_block = ciphertext[i:i + 2]
        ks = lfsr_keystream_bytes(block, 2)
        ks1, ks2 = ks[0], ks[1]
        p_block = Stripe.stripe_decryption(ks1, ks2, c_block)
        res += p_block

    if padded:
        # 마지막 1바이트 패딩 제거 (간단 데모용 규칙)
        res = res[:-1]

    return bytes(res)


# ------------------------------------------------------------------
# RSA3P로 LFSR 시드 교환 + 대칭 통신 데모
# ------------------------------------------------------------------

def generate_random_seeds(width: int = 8) -> List[int]:
    """
    width 비트 LFSR용 랜덤 시드 3개 생성 (각각 0 ~ 2^width-1)
    """
    mask = (1 << width) - 1
    seeds = []
    for _ in range(3):
        # os.urandom(1) → 0~255 사이 랜덤 바이트
        b = os.urandom(1)[0]
        seeds.append(b & mask)
    return seeds


def pack_seeds(seeds: List[int]) -> bytes:
    """
    시드 리스트를 bytes로 패킹 (각 시드를 1바이트로 가정)
    """
    return bytes(seeds)


def unpack_seeds(seed_bytes: bytes) -> List[int]:
    """
    bytes → 시드 리스트 복원
    """
    return list(seed_bytes)


def build_lfsr_block_from_seeds(seeds: List[int]) -> LfsrBlock:
    """
    공통 XOR 위치(다항식)를 고정으로 사용하여 LfsrBlock 생성.
    양쪽(Alice/Bob)이 같은 것을 사용해야 동일 키스트림 생성.
    """
    xor_positions1 = [7, 5, 4, 3]  # 예: x^8 + x^6 + x^5 + x^4 + 1
    xor_positions2 = [7, 3, 2, 1]
    xor_positions3 = [7, 6, 5, 0]

    return LfsrBlock(
        seeds=seeds,
        xor_positions1=xor_positions1,
        xor_positions2=xor_positions2,
        xor_positions3=xor_positions3,
        width=8
    )


def demo_communication():
    print("=== [1] 수신자(Bob) : RSA3P 키 생성 ===")
    bob_rsa = RSA3P(2048, 65537)
    print(f"Bob.N(bit) = {bob_rsa.N.bit_length()}")

    print("\n=== [2] 송신자(Alice) : LFSR 시드 생성 ===")
    alice_seeds = generate_random_seeds(width=8)
    print(f"Alice seeds (3개, 8bit): {alice_seeds}")

    seed_bytes = pack_seeds(alice_seeds)
    print(f"seed_bytes (hex): {seed_bytes.hex()}")

    print("\n=== [3] Alice → Bob : RSA3P로 시드 암호화 후 전송 ===")
    enc_seeds = bob_rsa.encrypt_bytes(seed_bytes)
    print(f"enc_seeds 길이 = {len(enc_seeds)}B")

    print("\n=== [4] Bob : RSA3P로 시드 복호화 ===")
    dec_seed_bytes = bob_rsa.decrypt_bytes(enc_seeds)
    bob_seeds = unpack_seeds(dec_seed_bytes)
    print(f"Bob이 복원한 seeds: {bob_seeds}")

    # 시드가 동일한지 확인
    assert alice_seeds == bob_seeds, "시드 불일치!"

    print("\n=== [5] Alice/Bob 공통 LFSR Block 생성 ===")
    alice_lfsr = build_lfsr_block_from_seeds(alice_seeds)
    bob_lfsr = build_lfsr_block_from_seeds(bob_seeds)

    print("\n=== [6] Alice : 평문 → LFSR+Stripe 암호화 ===")
    plaintext = b"LFSR + Stripe + RSA3P demo message!!!"
    print(f"Plaintext: {plaintext}")

    ciphertext, padded = stripe_encrypt_with_lfsr(alice_lfsr, plaintext)
    print(f"Ciphertext(hex): {ciphertext.hex()}")
    print(f"패딩 여부: {padded}")

    print("\n=== [7] Bob : 동일 LFSR 상태로 복호화 ===")
    recovered = stripe_decrypt_with_lfsr(bob_lfsr, ciphertext, padded)
    print(f"Recovered: {recovered}")
    print(f"복호 결과 일치? {recovered == plaintext}")


if __name__ == "__main__":
    demo_communication()
