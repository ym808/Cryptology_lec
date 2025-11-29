import time
from crypto.RSA import RSA2P, RSA3P

# 출력 보조
def hex_preview(b: bytes, limit=32):
    h = b.hex()
    return h if len(b) <= limit else (b[:limit].hex() + f"...(+{len(b)-limit}B)")

def sep_line(title):
    print("\n" + "="*80)
    print(title)
    print("="*80)

def trace_encrypt_decrypt(rsa, label, msg: bytes, preview_limit=32, trace_blocks=2):
    n = rsa.Nlen()
    max_pt = n - 11

    sep_line(f"[{label}] 키/블록 정보")
    print(f"N(bit) = {rsa.N.bit_length()}, N(bytes) = {n}")
    print(f"한 블록당 최대 평문 크기 = {max_pt}B")
    print(f"원문 길이 = {len(msg)}B, 원문 미리보기 = {hex_preview(msg, preview_limit)}")

    # 암호화
    sep_line(f"[{label}] 암호화 진행")
    t0 = time.perf_counter()
    ct = rsa.encrypt_bytes(msg)
    t1 = time.perf_counter()
    print(f"암호문 길이 = {len(ct)}B, 소요 = {(t1 - t0)*1000:.2f} ms")
    total_blocks = len(ct) // n
    print(f"블록 개수 = {total_blocks}")

    # 블록별(앞의 일부만) 내부 과정 추적
    print("\n[블록별 암호화 트레이스 (상위 일부 블록만)]")
    for bi in range(min(total_blocks, trace_blocks)):
        # 평문 구간
        pi0 = bi * max_pt
        pi1 = min(len(msg), pi0 + max_pt)
        m_block = msg[pi0:pi1]

        # 패딩 후 바이트 (직접 한 번 더 생성해서 보여줌)
        em = rsa.pad(m_block)
        m_int = int.from_bytes(em, "big")

        # 실제 암호문 블록
        ci0 = bi * n
        ci1 = ci0 + n
        c_block = ct[ci0:ci1]

        print(f"\n  - 블록 #{bi}")
        print(f"    평문블록({len(m_block)}B): {hex_preview(m_block, preview_limit)}")
        print(f"    패딩후(em)({len(em)}B): {hex_preview(em, preview_limit)}")
        print(f"    m(bit_length) = {m_int.bit_length()}")
        print(f"    암호문 블록({len(c_block)}B): {hex_preview(c_block, preview_limit)}")

    # 복호화
    sep_line(f"[{label}] 복호화 진행")
    t2 = time.perf_counter()
    pt = rsa.decrypt_bytes(ct)
    t3 = time.perf_counter()
    print(f"복호 길이 = {len(pt)}B, 소요 = {(t3 - t2)*1000:.2f} ms")
    print(f"복호 평문 미리보기 = {hex_preview(pt, preview_limit)}")
    print(f"복호 결과 일치: {pt == msg}")

    # 복호화 블록 내부(앞의 일부만) 확인
    print("\n[블록별 복호화 트레이스 (상위 일부 블록만)]")
    for bi in range(min(total_blocks, trace_blocks)):
        ci0 = bi * n
        ci1 = ci0 + n
        c_block = ct[ci0:ci1]
        m_int = rsa.decryption(int.from_bytes(c_block, "big"))
        em = m_int.to_bytes(n, "big")

        # 언패딩 지점 찾기 (0x00 after 0x02)
        sep = em.find(b"\x00", 2)
        data = em[sep+1:] if sep >= 0 else b""
        print(f"\n  - 블록 #{bi}")
        print(f"    암호문 블록({len(c_block)}B): {hex_preview(c_block, preview_limit)}")
        print(f"    복호(em)({len(em)}B): {hex_preview(em, preview_limit)}")
        if sep >= 0:
            print(f"    언패딩 구분자 index = {sep} (em[sep]==0x00)")
            print(f"    추출 평문({len(data)}B): {hex_preview(data, preview_limit)}")
        else:
            print("    [경고] 구분자(0x00) 못 찾음 → 패딩 오류")

    # 같은 평문 다시 암호화해서 다른 암호문 나옴을 확인
    sep_line(f"[{label}] 동일 평문 재암호화 (랜덤 PS 확인)")
    ct2 = rsa.encrypt_bytes(msg)
    diff = (ct != ct2)
    print(f"다시 암호화한 암호문 길이 = {len(ct2)}B")
    print(f"서로 다른가? {diff}")
    if diff:
        print(f"첫 블록 비교:\n  ct1: {hex_preview(ct[:n], 16)}\n  ct2: {hex_preview(ct2[:n], 16)}")

def main():
    # 비교용 평문 (여러 블록 되도록 살짝 길게)
    msg = b"PKCS1 v1.5 TRACE >>> " * 20

    # RSA2P
    sep_line("[RSA2P] 키 생성")
    t0 = time.perf_counter()
    rsa2 = RSA2P(2048, 65537)
    t1 = time.perf_counter()
    print(f"RSA2P keygen: {(t1 - t0)*1000:.2f} ms")

    trace_encrypt_decrypt(rsa2, "RSA2P", msg, preview_limit=32, trace_blocks=2)

    # RSA3P
    sep_line("[RSA3P] 키 생성")
    t2 = time.perf_counter()
    rsa3 = RSA3P(2048, 65537)
    t3 = time.perf_counter()
    print(f"RSA3P keygen: {(t3 - t2)*1000:.2f} ms")

    trace_encrypt_decrypt(rsa3, "RSA3P", msg, preview_limit=32, trace_blocks=2)

    # 최종 요약
    sep_line("요약")
    print("· 위 출력에서 각 블록의:")
    print("  - 평문블록 → 패딩후(em) → m(bit_length) → 암호문 블록 순서 확인")
    print("  - 복호 시 암호문 블록 → em → 언패딩 지점(index) → 평문 추출 확인")
    print("· 동일 평문 재암호화 결과가 서로 다른 것도 확인 (랜덤 PS)")

if __name__ == "__main__":
    main()
