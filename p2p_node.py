# p2p_node.py
import argparse
import os
import socket
import threading
from typing import Optional, List, Tuple

from RSA import RSA3P
from LfsrStripeCipher import LfsrStripeCipher


# ================= 공통 유틸 =================

def send_frame(sock: socket.socket, payload: bytes) -> None:
    """
    4바이트 길이 헤더 + payload 전송
    """
    length = len(payload)
    sock.sendall(length.to_bytes(4, "big") + payload)


def recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    """
    정확히 n바이트 수신. 끊기면 None 반환.
    """
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def recv_frame(sock: socket.socket) -> Optional[bytes]:
    """
    4바이트 길이 헤더 + payload 수신
    """
    header = recv_exact(sock, 4)
    if header is None:
        return None
    length = int.from_bytes(header, "big")
    if length == 0:
        return b""
    return recv_exact(sock, length)


# ================= RSA 공개키 교환 =================

def rsa_send_pubkey(sock: socket.socket, rsa: RSA3P) -> None:
    """
    RSA 공개키(N, e)를 상대에게 전송.
    payload = [2B: N 길이] + [N 바이트] + [e 바이트]
    """
    n_len_bytes = (rsa.N.bit_length() + 7) // 8
    N_bytes = rsa.N.to_bytes(n_len_bytes, "big")
    e_bytes = rsa.e.to_bytes((rsa.e.bit_length() + 7) // 8 or 1, "big")

    payload = len(N_bytes).to_bytes(2, "big") + N_bytes + e_bytes
    send_frame(sock, payload)


def rsa_recv_pubkey(sock: socket.socket) -> Tuple[int, int]:
    """
    RSA 공개키(N, e) 수신.
    """
    payload = recv_frame(sock)
    if payload is None or len(payload) < 2:
        raise ValueError("공개키 수신 실패")

    n_len = int.from_bytes(payload[:2], "big")
    if len(payload) < 2 + n_len + 1:
        raise ValueError("공개키 payload 길이 오류")

    N_bytes = payload[2:2 + n_len]
    e_bytes = payload[2 + n_len:]

    N = int.from_bytes(N_bytes, "big")
    e = int.from_bytes(e_bytes, "big")
    return N, e


# ================= seed 생성/교환 =================

def generate_random_seeds_for_two_blocks(width: int = 8) -> List[int]:
    """
    LfsrBlock 2개 × LFSR 3개 = 총 6개의 seed 생성
      base_seeds = [s1, s2, s3, s4, s5, s6]
    """
    mask = (1 << width) - 1
    return [os.urandom(1)[0] & mask for _ in range(6)]


def handshake_as_owner(sock: socket.socket) -> LfsrStripeCipher:
    """
    RSA 키를 가진 쪽 (owner) 의 핸드셰이크:
      1) RSA3P 키 생성
      2) 공개키 전송
      3) 암호화된 base_seeds 수신 → 복호화
      4) LfsrStripeCipher(role="owner") 생성
    """
    print("[*] RSA3P 키 생성 중...")
    rsa = RSA3P(2048, 65537)
    print("[*] RSA3P 키 생성 완료")

    rsa_send_pubkey(sock, rsa)
    print("[*] 공개키 전송 완료, base_seeds 수신 대기 중...")

    enc_seed_bytes = recv_frame(sock)
    if enc_seed_bytes is None:
        raise ValueError("암호화된 seed 수신 실패")

    print(f"[*] 암호화된 seed 수신(hex): {enc_seed_bytes.hex()}")

    seed_bytes = rsa.decrypt_bytes(enc_seed_bytes)
    base_seeds = list(seed_bytes)
    print(f"[*] base_seeds 수신/복호화: {base_seeds}")

    cipher = LfsrStripeCipher.from_base_seeds(base_seeds, role="owner")
    return cipher


def handshake_as_peer(sock: socket.socket) -> LfsrStripeCipher:
    """
    RSA 키 없는 쪽 (peer) 의 핸드셰이크:
      1) 공개키 수신
      2) base_seeds(6바이트) 생성
      3) RSA 공개키로 암호화해서 전송
      4) LfsrStripeCipher(role="peer") 생성
    """
    print("[*] 공개키 수신 대기...")
    N, e = rsa_recv_pubkey(sock)
    print(f"[*] 공개키 수신 완료: N(bit)={N.bit_length()}, e={e}")

    rsa = RSA3P()     # 생성자 내부에서 키를 만들긴 하지만, N,e 를 곧바로 덮어씀
    rsa.N = N
    rsa.e = e

    base_seeds = generate_random_seeds_for_two_blocks(width=8)
    print(f"[*] base_seeds 생성: {base_seeds}")

    enc_seed_bytes = rsa.encrypt_bytes(bytes(base_seeds))
    print(f"[*] 암호화된 seed 전송(hex): {enc_seed_bytes.hex()}")
    send_frame(sock, enc_seed_bytes)
    print("[*] 암호화된 seed 전송 완료")

    cipher = LfsrStripeCipher.from_base_seeds(base_seeds, role="peer")
    return cipher


# ================= 채팅 루프 =================

def recv_loop(sock: socket.socket, cipher: LfsrStripeCipher) -> None:
    """
    상대가 보내는 메시지를 계속 수신/복호화하는 스레드.
    """
    while True:
        frame = recv_frame(sock)
        if frame is None:
            print("\n[!] 연결이 종료되었습니다.")
            break

        print(f"\n[수신 암호문(hex)] {frame.hex()}")

        msg = cipher.decrypt_frame_to_text(frame)
        if msg == "":
            continue
        print(f"[상대] {msg}")
        print("> ", end="", flush=True)


def chat_loop(sock: socket.socket, cipher: LfsrStripeCipher) -> None:
    t = threading.Thread(target=recv_loop, args=(sock, cipher), daemon=True)
    t.start()

    print("[*] 채팅 시작. '/quit' 입력하면 종료.")
    while True:
        try:
            text = input("> ")
        except EOFError:
            break

        if text.strip() == "/quit":
            break

        frame = cipher.encrypt_text(text)
        send_frame(sock, frame)

        print(f"[송신 암호문(hex)] {frame.hex()}")

    sock.close()
    print("[*] 연결 종료")


# ================= main: 모드 선택 =================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["listen", "connect"], required=True,
                        help="listen: 포트 열고 대기 / connect: 상대에게 접속")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument(
        "--rsa-owner",
        action="store_true",
        help="이 노드가 RSA 키를 생성/보유하는 쪽이면 지정 (보통 listen 쪽이 owner)"
    )

    args = parser.parse_args()

    if args.mode == "listen":
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind((args.host, args.port))
        srv.listen(1)
        print(f"[*] listen 중... {args.host}:{args.port}")

        conn, addr = srv.accept()
        print(f"[*] 연결 수락: {addr}")

        if args.rsa_owner:
            cipher = handshake_as_owner(conn)
        else:
            cipher = handshake_as_peer(conn)

        chat_loop(conn, cipher)

    else:  # connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((args.host, args.port))
        print(f"[*] {args.host}:{args.port} 에 연결됨")

        if args.rsa_owner:
            print("[!] 보통 listen 쪽에 --rsa-owner를 주는 걸 추천합니다.")
            cipher = handshake_as_owner(sock)
        else:
            cipher = handshake_as_peer(sock)

        chat_loop(sock, cipher)


if __name__ == "__main__":
    main()
