# com/Receiver.py
import socket
import sys
from com.Communication import Receiver as CryptoReceiver  # 같은 폴더에 Communication.py 있다고 가정


HOST = "127.0.0.1"


def recv_exact(conn, n: int) -> bytes:
    """n바이트 딱 맞게 읽기 (길이 프레임용)"""
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            # 연결 끊김
            return b""
        data += chunk
    return data


def main():
    # 포트는 인자로 받기 (없으면 기본 9000)
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9000

    # 1) Receiver 인스턴스 생성 → RSA 키 자동 생성
    rcv = CryptoReceiver(2048)
    print("[Receiver] RSA key generated.")

    # 2) 서버 소켓 열기
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, port))
    server.listen(1)
    print(f"[Receiver] Listening on {HOST}:{port} ...")

    conn, addr = server.accept()
    print(f"[Receiver] Connected by {addr}")

    # 3) 송신자에게 공개키 전송
    N, e = rcv.public_key
    pk_str = f"{N},{e}"
    conn.sendall(pk_str.encode("utf-8"))
    print("[Receiver] Public key sent.")

    # 4) 송신자로부터 enc_seed(정수) 수신
    enc_seed_data = conn.recv(4096).decode("utf-8").strip()
    if not enc_seed_data:
        print("[Receiver] ERROR: EncSeed is empty. Sender side error.")
        conn.close()
        server.close()
        return

    enc_seed = int(enc_seed_data)
    print("[Receiver] EncSeed received:", enc_seed)

    # 5) 하이브리드 암호 초기화
    rcv.seed_init(enc_seed)

    print("[Receiver] Ready to receive multiple messages.")
    print("[Receiver] (Sender가 종료 패킷 보내면 자동 종료됩니다.)")

    # 6) 여러 메시지 반복 수신
    while True:
        # 먼저 길이 4바이트 받기
        header = recv_exact(conn, 4)
        if not header:
            print("[Receiver] Connection closed by sender.")
            break

        msg_len = int.from_bytes(header, "big")
        if msg_len == 0:
            print("[Receiver] Received close signal. Bye!")
            break

        cipher = recv_exact(conn, msg_len)
        if not cipher:
            print("[Receiver] Cipher recv failed. Closing.")
            break

        plain = rcv.decrypt(cipher)
        try:
            text = plain.decode("utf-8")
        except UnicodeDecodeError:
            text = plain.decode("utf-8", errors="replace")

        print(f"[Receiver] Message: {text}")

    conn.close()
    server.close()
    print("[Receiver] Program end.")


if __name__ == "__main__":
    main()
