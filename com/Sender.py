# com/Sender.py
import socket
import sys

from com.Communication import Sender as CryptoSender, short_int

HOST = "127.0.0.1"


def send_with_len(sock: socket.socket, data: bytes) -> None:
    """앞에 길이(4바이트)를 붙여서 전송."""
    length = len(data)
    header = length.to_bytes(4, "big")
    sock.sendall(header + data)


def main() -> None:
    # 포트는 인자로 받기 (없으면 기본 9000)
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9000

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, port))
    print(f"[Sender] 수신자 {HOST}:{port}에 연결됨")

    # 1) 수신자로부터 공개키 2개 수신
    # 형식: "N_even,e_even;N_odd,e_odd"
    pk_data = client.recv(4096).decode("utf-8").strip()
    try:
        pk_even_str, pk_odd_str = pk_data.split(";")
        N_even, e_even = map(int, pk_even_str.split(","))
        N_odd, e_odd = map(int, pk_odd_str.split(","))
    except Exception as e:
        print("[Sender] 오류: 잘못된 공개키 형식:", pk_data)
        client.close()
        return

    print(f"[Sender]  짝수: N={short_int(N_even)}, e={e_even}")
    print(f"[Sender]  홀수: N={short_int(N_odd)},  e={e_odd}")

    # 2) Sender 인스턴스 생성 (RSA 공개키 2개로 enc_seed 생성 + cipher 초기화)
    sender = CryptoSender(((N_even, e_even), (N_odd, e_odd)))
    enc_seed = sender.enc_seed
    client.sendall(str(enc_seed).encode("utf-8"))
    print("[Sender] 암호화된 시드 전송 완료.")

    print("[Sender] 메시지 전송 준비 완료. ('/quit' 입력 시 종료)")

    # 3) 여러 메시지 전송 루프
    while True:
        try:
            msg_text = input("You: ")
        except (EOFError, KeyboardInterrupt):
            msg_text = "/quit"

        if msg_text.strip().lower() in ("/quit", "quit", "exit"):
            # 길이 0 패킷을 종료 신호로 사용
            client.sendall((0).to_bytes(4, "big"))
            print("[Sender] 종료 신호 전송.")
            break

        msg_bytes = msg_text.encode("utf-8")
        cipher = sender.encrypt(msg_bytes)
        send_with_len(client, cipher)
        print("[Sender] 암호문 전송 완료.")

    client.close()
    print("[Sender] 프로그램 종료.")


if __name__ == "__main__":
    main()
