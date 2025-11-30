# com/Sender.py
import socket
import sys
from com.Communication import Sender as CryptoSender  # 같은 폴더에 Communication.py 있다고 가정


HOST = "127.0.0.1"


def send_with_len(sock: socket.socket, data: bytes):
    """앞에 길이(4바이트)를 붙여서 전송"""
    length = len(data)
    header = length.to_bytes(4, "big")
    sock.sendall(header + data)


def main():
    # 포트는 인자로 받기 (없으면 기본 9000)
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9000

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, port))
    print("[Sender] Connected to Receiver.")

    # 1) 수신자로부터 공개키 수신
    pk_data = client.recv(4096).decode("utf-8").strip()
    N, e = map(int, pk_data.split(","))
    print("[Sender] Public key received.")

    # 2) Sender 인스턴스 생성 (RSA 공개키로 enc_seed 생성 + cipher 초기화)
    sender = CryptoSender((N, e))
    enc_seed = sender.enc_seed
    client.sendall(str(enc_seed).encode("utf-8"))
    print("[Sender] EncSeed sent:", enc_seed)

    print("[Sender] Ready to send messages.")
    print("[Sender] '/quit' 입력 시 대화 종료 및 창 닫힘.")

    # 3) 여러 메시지 전송 루프
    while True:
        msg_text = input("You: ")
        if msg_text.strip().lower() in ("/quit", "quit", "exit"):
            # 종료 패킷: 길이 0
            client.sendall((0).to_bytes(4, "big"))
            print("[Sender] Close signal sent. Bye!")
            break

        msg_bytes = msg_text.encode("utf-8")
        cipher = sender.encrypt(msg_bytes)
        send_with_len(client, cipher)
        print("[Sender] Cipher sent.")

    client.close()
    print("[Sender] Program end.")


if __name__ == "__main__":
    main()
