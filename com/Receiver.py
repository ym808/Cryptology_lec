# receiver.py
import socket
from crypto.RSA import RSA3P
from Communication import Receiver

HOST = '127.0.0.1'
PORT = 9000

def main():
    # 1) Receiver 생성 → RSA 키 생성
    rcv = Receiver(RSA3P(2048))
    print("[Receiver] RSA key generated.")

    # 2) 서버 소켓 열기
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(1)
    print("[Receiver] Waiting for connection...")

    conn, addr = server.accept()
    print(f"[Receiver] Connected by {addr}")

    # 3) Sender에게 공개키 전송
    N, e = rcv.public_key
    conn.sendall(f"{N},{e}".encode())
    print("[Receiver] Public key sent.")

    # 4) 암호화된 seed 수신
    enc_seed = int(conn.recv(1024).decode())
    print("[Receiver] EncSeed received:", enc_seed)

    rcv.receive_seeds(enc_seed)
    print("[Receiver] Hybrid cipher initialized.")

    # 5) 암호문 수신 → 복호화
    cipher = conn.recv(2048)
    print("[Receiver] Cipher:", cipher)

    plain = rcv.decrypt(cipher)
    print("[Receiver] Decrypted:", plain.decode('utf-8'))

    conn.close()
    server.close()

if __name__ == "__main__":
    main()
