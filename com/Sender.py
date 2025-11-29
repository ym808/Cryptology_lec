# sender.py
import socket
from Communication import Sender

HOST = '127.0.0.1'
PORT = 9000

def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
    print("[Sender] Connected to Receiver.")

    # 1) 공개키 수신
    pk_data = client.recv(1024).decode()
    N, e = map(int, pk_data.split(","))
    print("[Sender] Public key received.")

    # 2) seed 암호화 + Hybrid 초기화
    sender, enc_seed = Sender.init((N, e))
    client.sendall(str(enc_seed).encode())
    print("[Sender] EncSeed sent:", enc_seed)

    # 3) 평문 입력 → 암호화
    msg = input("Enter Message: ").encode()
    cipher = sender.encrypt(msg)

    client.sendall(cipher)
    print("[Sender] Cipher sent:", cipher)

    client.close()

if __name__ == "__main__":
    main()
