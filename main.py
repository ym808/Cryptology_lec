# launcher.py
import subprocess
import time


def main():
    # 1️⃣ Receiver 창 실행
    subprocess.Popen(
        'start cmd /k python receiver.py',
        shell=True
    )
    print("[Launcher] Receiver window opened.")

    # 서버 준비 시간(1초 정도 여유)
    time.sleep(1)

    # 2️⃣ Sender 창 실행
    subprocess.Popen(
        'start cmd /k python sender.py',
        shell=True
    )
    print("[Launcher] Sender window opened.")


if __name__ == "__main__":
    main()
