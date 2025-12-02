# launcher.py
import subprocess
import time
import os
import sys
import platform


def main():
    # 포트는 인자로 받거나, 없으면 기본 9000
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9000

    base_path = os.path.dirname(os.path.abspath(__file__))
    receiver_path = os.path.join(base_path, "com", "Receiver.py")
    sender_path = os.path.join(base_path, "com", "Sender.py")

    current_os = platform.system().lower()

    print(f"[Launcher] Detected OS: {current_os}")

    # ----------------------
    # Windows (start cmd 사용)
    # ----------------------
    if "windows" in current_os:
        subprocess.Popen(
            f'start cmd /c python -u "{receiver_path}" {port}',
            shell=True
        )
        print(f"[Launcher] Receiver window opened on port {port}.")

        time.sleep(1)

        subprocess.Popen(
            f'start cmd /c python -u "{sender_path}" {port}',
            shell=True
        )
        print("[Launcher] Sender window opened.")
        return

    # ----------------------
    # Linux/macOS (GUI 터미널 없음 → Codespaces 대응)
    # ----------------------
    print("[Launcher] GUI terminal unsupported in this OS environment.")
    print("[Launcher] Please run manually in two terminals:")

    print(f"\nTerminal #1:")
    print(f"python -m com.Receiver {port}")

    print(f"\nTerminal #2:")
    print(f"python -m com.Sender {port}\n")

    print("[Launcher] (Press Enter to exit)")
    input()


if __name__ == "__main__":
    main()
