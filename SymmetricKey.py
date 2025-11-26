class Stripe:
    @staticmethod
    def stripe_encryption(ks1: int, ks2: int, P: bytes) -> bytes:
        """
        ks1, ks2 : 각 8비트
        P       : bytes 길이 2
        """
        if len(P) != 2:
            raise ValueError("P는 반드시 길이 2인 bytes여야 합니다.")

            # 각 바이트 XOR
        c0 = P[0] ^ ks1
        c1 = P[1] ^ ks2

        # 다시 바이트 두 개로 결합
        return bytes([c0, c1])

    @staticmethod
    def stripe_decryption(ks1: int, ks2: int, C: bytes) -> bytes:
        """
        ks1, ks2 : 각 8비트
        C       : bytes 길이 2
        """
        if len(C) != 2:
            raise ValueError("C는 반드시 길이 2인 bytes여야 합니다.")

        p0 = C[0] ^ ks1
        p1 = C[1] ^ ks2

        # 다시 바이트 두 개로 결합
        return bytes([p0, p1])
