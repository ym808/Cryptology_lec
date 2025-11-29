from sympy.ntheory.modular import crt

def LFSR_left_step(state):
    
    seq = []
    tap_indices = [8,6,5,4]

    # 기존 8bit + 7bit 주기 확보
    for j in range(15):
        out = state[0]
        feedback = 0

        for i in tap_indices:
            feedback ^= state[i-1]
        
        state = state[1:] + [feedback]
        seq.append(out)
        # if j < 7:
        #     print("".join(map(str, state)))

    # 끝에 8bit 자르기
    seq = seq[7:]

    return seq

def separate_seed(seed):
    # 10진수 -> 2진수 리스트 변환
    seed = [int(b) for b in bin(seed)[2:]]
    
    # 패딩작업
    if len(seed) > 24:
        seed = seed[-24:]
    elif len(seed) < 24:
        count = 24 - len(seed)
        padding = [0 for _ in range(count)]
        seed = padding + seed

    # 시드 3분할
    seed1 = seed[:8]
    seed2 = seed[8:16]
    seed3 = seed[16:]

    # 전부 0이면 끝에 1추가
    for seed in seed1, seed2, seed3:
        if seed.count(0) == 8:
            seed[-1] = 1

    return [seed1, seed2, seed3]

# lfsr 3개 한꺼번에
def do_triple_LFSR(seeds):
    seqs = []
    for seed in seeds:
        seq = LFSR_left_step(seed)
        seqs.append(seq)
    return seqs

def generate_key(seeds):
    # lsfr1의 끝 비트 뭔지 확인
    if seeds[0][-1] == 0:
        lfsr1_lastbit = 0
    elif seeds[0][-1] == 1:
        lfsr1_lastbit = 1
    else:
        raise ValueError("0 또는 1이 아닙니다")

    # seeds 2진수 리스트 형태 -> 10진수로 변환
    decimal_seeds = []
    for seed in seeds:
        decimal = 0
        for i in range(8):
            decimal = decimal * 2 + seed[i]
        decimal_seeds.append(decimal)  

    # lfsr1 마지막 비트에 따라 쉬프트
    if lfsr1_lastbit == 0:
        decimal_seeds[2] >>= decimal_seeds[2]
    else:
        decimal_seeds[1] >>= decimal_seeds[1]

    # crt 진행
    moduli = [101, 103, 107]

    (result, modular) = crt(moduli, decimal_seeds)
    
    key = result % 256

    return key

def encrypt(message, seeds):
    encrypted_m = []

    for c in message:
        seeds = do_triple_LFSR(seeds)
        key = generate_key(seeds)
        encrypted_m.append(c ^ key)

    return encrypted_m

def decrypt(cipher, seeds):
    decrypted_m = []

    for c in cipher:
        seeds = do_triple_LFSR(seeds)
        key = generate_key(seeds)
        decrypted_m.append(c ^ key)

    return decrypted_m

def do_Hybrid_3RLC(seed, message):
    # 시드 3분할 (2진수 리스트 형태로 반환함)
    seeds = separate_seed(seed)    
    
    # 인코딩
    byte = message.encode('utf-8')
    message = list(byte)

    #암호화
    encrypted_m = encrypt(message, seeds)

    #복호화
    decrypted_m = decrypt(encrypted_m, seeds)

    # 디코딩
    byte = bytes(decrypted_m)
    message = byte.decode('utf-8')

    return message

# 임시. RSA에서 받는걸로 구현필요
seed1 = 557 
seed2 = 91

message = input("Enter your message : ")

# 메시지 분리
even_message = message[::2]
odd_message = message[1::2]
print(even_message)
print(odd_message)

processed_even_m = do_Hybrid_3RLC(seed1, even_message)
processed_odd_m = do_Hybrid_3RLC(seed2, odd_message)
print(processed_even_m)
print(processed_odd_m)


# 메시지 합치기
length = len(processed_even_m)

combined_m = []

for i in range(length):
    combined_m.append(processed_even_m[i])
    if i > len(processed_odd_m): 
        break
    combined_m.append(processed_odd_m[i])

message = "".join(combined_m)
print(f"recovered message : {message}")


    