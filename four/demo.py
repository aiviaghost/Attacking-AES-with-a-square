from secrets import token_bytes

from aes import AES
from attack import attack

num_rounds = 4

main_key = token_bytes(AES.BLOCK_SIZE)
print(f"Main key = {main_key.hex()}")

encryption_service = AES(main_key, num_rounds)

print(f"Performing key recovery on {num_rounds} rounds of AES ...")

recovered_key = attack(encryption_service)

print(f"Recovered key = {recovered_key.hex()}")

if recovered_key == main_key:
    print("Attack successful!")
else:
    print("Attack unsuccessful!")
