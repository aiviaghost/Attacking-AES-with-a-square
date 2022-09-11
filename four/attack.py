from aes import AES
import random

def setup(main_key):
    random_byte = random.randint(0, 255)
    delta_set = [[random_byte] * 16 for _ in range(256)]
    for i in range(256):
        delta_set[i][0] = i
    return [AES.encrypt(bytes(pt).hex(), main_key, num_rounds = 3) for pt in delta_set]
