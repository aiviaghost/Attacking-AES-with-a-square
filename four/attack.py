from functools import reduce
from aes import AES
import random

from util import xor

def setup(main_key, num_rounds):
    random_byte = random.randint(0, 255)
    delta_set = [[random_byte] * 16 for _ in range(256)]
    for i in range(256):
        delta_set[i][0] = i
    return [AES.encrypt(bytes(pt).hex(), main_key, num_rounds) for pt in delta_set]

def reverse_state(key_guess, pos, delta_set_enc):
    reversed_bytes = []
    round_key = bytearray([0] * 16)
    round_key[pos] = key_guess
    round_key = round_key.hex()
    for enc in delta_set_enc:
        inv = AES.inverse_sub_bytes(AES.inverse_add_round_key(enc, round_key))
        reversed_bytes.append(bytes.fromhex(inv)[pos])
    return reversed_bytes

def check_key_guess(key_guess, reversed_bytes):
    return bytes(reduce(lambda x, y: x ^ y, reversed_bytes)) == b"\x00"
