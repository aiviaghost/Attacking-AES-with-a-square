from functools import reduce
from secrets import token_bytes
from aes import AES

def setup(enc_oracle, num_rounds):
    random_bytes = token_bytes(16)
    delta_set = [[i for i in random_bytes] for _ in range(256)]
    for i in range(256):
        delta_set[i][0] = i
    return [enc_oracle.encrypt(bytes(pt).hex(), num_rounds = num_rounds) for pt in delta_set]

def reverse_state(key_guess, pos, delta_set_enc):
    reversed_bytes = []
    round_key = bytearray([0] * 16)
    round_key[pos] = key_guess
    round_key = round_key.hex()
    for enc in delta_set_enc:
        inv = AES.inverse_sub_bytes(AES.inverse_add_round_key(enc, round_key))
        reversed_bytes.append(bytes.fromhex(inv)[pos])
    return reversed_bytes

def check_key_guess(reversed_bytes):
    return reduce(lambda x, y: x ^ y, reversed_bytes) == 0

def attack(enc_oracle):
    pass
