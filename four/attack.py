from functools import reduce
from secrets import token_bytes
from aes import AES
from util import xor, flatten

def setup(enc_service, num_rounds):
    random_bytes = token_bytes(AES.BLOCK_SIZE)
    delta_set = [[i for i in random_bytes] for _ in range(256)]
    for i in range(256):
        delta_set[i][0] = i
    return [enc_service.encrypt(bytes(pt).hex(), num_rounds = num_rounds) for pt in delta_set]

def reverse_state(key_guess, pos, delta_set_enc):
    reversed_bytes = []
    round_key = bytearray([0] * AES.BLOCK_SIZE)
    round_key[pos] = key_guess
    round_key = round_key.hex()
    for enc in delta_set_enc:
        inv = AES.inverse_sub_bytes(AES.inverse_add_round_key(enc, round_key))
        reversed_bytes.append(bytes.fromhex(inv)[pos])
    return reversed_bytes

def check_key_guess(reversed_bytes):
    return reduce(lambda x, y: x ^ y, reversed_bytes) == 0

def get_potential_key_bytes(key_pos, enc_service, num_rounds):
    pkbs = []
    delta_set_enc = setup(enc_service, num_rounds)
    for guess in range(256):
        guessed_state = reverse_state(guess, key_pos, delta_set_enc)
        if check_key_guess(guessed_state):
            pkbs.append(guess)
    return pkbs

def attack(enc_service, num_rounds):
    last_round_key = []
    for key_pos in range(AES.BLOCK_SIZE):
        while len(pkbs := get_potential_key_bytes(key_pos, enc_service, num_rounds)) != 1 : pass
        last_round_key.append(pkbs[0])
    return bytes(last_round_key).hex()

def reverse_key_expansion(last_round_key, num_rounds):
    next_key = bytes.fromhex(last_round_key)
    for round_number in range(num_rounds, 0, -1):
        prev_columns = [None] * 4
        for i in range(1, 4):
            prev_columns[i] = xor(AES.get_column(next_key, i - 1), AES.get_column(next_key, i))
        transformed = AES.sub_word(AES.rot_word(prev_columns[-1]))
        prev_columns[0] = xor(xor(transformed, AES.rcon(round_number)), AES.get_column(next_key, 0))
        next_key = bytes(flatten(prev_columns))
    return next_key.hex()
