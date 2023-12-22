from functools import reduce
from secrets import token_bytes

from aes import AES
from util import xor, flatten
try:
    from tqdm import tqdm
    bar_format = "{percentage:3.0f}% |{bar}| Bytes recovered: {n_fmt}/{total_fmt} | Time elapsed: {elapsed} | {rate_fmt}"
    display_progress = lambda x, **kwargs: tqdm(
        x, ncols=100, disable=kwargs["disable_tqdm"], bar_format=bar_format, unit="byte")
except:
    display_progress = lambda x, *args, **kwargs: x


def setup(enc_service, num_rounds):
    random_bytes = token_bytes(AES.BLOCK_SIZE)
    delta_set = [[i for i in random_bytes] for _ in range(256)]
    for i in range(256):
        delta_set[i][0] = i
    return [enc_service.encrypt(bytes(pt).hex(), num_rounds=num_rounds) for pt in delta_set]


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


def recover_round_key(enc_service, num_rounds, disable_tqdm=False):
    last_round_key = []
    for key_pos in display_progress(range(AES.BLOCK_SIZE), disable_tqdm=disable_tqdm):
        while len(pkbs := get_potential_key_bytes(key_pos, enc_service, num_rounds)) != 1:
            pass
        last_round_key.append(pkbs[0])
    return bytes(last_round_key).hex()


def reverse_key_expansion(last_round_key, num_rounds):
    next_key = bytes.fromhex(last_round_key)
    for round_number in range(num_rounds, 0, -1):
        prev_columns = [None] * 4
        for i in range(1, 4):
            prev_columns[i] = xor(AES.get_column(
                next_key, i - 1), AES.get_column(next_key, i))
        transformed = AES.sub_word(AES.rot_word(prev_columns[-1]))
        prev_columns[0] = xor(xor(transformed, AES.rcon(
            round_number)), AES.get_column(next_key, 0))
        next_key = bytes(flatten(prev_columns))
    return next_key.hex()


def attack(enc_service, num_rounds, disable_tqdm=False):
    round_key = recover_round_key(enc_service, num_rounds, disable_tqdm)
    return reverse_key_expansion(round_key, num_rounds)
