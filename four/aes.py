from matrix import GF_256_Matrix
from polynomial import GF_256_Polynomial
from rijndael_sbox import RIJNDAEL_SBOX, INV_RIJNDAEL_SBOX
from util import flatten

class AES:

    ROUNDS = 10

    SBOX = RIJNDAEL_SBOX

    INV_SBOX = INV_RIJNDAEL_SBOX

    MIX_MATRIX = GF_256_Matrix([
        [2, 3, 1, 1],
        [1, 2, 3, 1],
        [1, 1, 2, 3],
        [3, 1, 1, 2]
    ])

    INV_MIX_MATRIX = GF_256_Matrix([
        [14, 11, 13, 9],
        [9, 14, 11, 13],
        [13, 9, 14, 11],
        [11, 13, 9, 14]
    ])

    @staticmethod
    def rot_word(w):
        assert len(w) == 4, f"rot_word expects input to be 4 bytes, got {len(w)} bytes!"
        return w[1 : ] + w[0 : 1]
    
    @staticmethod
    def inverse_rot_word(w):
        assert len(w) == 4, f"inverse_rot_word expects input to be 4 bytes, got {len(w)} bytes!"
        return w[-1 : ] + w[ : -1]

    @staticmethod
    def sub_word(w, sbox = SBOX):
        assert len(w) == 4, f"sub_word expects input to be 4 bytes, got {len(w)} bytes!"
        return bytes(sbox[16 * lower + upper] for lower, upper in map(lambda b: ((b & 0b11110000) >> 4, b & 0b1111), w))
    
    @staticmethod
    def inverse_sub_word(w):
        return AES.sub_word(w, sbox = AES.INV_SBOX)

    @staticmethod
    def rcon(i):
        x = GF_256_Polynomial.from_coeffs([1, 0])
        r = GF_256_Polynomial.pow(x, i - 1).to_num()
        return bytes((r, 0, 0, 0))
    
    @staticmethod
    def __xor(a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    @staticmethod
    def __get_column(key, column_index):
        assert 0 <= column_index <= 3, "Invalid column index!"
        return key[column_index * 4 : (column_index + 1) * 4]

    @staticmethod
    def key_expansion(original_key):
        round_keys = [bytes.fromhex(original_key)]
        for round_number in range(1, AES.ROUNDS + 1):
            first_word = AES.__get_column(round_keys[-1], 0)
            last_word = AES.__get_column(round_keys[-1], 3)
            transformed = AES.sub_word(AES.rot_word(last_word))
            next_word = AES.__xor(AES.__xor(first_word, transformed), AES.rcon(round_number))
            next_key = [next_word]
            for i in range(1, 4):
                next_key.append(AES.__xor(next_key[-1], AES.__get_column(round_keys[-1], i)))
            round_keys.append(bytes(flatten(next_key)))
        return [key.hex() for key in round_keys]
    
    @staticmethod
    def sub_bytes(state, sub_function = sub_word.__func__):
        b = bytes.fromhex(state)
        return bytes(flatten([sub_function(AES.__get_column(b, i)) for i in range(4)])).hex()

    @staticmethod
    def inverse_sub_bytes(state):
        return AES.sub_bytes(state, AES.inverse_sub_word)

    @staticmethod
    def __get_rows(state):
        return [[state[i + j] for j in range(0, len(state), 4)] for i in range(4)]

    @staticmethod
    def shift_rows(state, rot_function = rot_word.__func__):
        rows = AES.__get_rows(bytes.fromhex(state))
        for i in range(1, 4):
            for j in range(i, 4):
                rows[j] = rot_function(rows[j])
        return bytes(flatten(AES.__get_rows(flatten(rows)))).hex()

    @staticmethod
    def inverse_shift_rows(state):
        return AES.shift_rows(state, AES.inverse_rot_word)

    @staticmethod
    def mix_columns(state, matrix = MIX_MATRIX):
        b = bytes.fromhex(state)
        new_state = []
        for column_index in range(4):
            column_vector = GF_256_Matrix.vector(AES.__get_column(b, column_index))
            res = matrix * column_vector
            column = flatten(res.to_list())
            new_state.append(column)
        return bytes(flatten(new_state)).hex()

    @staticmethod
    def inverse_mix_columns(state):
        return AES.mix_columns(state, matrix = AES.INV_MIX_MATRIX)

    @staticmethod
    def add_round_key(state, round_key):
        return AES.__xor(bytes.fromhex(state), bytes.fromhex(round_key)).hex()

    @staticmethod
    def inverse_add_round_key(state, round_key):
        return AES.add_round_key(state, round_key)
    
    @staticmethod
    def encrypt(plaintext, key):
        assert len(plaintext) == 16, "Plaintext must be exactly 16 bytes!"
        assert len(key) == 32, "Key must be exactly 32 bytes in hex!"
        pt = plaintext.encode().hex()
        round_keys = AES.key_expansion(key)
        ct = AES.add_round_key(pt, round_keys[0])
        for i in range(1, AES.ROUNDS):
            transformations = [AES.sub_bytes, AES.shift_rows, AES.mix_columns, lambda x: AES.add_round_key(x, round_keys[i])]
            for f in transformations:
                ct = f(ct)
        return AES.add_round_key(AES.shift_rows(AES.sub_bytes(ct)), round_key = round_keys[-1])

    @staticmethod
    def decrypt(ciphertext, key):
        assert len(ciphertext) == 32, "Plaintext must be exactly 32 bytes in hex!"
        assert len(key) == 32, "Key must be exactly 32 bytes in hex!"
        round_keys = AES.key_expansion(key)
        pt = AES.inverse_sub_bytes(AES.inverse_shift_rows(AES.inverse_add_round_key(ciphertext, round_key = round_keys[-1])))
        for i in range(AES.ROUNDS - 1, 0, -1):
            transformations = [lambda x: AES.inverse_add_round_key(x, round_keys[i]), AES.inverse_mix_columns, AES.inverse_shift_rows, AES.inverse_sub_bytes]
            for f in transformations:
                pt = f(pt)
        return bytes.fromhex(AES.inverse_add_round_key(pt, round_key = round_keys[0])).decode()
