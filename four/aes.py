from sbox import SBOX, INV_SBOX
from polynomial import GF_256_Polynomial

class AES:

    @staticmethod
    def sbox(r, c):
        return SBOX[16 * r + c]

    @staticmethod
    def inv_sbox(r, c):
        return INV_SBOX[16 * r + c]

    @staticmethod
    def rot_word(w):
        assert len(w) == 4, f"rot_word expects input to be 4 bytes, got {len(w)} bytes!"
        return w[1 : ] + w[0 : 1]
    
    @staticmethod
    def sub_word(w):
        assert len(w) == 4, f"sub_word expects input to be 4 bytes, got {len(w)} bytes!"
        return bytes(AES.sbox(lower, upper) for lower, upper in map(lambda b: ((b & 0b11110000) >> 4, b & 0b1111), w))
    
    @staticmethod
    def rcon(i):
        x = GF_256_Polynomial([1, 0])
        r = GF_256_Polynomial.pow(x, (i - 1) % 255).to_num()
        return bytes((r, 0, 0, 0))
