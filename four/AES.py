from sbox import SBOX, INV_SBOX
from polynomial import Polynomial

class AES:

    POLY_MOD = Polynomial([1, 0, 0, 0, 1, 1, 0, 1, 1])

    @staticmethod
    def sbox(r, c):
        return SBOX[16 * r + c]

    @staticmethod
    def inv_sbox(r, c):
        return INV_SBOX[16 * r + c]

    @staticmethod
    def RotWord(w):
        assert len(w) == 4, f"RotWord expects input to be 4 bytes!, got {len(w)}"
        return w[1 : ] + w[0 : 1]
    
    @staticmethod
    def SubWord(w):
        assert len(w) == 4, f"SubWord expects input to be 4 bytes!, got {len(w)}"
        return bytes(AES.sbox(lower, upper) for lower, upper in map(lambda b: ((b & 0b11110000) >> 4, b & 0b1111), w))
    
    @staticmethod
    def Rcon(i):
        x = Polynomial([1, 0])
        r = Polynomial.pow(x, i - 1, AES.POLY_MOD).to_num()
        return bytes((r, 0, 0 , 0))
