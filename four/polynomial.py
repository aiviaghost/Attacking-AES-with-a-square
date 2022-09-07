class GF_256_Polynomial:

    def __trim_zeros(self, coeffs):
        return [int(i) for i in "".join(map(str, coeffs)).rstrip("0")]

    def __init__(self, coeffs, rev = True):
        self.coeffs = self.__trim_zeros(coeffs[::-1] if rev else coeffs)
        self.deg = len(self.coeffs) - 1

    @staticmethod
    def from_num(num):
        return GF_256_Polynomial([int(i) for i in bin(num)[2 : ]])
    
    def to_num(self):
        return int("".join(map(str, self.coeffs[::-1])), 2)

    def __mul__(self, other):
        res = [0] * (self.deg + other.deg + 1)
        for i, c1 in enumerate(self.coeffs):
            for j, c2 in enumerate(other.coeffs):
                res[i + j] ^= c1 * c2
        return GF_256_Polynomial(res, rev = False)

    def __add__(self, other):
        if self.deg >= other.deg:
            p1 = self.coeffs
            p2 = other.coeffs
        else:
            p1 = other.coeffs
            p2 = self.coeffs
        for i, c in enumerate(p2):
            p1[i] ^= c
        return GF_256_Polynomial(p1, rev = False)
    
    def __sub__(self, other):
        return self + other

    def __mod__(self, other):
        pass

    @staticmethod
    def pow_mod(base, exp, mod):
        res = GF_256_Polynomial([1])
        while exp > 0:
            if (exp & 1) == 1:
                base = (base * base) % mod
            res = (res * base) % mod
            exp >>= 1
        return res
