class GF_256_Polynomial:

    def __trim_zeros(self, coeffs):
        return [int(i) for i in "".join(map(str, coeffs)).rstrip("0")]

    def __init__(self, coeffs, rev = True):
        self.__coeffs = self.__trim_zeros(coeffs[::-1] if rev else coeffs)
        self.deg = len(self.__coeffs) - 1

    def coeffs(self):
        return self.__coeffs.copy()

    @staticmethod
    def from_num(num):
        return GF_256_Polynomial([int(i) for i in bin(num)[2 : ]])
    
    def to_num(self):
        return int("".join(map(str, self.__coeffs[::-1])), 2)

    def __mul__(self, other):
        res = [0] * (self.deg + other.deg + 1)
        for i, c1 in enumerate(self.__coeffs):
            for j, c2 in enumerate(other.coeffs()):
                res[i + j] ^= c1 * c2
        return GF_256_Polynomial(res, rev = False)

    def __add__(self, other):
        if self.deg >= other.deg:
            p1 = self.coeffs()
            p2 = other.coeffs()
        else:
            p1 = other.coeffs()
            p2 = self.coeffs()
        for i, c in enumerate(p2):
            p1[i] ^= c
        return GF_256_Polynomial(p1, rev = False)

    def __sub__(self, other):
        return self + other

    def shift(self, steps):
        return GF_256_Polynomial([0] * steps + self.__coeffs, rev = False)

    def __mod__(self, other):
        N = GF_256_Polynomial(self.coeffs(), rev = False)
        D = GF_256_Polynomial(other.coeffs(), rev = False)
        q = [0] * (N.deg + 1)
        while N.deg >= other.deg:
            deg_diff = N.deg - D.deg
            d = D.shift(deg_diff)
            q[deg_diff] = N.coeffs()[N.deg] * d.coeffs()[d.deg]
            d = d * GF_256_Polynomial([q[deg_diff]])
            N = N - d
        return N

    @staticmethod
    def pow(base, exp):
        res = GF_256_Polynomial([1])
        while exp > 0:
            if (exp & 1) == 1:
                res = (res * base) % GF_256_Polynomial.REDUCTION_POLY
            base = (base * base) % GF_256_Polynomial.REDUCTION_POLY
            exp >>= 1
        return res

# Ugly hack to have static member of same type as the class it is a member of
GF_256_Polynomial.REDUCTION_POLY = GF_256_Polynomial([1, 0, 0, 0, 1, 1, 0, 1, 1])
