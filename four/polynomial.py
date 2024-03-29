class GF_256_Polynomial:

    def __trim_zeros(self, coeffs):
        return [int(i) for i in "".join(map(str, coeffs)).rstrip("0")]

    def __init__(self, coeffs):
        self.__coeffs = self.__trim_zeros(coeffs)
        self.deg = len(self.__coeffs) - 1

    @staticmethod
    def from_coeffs(coeffs):
        return GF_256_Polynomial(coeffs[::-1]) % GF_256_Polynomial.REDUCTION_POLY

    @staticmethod
    def from_num(num):
        return GF_256_Polynomial.from_coeffs([int(i) for i in bin(num)[2:]])

    def to_num(self):
        return int("".join(map(str, self.__coeffs[::-1])), 2) if self.deg >= 0 else 0

    def coeffs(self):
        return self.__coeffs.copy()

    def __mul__(self, other):
        res = [0] * (self.deg + other.deg + 1)
        for i, c1 in enumerate(self.__coeffs):
            for j, c2 in enumerate(other.__coeffs):
                res[i + j] ^= c1 * c2
        return GF_256_Polynomial(res) % GF_256_Polynomial.REDUCTION_POLY

    def __add__(self, other):
        if self.deg >= other.deg:
            p1 = self.coeffs()
            p2 = other.__coeffs
        else:
            p1 = other.coeffs()
            p2 = self.__coeffs
        for i, c in enumerate(p2):
            p1[i] ^= c
        return GF_256_Polynomial(p1) % GF_256_Polynomial.REDUCTION_POLY

    def __sub__(self, other):
        return self + other

    def __shift(self, steps):
        return GF_256_Polynomial([0] * steps + self.__coeffs)

    def __mod__(self, other):
        N = GF_256_Polynomial(self.__coeffs)
        D = GF_256_Polynomial(other.__coeffs)
        while N.deg >= other.deg:
            N = N - D.__shift(N.deg - D.deg)
        return N

    @staticmethod
    def pow(base, exp):
        exp = exp % 255
        res = GF_256_Polynomial([1])
        while exp > 0:
            if (exp & 1) == 1:
                res = res * base
            base = base * base
            exp >>= 1
        return res

    def __pow__(self, exp):
        return GF_256_Polynomial.pow(self, exp)


# Ugly hack to have static member of same type as the class it is a member of
# This is the "AES-polynomial", x^8 + x^4 + x^3 + x + 1
GF_256_Polynomial.REDUCTION_POLY = GF_256_Polynomial(
    [1, 0, 0, 0, 1, 1, 0, 1, 1][::-1])
