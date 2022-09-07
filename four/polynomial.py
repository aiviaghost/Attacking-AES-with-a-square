class Polynomial:

    def __init__(self, coeffs):
        self.coeffs = coeffs[::-1]
        self.deg = len(self.coeffs) - 1

    @staticmethod
    def from_num(num):
        return Polynomial([int(i) for i in bin(num)[2 : ]])
    
    def to_num(self):
        return int("".join(map(str, self.coeffs[::-1])), 2)

    def __mul__(self, other):
        res = [0] * (self.deg + other.deg + 1)
        for i, c1 in enumerate(self.coeffs):
            for j, c2 in enumerate(other.coeffs):
                res[i + j] ^= c1 * c2
        return Polynomial(res)

    def __mod__(self, other):
        pass

    @staticmethod
    def pow(base, exp, mod):
        res = Polynomial([1])
        while exp > 0:
            if exp % 2 == 1:
                base = (base * base) % mod
            res = (res * base) % mod
            exp //= 2
        return res
