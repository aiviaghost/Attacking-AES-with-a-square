from polynomial import GF_256_Polynomial


class GF_256_Matrix:

    def __init__(self, M):
        self.M = [[GF_256_Polynomial.from_num(i) for i in row] for row in M]
        self.r = len(self.M)
        self.c = len(self.M[0])

    def __mul__(self, other):
        assert self.c == other.r, "Invalid dimensions for multiplication!"
        n, m, p = self.r, self.c, other.c
        res = GF_256_Matrix.__zeros(n, p)
        for i in range(n):
            for j in range(p):
                for k in range(m):
                    res.M[i][j] += self.M[i][k] * other.M[k][j]
        return res

    def shape(self):
        return self.r, self.c

    def __add__(self, other):
        assert self.shape() == other.shape(), "Matrix shapes need to be equal!"
        n, m = self.r, self.c
        res = GF_256_Matrix.__zeros(n, m)
        for i in range(n):
            for j in range(m):
                res.M[i][j] = self.M[i][j] + other.M[i][j]
        return res

    def to_list(self):
        return [[i.to_num() for i in row] for row in self.M]

    @staticmethod
    def __zeros(r, c):
        return GF_256_Matrix([[0 for _ in range(c)] for _ in range(r)])

    @staticmethod
    def vector(xs):
        return GF_256_Matrix([[i] for i in xs])
