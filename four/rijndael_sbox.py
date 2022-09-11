from polynomial import GF_256_Polynomial
from matrix import GF_256_Matrix
from util import flatten

transform_matrix = GF_256_Matrix([
    [1, 0, 0, 0, 1, 1, 1, 1],
    [1, 1, 0, 0, 0, 1, 1, 1],
    [1, 1, 1, 0, 0, 0, 1, 1],
    [1, 1, 1, 1, 0, 0, 0, 1],
    [1, 1, 1, 1, 1, 0, 0 ,0],
    [0, 1, 1, 1, 1, 1, 0, 0],
    [0, 0, 1, 1, 1, 1, 1, 0],
    [0, 0, 0, 1, 1, 1, 1, 1]
])

transform_vector = GF_256_Matrix.vector([1, 1, 0, 0, 0, 1, 1, 0])

def pad(xs):
    return xs + [0] * (8 - len(xs))

def transform(num):
    inv = GF_256_Polynomial.from_num(num) ** -1
    bit_vector = GF_256_Matrix.vector(pad(inv.coeffs()))
    transformed = transform_matrix * bit_vector + transform_vector
    return GF_256_Polynomial(flatten(transformed.to_list())).to_num()

RIJNDAEL_SBOX = [transform(i) for i in range(256)]

INV_RIJNDAEL_SBOX = [RIJNDAEL_SBOX.index(i) for i in range(len(RIJNDAEL_SBOX))]
