def flatten(xs):
    return [i for sublist in xs for i in sublist]


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))
