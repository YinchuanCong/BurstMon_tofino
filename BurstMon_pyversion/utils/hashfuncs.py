import random
import hashlib

_memomask = {}


def hash_function(n):
    """
    :param n: the index of the hash function
    :return: a generated hash function
    """
    mask = _memomask.get(n)

    if mask is None:
        random.seed(n)
        mask = _memomask[n] = random.getrandbits(32)

    def my_hash(x):
        return hash(str(x) + str(n)) ^ mask

    return my_hash