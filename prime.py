import random
import modulo

small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
                71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
                157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239,
                241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337,
                347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433,
                439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
                547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641,
                643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743,
                751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857,
                859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971,
                977, 983, 991, 997]

# Miller-Rabin Primality Testing
def miller_rabin(n):
    s = n - 1
    t = 0
    while s % 2 == 0:
        s = s // 2
        t += 1

    for times in range(20):
        a = random.randrange(2, n - 1)
        v = modulo.quick_mul(a, s, n)
        if v != 1:
            i = 0
            while v != n - 1:
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % n

    return True

# Test if a number is a prime
def is_prime(n):
    if n < 2:
        return False
    if n in small_primes:
        return True
    for prime in small_primes:
        if n % prime == 0:
            return  False
    return miller_rabin(n)

# Generate big primes
def gen_prime(size = 1024):
    while True:
        n = random.randrange(2 ** (size - 1), 2 ** size)
        if is_prime(n):
            return n

# Given key size, generate two primes p, q, s.t. p * q = n with the given size
def gen_prime_pair(size = 1024):
    size_p = size // 2
    size_q = size - size_p
    p_or_q = 0

    while True:
        p = gen_prime(size_p)
        q = gen_prime(size_q)
        x = p * q
        k = x.bit_length()
        if k > size and p_or_q == 0:
            size_p -= 1
            p_or_q = 1
            continue
        if k > size and p_or_q == 1:
            size_q -= 1
            p_or_q = 0
            continue
        if k < size and p_or_q == 0:
            size_p += 1
            p_or_q = 1
            continue
        if k < size and p_or_q == 1:
            size_q += 1
            p_or_q = 0
            continue
        if k == size:
            break

    return p, q