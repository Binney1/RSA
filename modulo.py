# Euclidean Algorithm
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Extended Euclidean Algorithm
def extended_gcd(a, b):
    u, v, s, t = 1, 0, 0, 1
    # Swap
    if (b < a):
        tmp = b
        b = a
        a = tmp
    while b != 0:
        q = a // b
        a, b = b, a - q * b
        u, s = s, u - q * s
        v, t = t, v - q * t
    return a, u, v

# Get multiplication inverse using Extended Euclidean Algorithm
def inverse(e, phi):
    (_, inv, _) = extended_gcd(e, phi)
    while(inv < 0):
        inv += phi
    return inv

# Quick module multiplication
def quick_mul(base, power, mod):
    base %= mod
    ans = 1
    while power != 0:
        if power & 1 == 1:
            ans = (ans * base) % mod
        power >>= 1
        base = (base * base) % mod
    return ans