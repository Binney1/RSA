import prime
import modulo
from OAEP import pad, unpad

class Myerror(RuntimeError):
    def __init__(self, arg):
        self.args = arg

size = 1024
while True:
    p, q = prime.gen_prime_pair(size)
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)

    if modulo.gcd(e, phi) == 1:
        break
d = modulo.inverse(e, phi)

print("\npublic key: ", e, ',', n)
print("\nprivate key: ", d)

message = input("\ninput a message: ")
while True:
    try:
        padding, binLen = pad(message)
        plaintext = int(padding,2)
        ciphertext = modulo.quick_mul(plaintext, e, n)
        decrypt = modulo.quick_mul(ciphertext, d, n)
        decrypt = bin(decrypt)
        decrypted = unpad(decrypt[2:], binLen)
        if decrypted != message:
            raise Myerror("unequal")
    except UnicodeDecodeError:
        pass
    except Myerror:
        pass
    else:
        print("\nencrypted = ", ciphertext)
        print("\ndecrypted = ", decrypted)
        break