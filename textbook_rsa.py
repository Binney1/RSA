import binascii
import modulo
import prime

# key generation
size = eval(input("key size: "))
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

# encryption
message = input("\nmessage = ")
plaintext = binascii.b2a_hex(bytes(message, encoding='utf8'))
ciphertext = modulo.quick_mul(int(plaintext, 16), e, n)
print("\nencrypted = ", ciphertext)

# decryption
decrypt = modulo.quick_mul(ciphertext, d, n)
decrypt = hex(decrypt)
print("\ndecrypted = ", str(binascii.a2b_hex(decrypt[2:]), encoding='utf8'))
