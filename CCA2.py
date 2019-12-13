import aes
import modulo
import prime
import random
import binascii

# The CCA attack implementation
def CCA(C, e, n, d):
    guess_key = 0
    WUP = "test WUP request"
    # try 128 times
    for b in range(128):
        print("----------round {}----------".format(b))
        # 2 ^ (b * e) in the paper
        factor = modulo.quick_mul(2, (127 - b) * e, n)
        C_b = modulo.quick_mul(C * factor, 1, n)
        print("\nC_{}: ".format(127 - b), C_b)

        attempt_key_b = (1 << 127) + (guess_key << (127 - b))
        print("trying k{}: ".format(127 - b), hex(attempt_key_b)[2:])

        forge_aes = aes.AESCrypto(binascii.a2b_hex(hex(attempt_key_b)[2:]))
        encrypted_msg = forge_aes.encrypt(WUP)
        print("encrypted_msg: ", encrypted_msg)

        res = response(C_b, encrypted_msg, d, n)
        print("response: ", res)

        if(res == b"test WUP request"):
            # the current bit should be 1
            guess_key = guess_key + (1 << b)
            print("k{}: ".format(127 - b), hex(guess_key << (127 - b))[2:])
        else:
            # the current bit should be 0, resend the forged message
            attempt_key_b = guess_key << (127 - b)
            print("trying k{}: ".format(127 - b), hex(attempt_key_b)[2:])

            str = ""
            for i in hex(attempt_key_b)[2:]:
                str += i
            str = '0' * (32 - len(str)) + str

            forge_aes = aes.AESCrypto(binascii.a2b_hex(str))
            encrypted_msg = forge_aes.encrypt(WUP)
            print("encrypted_msg: ", encrypted_msg)

            res = response(C_b, encrypted_msg, d, n)
            print("response: ", res)

            if(res == b"test WUP request"):
                print("k{}: ".format(127 - b), hex(guess_key << (127 - b))[2:])

        print("----------------------------")

    return guess_key


def response(C_b, encrypted_WUP, d, n):
    # RSA decryption
    k_b = bin(modulo.quick_mul(C_b, d, n))[-128:]
    k_b = int(k_b, 2)

    # pad with 0
    str = ""
    for i in hex(k_b)[2:]:
        str += i
    str = '0' * (32 - len(str)) + str

    # AES decryption
    dec_aes = aes.AESCrypto(binascii.a2b_hex(str))
    decrypted_WUP = dec_aes.decrypt(encrypted_WUP)

    return decrypted_WUP

if __name__ == '__main__':
    while True:
        p, q = prime.gen_prime_pair(1024)
        n = p * q
        e = 65537
        phi = (p - 1) * (q - 1)

        if modulo.gcd(e, phi) == 1:
            break
    d = modulo.inverse(e, phi)

    aes_key = random.randrange(1 << 127, 1 << 128)

    print("\npublic key", e, ',', n)
    print("\nprivate key", d)
    print("\naes_key = ", aes_key)
    print("\naes_key in hex = ", hex(aes_key)[2:])

    encrypted_aes_key = modulo.quick_mul(aes_key, e, n)
    print("\nencrypted_aes_key = ", encrypted_aes_key)

    real_message = "This is the real message!"
    real_aes = aes.AESCrypto(binascii.a2b_hex(hex(aes_key)[2:]))
    request = real_aes.encrypt(real_message)
    print("\nreal request = ", real_message)
    print("\nrequest eavesdropped = ", request)

    guess_key = CCA(encrypted_aes_key, e, n, d)
    print("\nguess_key: ", hex(guess_key)[2:])

    print("\ntrying to decrypt the request...")

    try_aes = aes.AESCrypto(binascii.a2b_hex(hex(guess_key)[2:]))
    try_plaintext = str(try_aes.decrypt(request), 'utf8')
    print("\nreal request: ", real_message)
    print("\nCCA2 result: ", try_plaintext)
