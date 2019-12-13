from Crypto.Cipher import AES
import binascii

class AESCrypto():
    def __init__(self, key, mode = AES.MODE_ECB):
        self.key = key
        self.mode = mode
        self.cryptor = AES.new(self.key, self.mode)

    def encrypt(self, plaintext):
        if len(plaintext) % 16 != 0:
            plaintext = plaintext + (16 - len(plaintext) % 16) * '\0'
        ciphertext = self.cryptor.encrypt(plaintext)
        return str(binascii.b2a_hex(ciphertext), 'utf8')

    def decrypt(self, ciphertext):
        plaintext = self.cryptor.decrypt(binascii.a2b_hex(ciphertext))
        return  plaintext