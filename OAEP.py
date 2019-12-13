import random
from Crypto.Hash import SHA512

n = 1024       # final length
k0 = 512       # appending random number length

def pad(msg):
    # generate 2 hashes
    G_hash = SHA512.new()
    H_hash = SHA512.new()

    # generate the random number
    r = format(random.getrandbits(k0), '0512b')
    # convert the message into binary
    bits = bin(int.from_bytes(msg.encode('utf8'),'big'))[2:]
    binMsg = bits.zfill(8*((len(bits) + 7) // 8))

    if len(binMsg) < n - k0:
        zeroMsg = binMsg + ('0' * (n - k0 - len(binMsg)))
    else:
        zeroMsg = binMsg

    # the OAEP algorithm, 4 steps using SHA512
    G_hash.update(r.encode('utf8'))
    x = format(int(zeroMsg, 2) ^ int(G_hash.hexdigest(), 16), '0512b')
    H_hash.update(x.encode('utf8'))
    y = format(int(H_hash.hexdigest(), 16) ^ int(r, 2), '0512b')

    return x + y, len(binMsg)

def unpad(msg, binLen):
    G_hash = SHA512.new()
    H_hash = SHA512.new()

    x = msg[:512]
    y = msg[512:]

    H_hash.update(x.encode('utf8'))
    r = format(int(y, 2) ^ int(H_hash.hexdigest(), 16), '0512b')
    G_hash.update(r.encode('utf8'))
    zeroMsg = format(int(x, 2) ^ int(G_hash.hexdigest(), 16), '0512b')
    message = zeroMsg[:binLen]

    return int(message, 2).to_bytes((int(message, 2).bit_length() + 7) // 8, 'big').decode('utf8')

if __name__ == '__main__':
    msg = input("input a message: ")
    padding, binLen = pad(msg)
    print("\npadding result: ", padding)
    print("\nunpadding result: ", unpad(padding, binLen))
