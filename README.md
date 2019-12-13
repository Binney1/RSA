# RSA
A simple implementation of RSA encryption algorithm.

## 实验目的

1. 复习巩固RSA非对称加密算法，尝试实现一个简单的RSA算法，并对公钥密码学有进一步的认识；
2. 理解textbook RSA算法的缺陷，并实现一个基于这种缺陷的选择明文攻击（Chosen-Ciphertext Attack），成功获得一个由RSA算法加密过的AES密钥；
3. 了解OAEP（Optimal Asymmetric Encryption Padding）的设计动机和实现原理，实现一个简单的OAEP并将其加入到RSA算法中。阐述添加OAEP给RSA算法带来的优势以及说明OAEP可以抵御之前所实现的那一种CCA2攻击。

## 实验环境

1. 操作系统：Windows 10
2. 程序语言：Python 3
3. IDE: JetBrains PyCharm

## 实验步骤和分析

### 1. 实现textbook RSA算法

首先回顾一下没有加任何填充的RSA算法的流程：

> 选择两个大素数 $p,q$，令 $n=pq$。选择一个指数 $e$ 并使得 $\gcd(e, \phi(n))=1$，其中$\phi(n)=(p-1)(q-1)$。再找一个 $d$ 使得 $ed\equiv1\pmod{\phi(n)}$。
>
> 将$(e,n)$作为公钥，将$(d,n)$作为私钥。
>
> 加密明文 $M$ 时，密文 $C\equiv M^e\pmod{n}$.
>
> 解密密文 $C$ 时，明文 $M\equiv C^d\pmod{n}$.

由此，我们可以得到我们程序的几个模块：

1. 模运算模块。包括欧几里得和扩展欧几里得算法、求乘法逆元以及快速幂的部分。
2. 素数模块。包括素数生成、Miller-Rabin素性测试的部分
3. RSA实现模块。包括对消息的加解密部分。



#### 模运算模块`modulo.py`

这部分主要包括四个函数。`gcd(a,b)`是使用欧几里得算法求两数的最大公因数，`extended_gcd`和`inverse`两个函数综合起来是求一个数在模运算意义下的乘法逆元，而`quick_mul`函数是采用为运算方法实现的模运算意义下的快速幂运算。

这个模块的各个函数主要作为后面其他模块的工具函数使用。



#### 素数模块`prime.py`

这部分包含四个函数。`miller_rabin(n)`是采用Miller-Rabin素性测试来检验一个大整数是否为素数的函数。在实现中，我采用了20轮的素性测试，这在现实情况下已经早就满足要求，几乎不可能出现Miller-Rabin素性测试中的伪证情况。

`is_prime`函数判断一个整数是否为素数。在数字比较小的情况下，该算法直接查素数表（程序中给出了1000以内的素数表），同时将这些素数的所有倍数筛除。而在数字比较大且没有被筛除的情况下，该函数就会调用上面的`miller_rabin`来进行素性检验。

`gen_prime`函数根据所给的位数随机生成一个范围内的整数，判断其是否为素数，如是素数则输出，不是则再次生成。

`gen_prime_pair`函数用来生成RSA加密所需要的两个素数$p,q$。首先生成两个长度为$n$的一半的素数，计算其乘积位数，如果乘积位数不满足要求则对这两个素数进行微调直到满足要求为止，这个主要步骤的代码如下：

```python
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
```



#### RSA实现模块`textbook_rsa.py`

有了前两个模块的帮助，RSA的实现变得很简单。

首先读入RSA的密钥长度，然后分别调用`gen_prime_pair`和`inverse`函数用来生成所需要的公私钥和公开参数。

然后程序会请求输入一个明文，用公钥进行加密，输出加密后的密文。随后程序会对其进行解密，输出解密后的明文。这部分的实现代码如下：

```python
# encryption
message = input("\nmessage = ")
plaintext = binascii.b2a_hex(bytes(message, encoding='utf8'))
ciphertext = modulo.quick_mul(int(plaintext, 16), e, n)
print("\nencrypted = ", ciphertext)

# decryption
decrypt = modulo.quick_mul(ciphertext, d, n)
decrypt = hex(decrypt)
print("\ndecrypted = ", str(binascii.a2b_hex(decrypt[2:]), encoding='utf8'))
```

由于RSA算法加密的是一个数字，所以我们必须要把输入的明文转换为数字之后才能执行加密算法。为了完成这项工作，我们引入了`binascii`包，其中包含字节流和数字的转换函数。`b2a_hex`函数将字节流转换成十六进制数字，而`a2b_hex`将十六进制数字转换为字节流。

上述代码的第2行首先将输入字符串用utf-8编码为字节流，然后调用`b2a_hex`将字节流转换成十六进制的数字。第4行将得到的输入用RSA的方式进行公钥加密。第8行用私钥对得到的密文进行解密，第9行将解密结果转换成表示十六进制数的字符串。第10行则将这个字符串表示的数字转换成字节流后，用utf-8编码成最后的结果字符串。



### 2. 实现对textbook RSA的CCA2攻击 `CCA2.py`

这部分主要是根据*When Textbook RSA is Used to Protect the Privacy of Hundreds of Millions of Users*这篇论文中提出的一种针对textbook RSA的CCA2攻击，复现攻击过程。

回顾这个CCA2攻击，其依据和方法是：

> 令 $C$ 是一个128-bit的AES密钥 $k$ 的加密结果，公钥是$(n,e)$。因此我们有
> $$
> C\equiv k^e\pmod{n}
> $$
> 现在令 $C_b$ 是 $k$ 左移 $b$ 位后的密钥的RSA加密密文，即
> $$
> k_b=2^b k\\
> C_b\equiv (k_b)^e\pmod{n}
> $$
> 此时，我们就可以**仅由 $C$ 和公钥**计算出 $C_b$ 而不需要知道 $k_b$， 方法如下（第一行为结论，下面为证明）：
> $$
> \begin{aligned} C_{b} & \equiv C\left(2^{b c} \bmod n\right) \quad(\bmod n) \\ & \equiv\left(k^{e} \bmod n\right)\left(2^{b c} \bmod n\right) \quad(\bmod n) \\ & \equiv k^{c} 2^{b c} \quad(\bmod n) \\ & \equiv\left(2^{b} k\right)^{c} \quad(\bmod n) \\ & \equiv k_{b}^{e} \quad(\bmod n) \end{aligned}
> $$
> 所以我们的攻击就是从 $C_{127}$ 开始一个个试，猜测 $k_{127}$ 首位为1，并将 $C_{127}$ 和一个由 $k_{127}$ 加密的AES密文发给服务器。根据服务器发回的相应判断这一位究竟是1还是0（是1则服务器能正确解密，否则发回解密错误）。以此类推，得到最终密钥的所有128位。

这一部分主要定义了两个函数，`CCA`和`response`。前者是模拟攻击者向服务器发送伪造的WUP包从而一步步得到AES密钥的过程，而后者则模拟了服务器在收到这些消息之后会作出怎样的回复。

在开始攻击之前，我先生成了1024-bit的RSA密钥、一个128-bit的AES密钥，将真正传输的消息`This is the real message!`用AES加密，将AES密钥用RSA加密，代码如下：

```python
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
```


其中，`request eavesdropped`表示攻击者所接收到的使用AES加密后的明文。

值得一提的是，AES加密部分我采用的是`Crypto`包中的相关函数，但在使用是我做了一点小小的修改，具体实现在`aes.py`中，其中用到`binascii`包的部分与上一部分基本一致：

```python
from Crypto.Cipher import AES
import binascii

class AESCrypto():
    def __init__(self, key, mode = AES.MODE_ECB):
        self.key = key
        self.mode = mode     # 默认采用ECB加密模式
        self.cryptor = AES.new(self.key, self.mode)

    def encrypt(self, plaintext):
        # 以下是在明文不够长度时的填充
        if len(plaintext) % 16 != 0:
            plaintext = plaintext + (16 - len(plaintext) % 16) * '\0'
        ciphertext = self.cryptor.encrypt(plaintext)
        return str(binascii.b2a_hex(ciphertext), 'utf8')

    def decrypt(self, ciphertext):
        plaintext = self.cryptor.decrypt(binascii.a2b_hex(ciphertext))
        return  plaintext
```



#### CCA2攻击函数`CCA`

这个函数是对CCA2攻击的模拟。

首先初始化猜测的密钥`guess_key`为0，测试用的WUP包为`“test WUP request”`，然后开始128轮的迭代寻找。

在每一次迭代中，利用论文中给出的公式，程序会先计算 $C_b$ ：

```python
# 第b轮迭代
factor = modulo.quick_mul(2, (127 - b) * e, n)
C_b = modulo.quick_mul(C * factor, 1, n)
```

然后猜测 $k_b$ 的最高位是1，生成伪造的WUP密文，并将其一同发送给服务器（在本程序中即为调用`response`函数）：

```python
attempt_key_b = (1 << 127) + (guess_key << (127 - b))   # 伪造的AES密钥

# 用伪造的AES密钥加密测试信息
forge_aes = aes.AESCrypto(binascii.a2b_hex(hex(attempt_key_b)[2:]))
encrypted_msg = forge_aes.encrypt(WUP)

# 将C_b和伪造的信息发送给服务器
res = response(C_b, encrypted_msg, d, n)
```

`response`函数会返回用 $C_b$ 中包含的AES密钥对加密信息解密的结果。如果解密成功，它就会返回`“test WUP request”`，否则它就会返回乱码。因此，如果第一次发送后就得到了正确的结果，那么正在猜测的这一位就为1，否则就将这一位改为0，重复上述过程，发送给服务器，若服务器给出正确结果（事实上这么做一定能得到正确结果），则将这一位确定为0：

```python
if(res == b"test WUP request"):
    # the current bit should be 1
    guess_key = guess_key + (1 << b)
    print("k{}: ".format(127 - b), hex(guess_key << (127 - b))[2:])
else:
    # the current bit should be 0, resend the forged message
    attempt_key_b = guess_key << (127 - b)
    print("trying k{}: ".format(127 - b), hex(attempt_key_b)[2:])

    # pad with 0s in the head to avoid encoding errors
    str = ""
    for i in hex(attempt_key_b)[2:]:
        str += i
    str = '0' * (32 - len(str)) + str

    # redo AES encryption
    forge_aes = aes.AESCrypto(binascii.a2b_hex(str))
    encrypted_msg = forge_aes.encrypt(WUP)
    print("encrypted_msg: ", encrypted_msg)

    res = response(C_b, encrypted_msg, d, n)
    print("response: ", res)

    # confirm the current bit is 0
    if(res == b"test WUP request"):
        print("k{}: ".format(127 - b), hex(guess_key << (127 - b))[2:])
```

在结束128轮迭代后，我们的 $k_0$ 就是原来真正的AES密钥了，于是函数将其返回。



#### 响应函数`response`

这个函数的作用是根据接收到的 $C_b$ 和加密后的WUP包，返回正常解密的结果。需要注意的是，在AES解密之前，要把不足的位数用0填充。最后函数返回的是一个`bytes`类型的解密结果。具体实现代码如下：

```python
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
```



### 3. 实现RSA加密中的OAEP填充

OAEP(Optimal Asymmetric Encryption Padding)是一种在实际RSA应用中常用的填充策略。上面提到，textbook RSA由于没有填充过程，虽然不能直接恢复出明文，但可以随意获得明文移位后的密文。该问题的根本原因是textbook RSA是一种确定性的加密方法。而OAEP的引入可以带来下面两点优势：

+ 加入随机性成分，使得RSA加密从原来的确定性加密转变为一种概率性加密
+ 防止攻击者对密文的部分解密，即若单向陷门不可逆，则不可能恢复出明文经过任意移位变换后的任何一部分信息

我们需要实现两次哈希和两次异或操作。

#### OAEP模块实现`OAEP.py`

**参数和函数的选取：**首先我们要选取两个哈希函数，即图中的G和H。我们最后需要得到的定长的填充后的结果是1024-bit的，且考虑到图中的r部分的哈希要和m000…00部分异或，X部分的哈希要和r部分异或，异或的两个数位数应该保持一致，所以我们不妨将X和Y的位数都设置成512-bit，这样哈希值就可以直接参与异或，这也决定了我们选用的哈希函数是**SHA512, 且k0=512**，SHA512可以在`Crypto.Hash`中找到。

这个模块包括两个函数，填充函数`pad`和其反函数`unpad`

在填充过程中，我们先创建两个新的SHA512对象，然后生成一个512-bit的随机数。随后，我们对明文进行填充，把它补到512-bit长。这部分的代码如下：

```python
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
```

随后，我们执行$X=m00\ldots0 \oplus G(r), Y=r\oplus H(X)$两步，代码如下：

```python
# the OAEP algorithm, 4 steps using SHA512
G_hash.update(r.encode('utf8'))
x = format(int(zeroMsg, 2) ^ int(G_hash.hexdigest(), 16), '0512b')
H_hash.update(x.encode('utf8'))
y = format(int(H_hash.hexdigest(), 16) ^ int(r, 2), '0512b')
```

我使用SHA512对象的`update`方法来将要哈希的值存入其中，然后使用`hexdigest`方法来获取哈希值，同时将异或结果用`format`函数变为字符串。

而在解填充的过程中，类似地，我们还是复现OAEP算法中的各个步骤。其中的X和Y是对输入的填充后的消息直接分割得到的。实现代码如下：

```python
G_hash = SHA512.new()
H_hash = SHA512.new()

x = msg[:512]
y = msg[512:]

H_hash.update(x.encode('utf8'))
r = format(int(y, 2) ^ int(H_hash.hexdigest(), 16), '0512b')
G_hash.update(r.encode('utf8'))
zeroMsg = format(int(x, 2) ^ int(G_hash.hexdigest(), 16), '0512b')
message = zeroMsg[:binLen]
```

实现了这两个函数后，我对OAEP模块进行了测试：

```python
if __name__ == '__main__':
    msg = input("input a message: ")
    padding, binLen = pad(msg)
    print(padding)
    print(unpad(padding, binLen))
```

读入一条消息，对其进行填充，输出填充后的值，再解填充，比对是否成功解密。

#### 实现RSA with OAEP`rsaOAEP.py`

有了OAEP模块后，我们只要简单地将其加入到RSA中，就可以得到带填充版本的RSA。RSA加密的核心代码如下：

```python
padding, binLen = pad(message)
plaintext = int(padding,2)
ciphertext = modulo.quick_mul(plaintext, e, n)
decrypt = modulo.quick_mul(ciphertext, d, n)
decrypt = bin(decrypt)
decrypted = unpad(decrypt[2:], binLen)
```

可以看到，与之前的RSA不同的地方只有在加密前进行填充和在解密后进行解填充。

RSA运行正常。

#### RSAOAEP相较于textbook RSA的优点

+ 加入了一定的随机性，使得即使是相同的明文，在RSAOAEP的加密下，也可能呈现出不同的结果，这使得其成为了一种概率性加密方案
+ 由于哈希函数的参与，相当于明文的各个部分已经被打乱了，然后由明文的信息摘要参与加密过程，从而在不能反转陷门单向函数的前提下，明文的各个部分的相互关系对破解它们并没有什么帮助，因为明文的某些既定模式已经被哈希函数所混淆掉了

#### 抵御上述的CCA2攻击

上述的CCA2攻击基于的是可以在不知道明文的情况下得到明文经过移位操作后的密文这一事实，这就相当于可以得到明文的部分信息。而在RSAOAEP中，明文的任意部分信息都是不可以被攻击者获得到的，也就是说，明文移位后所对应的密文与原来明文所对应的密文之间没有必然联系。因此，RSAOAEP可以成功抵御上述的CCA2攻击。

然而，近期的许多工作已经表明：在使用标准模型，假定的RSA难题的强度下无法证明RSAOAEP具有IND-CAA2的安全性。因此，仅知道它可以抵御这个特定的CCA2攻击而已。


