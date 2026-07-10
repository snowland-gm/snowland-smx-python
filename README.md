# snowland-smx

[![version](https://img.shields.io/pypi/v/snowland-smx.svg)](https://pypi.python.org/pypi/snowland-smx)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fsnowland-gm%2Fsnowland-smx-python.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fsnowland-gm%2Fsnowland-smx-python?ref=badge_shield)
[![gitee](https://gitee.com/snowlandltd/snowland-smx-python/badge/star.svg)](https://gitee.com/snowlandltd/snowland-smx-python/stargazers)
[![github](https://img.shields.io/github/stars/snowland-gm/snowland-smx-python)](https://github.com/snowland-gm/snowland-smx-python)
[![download](https://img.shields.io/pypi/dm/snowland-smx.svg?cacheSeconds=86400)](https://pypi.org/project/snowland-smx)
[![wheels](https://img.shields.io/pypi/wheel/snowland-smx.svg)](https://pypi.python.org/pypi/snowland-smx)
[![CodeFactor](https://www.codefactor.io/repository/github/astarchen/astartool/badge/master)](https://www.codefactor.io/repository/github/astarchen/astartool/overview/master)

国密算法（GM/T）Python 实现：SM2、SM3、SM4、SM9、ZUC。

## 安装

```bash
pip install snowland-smx
```

或从源码安装：

```bash
python setup.py install
```

---

## SM2 - 椭圆曲线公钥密码

SM2 非对称加解密、签名与验签。

### 密钥生成

```python
from pysmx.SM2 import generate_keypair

kp = generate_keypair()
print(kp.publicKey)   # bytes
print(kp.privateKey)  # bytes
```

### 签名与验签

```python
from pysmx.SM2 import Sign, Verify

len_para = 64
sig = Sign("你好", kp.privateKey, '12345678abcdef', len_para)
assert Verify(sig, "你好", kp.publicKey, len_para)
```

### 加密与解密

```python
from pysmx.SM2 import Encrypt, Decrypt

len_para = 64
cipher = Encrypt(b'hello', kp.publicKey, len_para, Hexstr=0)
plain = Decrypt(cipher, kp.privateKey, len_para)
```

#### API 参考

| 函数 | 说明 |
|------|------|
| `generate_keypair(len_param=64)` | 生成密钥对，返回 `KeyPair(publicKey, privateKey)` |
| `Sign(E, DA, K, len_para=64, Hexstr=0)` | 签名，返回 `r \|\| s` 字节串 |
| `Verify(Sign, E, PA, len_para=64, Hexstr=0)` | 验签，返回 `bool` |
| `Encrypt(M, PA, len_para, Hexstr=0, hash_algorithm='sm3')` | 加密，返回 `C1 \|\| C3 \|\| C2` 字节串 |
| `Decrypt(C, DA, len_para, Hexstr=0, hash_algorithm='sm3')` | 解密，返回明文 bytes 或 `None` |

---

## SM3 - 密码杂凑算法

SM3 输出 256 位（32 字节）摘要，兼容 hashlib 接口。

### 使用方式

**方式一：增量哈希（兼容 hashlib）**

```python
from pysmx.SM3 import SM3

sm3 = SM3()
sm3.update('abc')
print(sm3.hexdigest())
```

**方式二：一次性哈希**

```python
from pysmx.SM3 import hash_msg

print(hash_msg('abc'))
```

**方式三：指定编码**

```python
from pysmx.SM3 import SM3

sm3 = SM3(encoding='gbk')
sm3.update('你好')
print(sm3.digest())  # 原始字节
```

### 密钥派生（KDF）

```python
from pysmx.SM3 import KDF

# 从十六进制字符串派生 32 字节密钥
derived_key = KDF('abc123', 32)
```

#### API 参考

| 函数 / 类 | 说明 |
|-----------|------|
| `SM3(msg=b'', encoding='utf-8')` | SM3 哈希对象，支持 `update()`、`digest()`、`hexdigest()`、`copy()` |
| `SM3Type` | SM3 哈希对象类型（`SM3` 的别名，便于类型检查） |
| `hash_msg(msg) -> str` | 一次性哈希，返回十六进制字符串 |
| `hexdigest(msg) -> str` | 一次性哈希，返回十六进制字符串 |
| `Hash_sm3(msg, Hexstr=0) -> str` | 哈希计算，支持可选的十六进制输入 |
| `digest(msg, Hexstr=0) -> bytes` | 一次性哈希，返回原始字节 |
| `KDF(Z, klen) -> str` | 密钥派生，`klen` 单位为字节 |

---

## SM4 - 分组密码

SM4 分组密码：128 位分组大小，128 位密钥。支持 ECB、CBC、PCBC、CFB、OFB 模式。

### ECB 模式

```python
from pysmx.SM4 import Sm4, ENCRYPT, DECRYPT

key = b'0123456789abcdef'  # 必须恰好 16 字节
sm4 = Sm4()

# 加密
sm4.sm4_set_key(key, ENCRYPT)
ciphertext = sm4.sm4_crypt_ecb(b'Hello World!')

# 解密
sm4.sm4_set_key(key, DECRYPT)
plaintext = sm4.sm4_crypt_ecb(ciphertext)
```

### CBC 模式

```python
from pysmx.SM4 import Sm4, ENCRYPT, DECRYPT

key = b'0123456789abcdef'
iv = b'abcdef0123456789'

sm4 = Sm4()
sm4.sm4_set_key(key, ENCRYPT)
ciphertext = sm4.sm4_crypt_cbc(iv, b'Hello World!')
```

### 使用模块级便捷函数

```python
from pysmx.SM4 import sm4_crypt_ecb, sm4_crypt_cbc, ENCRYPT, DECRYPT

cipher = sm4_crypt_ecb(ENCRYPT, key, data)
cipher = sm4_crypt_cbc(ENCRYPT, key, iv, data)
```

### 流式加解密（大文件/大数据）

`SM4Stream` 提供 `update()` / `finalize()` 接口，支持增量处理大数据，

无需一次性加载全部数据到内存：

```python
from pysmx.SM4 import SM4Stream, ENCRYPT, DECRYPT

key = b'0123456789abcdef'
iv = b'abcdef0123456789'

# 加密
stream = SM4Stream(key, ENCRYPT, iv, method='cbc')
ciphertext = b''
with open('large_file.bin', 'rb') as f:
    while True:
        chunk = f.read(64 * 1024)  # 64KB per chunk
        if not chunk:
            break
        ciphertext += stream.update(chunk)
ciphertext += stream.finalize()

# 解密
stream = SM4Stream(key, DECRYPT, iv, method='cbc')
plaintext = b''
for chunk in split_into_chunks(ciphertext, 64 * 1024):
    plaintext += stream.update(chunk)
plaintext += stream.finalize()
```

#### API 参考

| 类 / 函数 | 说明 |
|-----------|------|
| `Sm4(padding_method='pkcs5')` | SM4 密码器，支持 `set_key()` 和 ECB/CBC/PCBC/CFB/OFB 方法 |
| `SM4` | `Sm4` 的别名 |
| `SM4Stream(key, mode, iv=None, method='ecb', padding_method='pkcs5')` | 流式密码器，`update(data)` 增量处理，`finalize()` 收尾 |
| `SM4BlockCyphers` | 分块密码封装，适配多块连续加解密场景 |
| `sm4_crypt_ecb(mode, key, data) -> bytes` | 便捷函数：ECB 模式 |
| `sm4_crypt_cbc(mode, key, iv, data) -> bytes` | 便捷函数：CBC 模式 |
| `sm4_crypt_cfb(mode, key, iv, data) -> bytes` | 便捷函数：CFB 模式 |
| `sm4_crypt_ofb(mode, key, iv, data) -> bytes` | 便捷函数：OFB 模式 |
| `sm4_crypt_pcbc(mode, key, iv, data) -> bytes` | 便捷函数：PCBC 模式 |

常量：`ENCRYPT`、`DECRYPT`

`SM4Stream` method 参数：`'ecb'`、`'cbc'`、`'cfb'`、`'ofb'`、`'pcbc'`。

---

## ZUC - 流密码

ZUC 流密码，用于 3GPP LTE 128-EEA3 / 128-EIA3。

```python
from pysmx.ZUC import ZUC

key = [0x00] * 16  # 16 字节密钥，int 列表
iv = [0x00] * 16   # 16 字节 IV，int 列表

zuc = ZUC(key, iv)

# 生成密钥流
keystream = zuc.zuc_generate_keystream()

# 通过 XOR 密钥流加密
encrypted = list(zuc.zuc_encrypt(b'hello'))
```

#### API 参考

| 方法 | 说明 |
|------|------|
| `ZUC(key, iv, buffer_size=100)` | 初始化 ZUC，key 和 iv 各 16 字节（`list[int]` 格式） |
| `zuc_generate_keystream() -> list` | 生成一个缓冲区的密钥流字 |
| `zuc_encrypt(input) -> generator` | 通过 XOR 密钥流进行加解密 |

---

## crypto - 工具

### hashlib 的 SM3 支持

```python
from pysmx.crypto import hashlib

h = hashlib.new('sm3', b'hello')
print(h.hexdigest())

# 同时支持标准 hashlib 算法
h = hashlib.sha256(b'hello')
```

### PBKDF2 密钥派生

```python
from pysmx.crypto import pbkdf2_hmac

dk = pbkdf2_hmac('sm3', b'password', b'salt', iterations=100000, dklen=32)
```

#### API 参考

| 函数 | 说明 |
|------|------|
| `hashlib.new(name, data=b'')` | 创建哈希对象（支持 sm3、sha256 等） |
| `pbkdf2_hmac(hash_name, password, salt, iterations, dklen=None)` | PKCS#5 PBKDF2 密钥派生 |

---

## SM9 - 标识密码算法

SM9 基于 BN 曲线双线性配对，符合 GM/T 0044-2016 标准。当前为实验性功能，API 如下：

```python
from pysmx.SM9 import (
    Sign, Verify,
    Encrypt, Decrypt,
    KEM_Encapsulate, KEM_Decapsulate,
    generate_master_key,
    generate_user_sign_key,
    generate_user_enc_key,
)
# 内部工具：用于计算签名主公钥
from pysmx.SM9._SM9 import _g2_to_affine, _g2_scalar_mult, _sm9_P2

# 生成主密钥（返回加密主公钥，G1群元素）
ke, P_pub_e = generate_master_key()

# 签名主公钥需单独计算（G2群元素）
P2 = ((_sm9_P2[0], _sm9_P2[1]), (_sm9_P2[2], _sm9_P2[3]))
P_pub_s = _g2_to_affine(_g2_scalar_mult(ke, P2))

# hid 参数：0x01 签名，0x02 KEM，0x03 加密
d_A = generate_user_sign_key(ke, b'alice', hid=0x01)
d_B = generate_user_enc_key(ke, b'bob', hid=0x03)

# 签名/验签
sig = Sign(b'hello', d_A, P_pub_s, hid=0x01)
Verify(b'hello', sig, b'alice', P_pub_s, hid=0x01)

# 加密/解密
ct = Encrypt(b'secret', b'bob', P_pub_e, hid=0x03)
pt = Decrypt(ct, d_B, b'bob', hid=0x03)

# 密钥封装（KEM）
K_enc, C = KEM_Encapsulate(b'bob', P_pub_e, klen=32, hid=0x02)
K_dec = KEM_Decapsulate(C, d_B, b'bob', klen=32, hid=0x02)
```

#### API 参考

| 函数 | 说明 |
|------|------|
| `generate_master_key() -> (int, tuple)` | 生成主密钥对，返回 `(主私钥, 加密主公钥(G1))` |
| `generate_user_sign_key(ks, ID, hid=0x01) -> tuple` | 派生用户签名私钥（G1 元素） |
| `generate_user_enc_key(ke, ID, hid=0x03) -> tuple` | 派生用户加密私钥（G2 元素） |
| `Sign(M, d_A, P_pub_s, hid=0x01) -> bytes` | SM9 签名 |
| `Verify(M, sig, ID_A, P_pub_s, hid=0x01) -> bool` | SM9 验签 |
| `Encrypt(M, ID_B, P_pub_e, hid=0x03) -> bytes` | 基于标识加密 |
| `Decrypt(C, d_B, ID_B, hid=0x03) -> bytes` | 基于标识解密 |
| `KEM_Encapsulate(ID_B, P_pub_e, klen, hid=0x02) -> (K, C)` | 密钥封装 |
| `KEM_Decapsulate(C1, d_B, ID_B, klen, hid=0x02) -> K` | 密钥解封装 |
| `sm9_hex(data) -> str` | 字节/整数转十六进制字符串 |
| `sm9_unhex(s) -> int` | 十六进制字符串转整数 |
| `_g2_to_affine(p) -> tuple` | G2 Jacobian 转仿射坐标 |
| `_g2_scalar_mult(k, p) -> tuple` | G2 标量乘法 |

---

## 数字信封 (GM/T 0010-2012)

结合 SM2（非对称加密）和 SM4-CBC（对称加密）实现安全数据传输。

```python
from pysmx.extra.envelope import envelope_seal, envelope_open
from pysmx.SM2 import generate_keypair

kp = generate_keypair()

# 用接收方公钥加密
result = envelope_seal(b'my data', kp.publicKey)
# result.encrypted_key  - 经 SM2 加密的 SM4 密钥
# result.iv             - SM4 初始化向量
# result.ciphertext     - SM4-CBC 密文

# 用接收方私钥解密
plaintext = envelope_open(result.encrypted_key, result.iv,
                          result.ciphertext, kp.privateKey)
```

#### API 参考

| 函数 | 说明 |
|------|------|
| `envelope_encrypt(plaintext, public_key=None, sm2_keypair=None, sm4_key=None, iv=None) -> EnvelopeResult` | 数字信封加密 |
| `envelope_decrypt(encrypted_key, iv, ciphertext, private_key) -> bytes` | 数字信封解密 |
| `envelope_seal(plaintext, public_key) -> EnvelopeResult` | 便捷封装：用接收方公钥加密 |
| `envelope_open(encrypted_key, iv, ciphertext, private_key) -> bytes` | 便捷解封：用接收方私钥解密 |

---

## 填充工具

分组密码填充方案，从 `pysmx.common` 导入。

```python
from pysmx.common import PKCS7Padding, PKCS7UnPadding

padded = PKCS7Padding(b'hello', block_size=16)
original = PKCS7UnPadding(padded)
```

#### 可用填充方案

| 方案 | 填充 / 去填充函数 |
|------|-------------------|
| PKCS5 | `PKCS5Padding()`, `PKCS5UnPadding()` |
| PKCS7 | `PKCS7Padding(text, block_size=16)`, `PKCS7UnPadding(text, block_size=16)` |
| Zero | `ZeroPadding(text, block_size=16)`, `ZeroUnPadding(text, block_size=16)` |
| ISO10126 | `ISO10126Padding(text, block_size=16)`, `ISO10126UnPadding(text, block_size=16)` |
| NoPadding | `NoPadding(text, block_size=16)`, `NoUnPadding(text, block_size=16)` |

---

## cryptography 库集成

安装 `cryptography` 库后，SMx 算法可注册为标准 `cryptography` 接口，
与 TLS/SSL、X.509 等框架无缝协作。

### SM2

```python
from pysmx.SM2 import (
    SM2EllipticCurve, SM2EllipticCurvePublicKey,
    SM2EllipticCurvePrivateKey,
    SM2SM3SignatureAlgorithm, SM2SHA256SignatureAlgorithm,
)

# 生成密钥对
curve = SM2EllipticCurve()
private_key = SM2EllipticCurvePrivateKey.generate(curve)
public_key = private_key.public_key()

# 签名与验签
sig = private_key.sign(b'hello', SM2SM3SignatureAlgorithm())
public_key.verify(sig, b'hello', SM2SM3SignatureAlgorithm())

# 加解密
cipher = private_key.encrypt_sm2(b'hello')
plain = private_key.decrypt_sm2(cipher)
```

### SM3

`SM3HashAlgorithm`、`SM3HashBackend`、`SM3HMACBackend` 导入即完成注册，
可通过 `cryptography.hazmat.primitives.hashes.Hash` 和 `HMAC` 直接使用。

### SM4

`SM4Algorithm` 基于 pysmx 原生 Sm4 实现，提供 `BlockCipherAlgorithm` 描述符及全模式便捷加解密函数。

```python
from pysmx.SM4 import (
    SM4Algorithm, SM4ModePCBC,
    sm4_encrypt_ecb, sm4_decrypt_ecb,
    sm4_encrypt_cbc, sm4_decrypt_cbc,
)

key = b'0123456789abcdef'
iv = b'abcdef0123456789'

# ECB 模式
ciphertext = sm4_encrypt_ecb(key, b'Hello World!')
plaintext = sm4_decrypt_ecb(key, ciphertext)

# CBC 模式
ciphertext = sm4_encrypt_cbc(key, iv, b'Hello World!')
plaintext = sm4_decrypt_cbc(key, iv, ciphertext)
```

**流式加解密（`SM4StreamCipher`）**

```python
from pysmx.block_cyphers import ENCRYPT, DECRYPT
from pysmx.SM4 import SM4StreamCipher

# 加密
cipher = SM4StreamCipher(key, ENCRYPT, iv, mode='cbc')
ct1 = cipher.update(data_chunk1)
ct2 = cipher.update(data_chunk2)
ct_final = cipher.finalize()

# 解密
cipher = SM4StreamCipher(key, DECRYPT, iv, mode='cbc')
pt = cipher.update(ct_all)
pt += cipher.finalize()
```

### SM9

```python
from pysmx.SM9 import (
    SM9EllipticCurve, SM9EllipticCurvePublicKey,
    SM9EllipticCurvePrivateKey, SM9SM3SignatureAlgorithm,
)
```

### ZUC

```python
from pysmx.ZUC import ZUCAlgorithm, zuc_encrypt, zuc_decrypt

key = b'0123456789abcdef'
iv = b'fedcba9876543210'
cipher = zuc_encrypt(key, iv, b'hello')
plain = zuc_decrypt(key, iv, cipher)
```

#### API 参考

| 模块 | 类 / 函数 | 说明 |
|------|-----------|------|
| SM2 | `SM2EllipticCurve` | SM2 椭圆曲线描述符 |
| SM2 | `SM2EllipticCurvePublicKey` | SM2 公钥（cryptography 接口） |
| SM2 | `SM2EllipticCurvePrivateKey` | SM2 私钥，支持 `sign()` / `verify()` / `encrypt_sm2()` / `decrypt_sm2()` |
| SM2 | `SM2SM3SignatureAlgorithm` | SM2 with SM3 签名算法 |
| SM2 | `SM2SHA256SignatureAlgorithm` | SM2 with SHA256 签名算法 |
| SM3 | `SM3HashAlgorithm` | SM3 哈希算法描述符 |
| SM3 | `SM3HashContext` | SM3 哈希上下文 |
| SM3 | `SM3HMACContext` | SM3 HMAC 上下文 |
| SM3 | `SM3HashBackend` | SM3 哈希后端 |
| SM3 | `SM3HMACBackend` | SM3 HMAC 后端 |
| SM4 | `SM4Algorithm` | SM4 分组密码算法描述符（pysmx 原生 Sm4 后端） |
| SM4 | `SM4ModePCBC` | SM4 PCBC 模式 |
| SM4 | `sm4_encrypt_ecb(key, data)` | SM4-ECB 加密 |
| SM4 | `sm4_decrypt_ecb(key, data)` | SM4-ECB 解密 |
| SM4 | `sm4_encrypt_cbc(key, iv, data)` | SM4-CBC 加密 |
| SM4 | `sm4_decrypt_cbc(key, iv, data)` | SM4-CBC 解密 |
| SM4 | `sm4_encrypt_cfb(key, iv, data)` | SM4-CFB 加密 |
| SM4 | `sm4_decrypt_cfb(key, iv, data)` | SM4-CFB 解密 |
| SM4 | `sm4_encrypt_ofb(key, iv, data)` | SM4-OFB 加密 |
| SM4 | `sm4_decrypt_ofb(key, iv, data)` | SM4-OFB 解密 |
| SM4 | `sm4_encrypt_pcbc(key, iv, data)` | SM4-PCBC 加密 |
| SM4 | `sm4_decrypt_pcbc(key, iv, data)` | SM4-PCBC 解密 |
| SM4 | `SM4StreamCipher(key, direction, iv, mode, padding_method)` | 流式密码器，`update(data)` 增量处理，`finalize()` 收尾 |
| SM9 | `SM9EllipticCurve` | SM9 BN 曲线描述符 |
| SM9 | `SM9EllipticCurvePublicKey` | SM9 公钥（cryptography 接口） |
| SM9 | `SM9EllipticCurvePrivateKey` | SM9 私钥（cryptography 接口） |
| SM9 | `SM9SM3SignatureAlgorithm` | SM9 with SM3 签名算法 |
| ZUC | `ZUCAlgorithm` | ZUC 流密码算法描述符 |
| ZUC | `zuc_encrypt(key, iv, data)` | ZUC 加密 |
| ZUC | `zuc_decrypt(key, iv, ciphertext)` | ZUC 解密 |

---

## License

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fsnowland-gm%2Fsnowland-smx-python.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fsnowland-gm%2Fsnowland-smx-python?ref=badge_large)
