# snowland-smx

[![version](https://img.shields.io/pypi/v/snowland-smx.svg)](https://pypi.python.org/pypi/snowland-smx)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2BASTARCHEN%2Fsnowland-smx-python.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2BASTARCHEN%2Fsnowland-smx-python?ref=badge_shield)
[![gitee](https://gitee.com/snowlandltd/snowland-smx-python/badge/star.svg)](https://gitee.com/snowlandltd/snowland-smx-python/stargazers)
[![github](https://img.shields.io/github/stars/ASTARCHEN/snowland-smx-python)](https://img.shields.io/github/stars/ASTARCHEN/snowland-smx-python)
[![download](https://img.shields.io/pypi/dm/snowland-smx.svg?cacheSeconds=43200)](https://pypi.org/project/snowland-smx)
[![wheels](https://img.shields.io/pypi/wheel/snowland-smx.svg)](https://pypi.python.org/pypi/snowland-smx)
[![CodeFactor](https://www.codefactor.io/repository/github/astarchen/astartool/badge/master)](https://www.codefactor.io/repository/github/astarchen/astartool/overview/master)

国密算法（GM/T）Python 实现：SM2、SM3、SM4、ZUC。

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
| `hash_msg(msg) -> str` | 一次性哈希，返回十六进制字符串 |
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

#### API 参考

| 类 / 函数 | 说明 |
|-----------|------|
| `Sm4(padding_method='pkcs5')` | SM4 密码器，支持 `set_key()` 和 ECB/CBC/PCBC/CFB/OFB 方法 |
| `sm4_crypt_ecb(mode, key, data) -> bytes` | 便捷函数：ECB 模式 |
| `sm4_crypt_cbc(mode, key, iv, data) -> bytes` | 便捷函数：CBC 模式 |
| `sm4_crypt_cfb(mode, key, iv, data) -> bytes` | 便捷函数：CFB 模式 |
| `sm4_crypt_ofb(mode, key, iv, data) -> bytes` | 便捷函数：OFB 模式 |
| `sm4_crypt_pcbc(mode, key, iv, data) -> bytes` | 便捷函数：PCBC 模式 |

常量：`ENCRYPT`、`DECRYPT`

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

## SM9

开发中。

---

## License

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FASTARCHEN%2Fsnowland-smx-python.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2FASTARCHEN%2Fsnowland-smx-python?ref=badge_large)
