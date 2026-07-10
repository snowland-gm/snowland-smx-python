# snowland-smx API 文档

## 概述

`snowland-smx` (版本 0.3.2-alpha.1) 是国密算法（GM/T 标准）的纯 Python 实现，包含 SM2、SM3、SM4 和 ZUC 算法。

包名: `pysmx`

---

## 1. SM2 - 椭圆曲线公钥密码算法

`from pysmx.SM2 import ...`

SM2 是基于 SM2 曲线（256 位素域）的椭圆曲线公钥算法，支持数字签名、验签、加密和解密。

### 1.1 `generate_keypair(len_param=64) -> KeyPair`

生成公私钥对。

| 参数 | 类型 | 默认值 | 说明 |
|-----------|------|---------|-------------|
| `len_param` | `int` | `64` | 密钥长度（十六进制字符数） |

| 返回值 | 类型 | 说明 |
|--------|------|-------------|
| `KeyPair` | `namedtuple` | `KeyPair(publicKey, privateKey)`，均为 `bytes` 类型 |

```python
from pysmx.SM2 import generate_keypair
kp = generate_keypair()
print(kp.publicKey)   # bytes
print(kp.privateKey)  # bytes
```

### 1.2 `Sign(E, DA, K, len_para=64, Hexstr=0, encoding='utf-8') -> bytes`

使用 SM2 对消息签名。

| 参数 | 类型 | 默认值 | 说明 |
|-----------|------|---------|-------------|
| `E` | `str` / `bytes` | — | 消息或其哈希值。若为十六进制字符串，需设置 `Hexstr=1` |
| `DA` | `str` / `bytes` | — | 私钥（十六进制字符串或 bytes） |
| `K` | `str` | — | 随机数（十六进制字符串） |
| `len_para` | `int` | `64` | 固定值，长度参数 |
| `Hexstr` | `int` | `0` | `E` 为十六进制字符串时设为 `1`，否则为 `0` |
| `encoding` | `str` | `'utf-8'` | 当 `E` 为 `str` 且 `Hexstr=0` 时的字符编码 |

| 返回值 | 类型 | 说明 |
|--------|------|-------------|
| 签名 | `bytes` 或 `None` | 格式: `r || s`；失败时返回 `None` |

### 1.3 `Verify(Sign, E, PA, len_para=64, Hexstr=0, encoding='utf-8') -> bool`

验证 SM2 签名。

| 参数 | 类型 | 默认值 | 说明 |
|-----------|------|---------|-------------|
| `Sign` | `str` / `bytes` | — | `r || s` 格式的签名 |
| `E` | `str` / `bytes` | — | 待验证的消息 |
| `PA` | `str` / `bytes` | — | 公钥 |
| `len_para` | `int` | `64` | 固定值 |
| `Hexstr` | `int` | `0` | `E` 为十六进制字符串时设为 `1` |
| `encoding` | `str` | `'utf-8'` | 当 `E` 为 `str` 且 `Hexstr=0` 时的编码 |

| 返回值 | 类型 | 说明 |
|--------|------|-------------|
| 结果 | `bool` | 有效返回 `True`，否则 `False` |

### 1.4 `Encrypt(M, PA, len_para, Hexstr=0, encoding='utf-8', hash_algorithm='sm3') -> bytes`

使用 SM2 加密消息。

| 参数 | 类型 | 默认值 | 说明 |
|-----------|------|---------|-------------|
| `M` | `str` / `bytes` | — | 明文。若为十六进制字符串，设置 `Hexstr=1` |
| `PA` | `str` / `bytes` | — | 公钥 |
| `len_para` | `int` | — | 固定值 `64` |
| `Hexstr` | `int` | `0` | `M` 为十六进制字符串时设为 `1` |
| `encoding` | `str` | `'utf-8'` | 当 `M` 为 `str` 且 `Hexstr=0` 时的编码 |
| `hash_algorithm` | `str` | `'sm3'` | 哈希算法名称（支持 hashlib 所有算法） |

| 返回值 | 类型 | 说明 |
|--------|------|-------------|
| 密文 | `bytes` 或 `None` | 格式: `C1 || C3 || C2`；失败返回 `None` |

### 1.5 `Decrypt(C, DA, len_para, Hexstr=0, encoding='utf-8', hash_algorithm='sm3') -> bytes`

解密 SM2 密文。

| 参数 | 类型 | 默认值 | 说明 |
|-----------|------|---------|-------------|
| `C` | `str` / `bytes` | — | 密文。若为十六进制字符串，设置 `Hexstr=1` |
| `DA` | `str` / `bytes` | — | 私钥 |
| `len_para` | `int` | — | 固定值 `64` |
| `Hexstr` | `int` | `0` | `C` 为十六进制字符串时设为 `1` |
| `encoding` | `str` | `'utf-8'` | 编码方式 |
| `hash_algorithm` | `str` / `callable` | `'sm3'` | 哈希算法（名称或可调用对象） |

| 返回值 | 类型 | 说明 |
|--------|------|-------------|
| 明文 | `bytes` 或 `None` | 完整性校验失败时返回 `None` |

### 1.6 `SM2` 类

继承自 `ECCAlgorithm` 的高级封装类。

```python
class SM2(ECCAlgorithm):
    name = 'sm2'
    key_size = 64

    def __init__(self, pk=None, sk=None, key=None, curve=CurveSM2)
    def sign(self, message)       # 存根（尚未实现）
    def verify(self, message)     # 存根
    def encrypt(self, message)    # 存根
    def decrypt(self, message)    # 存根
```

---

## 2. SM3 - 密码杂凑算法

`from pysmx.SM3 import ...`

SM3 是密码杂凑函数，输出 256 位（32 字节）摘要。

### 2.1 `SM3Type` / `SM3` 类

`SM3` 是 `SM3Type` 的别名，提供 hashlib 兼容接口。

```python
class SM3Type:
    name = 'SM3'
    digest_size = 32    # 32 字节（256 位）
    block_size = 64     # 64 字节

    def __init__(self, msg=b'', encoding='utf-8')
    def update(self, msg)        # 增量输入数据
    def digest(self) -> bytes    # 获取原始摘要，重置状态
    def hexdigest(self) -> str   # 获取十六进制摘要字符串
    def copy(self)               # 返回哈希对象的副本
```

**用法:**

```python
from pysmx.SM3 import SM3

# 方式 1: 一次性
sm3 = SM3(b'abc')
print(sm3.hexdigest())

# 方式 2: 增量
sm3 = SM3()
sm3.update(b'abc')
print(sm3.hexdigest())
```

### 2.2 `hash_msg(msg) -> str`

计算消息的 SM3 哈希并返回十六进制字符串。

| 参数 | 类型 | 说明 |
|-----------|------|-------------|
| `msg` | `str` / `bytes` | 输入消息 |

| 返回值 | 类型 | 说明 |
|--------|------|-------------|
| 哈希值 | `str` | 64 字符十六进制字符串 |

### 2.3 `Hash_sm3(msg, Hexstr=0) -> str`

计算 SM3 哈希，支持十六进制输入。

| 参数 | 类型 | 默认值 | 说明 |
|-----------|------|---------|-------------|
| `msg` | `str` | — | 输入消息 |
| `Hexstr` | `int` | `0` | `msg` 为十六进制字符串时设为 `1` |

| 返回值 | 类型 | 说明 |
|--------|------|-------------|
| 哈希值 | `str` | 十六进制摘要 |

> `hexdigest` 是 `Hash_sm3` 的别名。

### 2.4 `digest(msg, Hexstr=0) -> bytes`

计算 SM3 哈希并返回原始字节。

| 参数 | 类型 | 默认值 | 说明 |
|-----------|------|---------|-------------|
| `msg` | `list` / `str` | — | 字节列表或字符串形式的输入 |
| `Hexstr` | `int` | `0` | `msg` 为十六进制字符串时设为 `1` |

| 返回值 | 类型 | 说明 |
|--------|------|-------------|
| 摘要 | `bytes` | 32 字节原始摘要 |

### 2.5 `KDF(Z, klen) -> str`

基于 SM3 的密钥派生函数。

| 参数 | 类型 | 说明 |
|-----------|------|-------------|
| `Z` | `str` | 十六进制表示的比特串 |
| `klen` | `int` | 期望的密钥长度，单位**字节** |

| 返回值 | 类型 | 说明 |
|--------|------|-------------|
| 派生密钥 | `str` | 长度为 `klen * 2` 的十六进制字符串 |

### 2.6 工具函数

| 函数 | 说明 |
|----------|-------------|
| `str2bytes(msg, encoding='utf-8')` | 字符串转字节列表 |
| `byte2str(msg, decode='utf-8')` | 字节列表转字符串 |
| `hex2byte(msg)` | 十六进制字符串转字节列表 |
| `rotate_left(a, k)` | 32 位循环左移 |

---

## 3. SM4 - 分组密码算法

`from pysmx.SM4 import ...`

SM4 分组密码：128 位（16 字节）分组大小，128 位密钥。

### 3.1 常量

```python
from pysmx.SM4 import ENCRYPT, DECRYPT
```

- `ENCRYPT` — 加密模式
- `DECRYPT` — 解密模式

### 3.2 `Sm4` 类（同时导出为 `SM4`）

继承自 `BlockCyphers`，支持多种分组密码模式及自动填充。

```python
class Sm4(BlockCyphers):
    block_size = 16
    name = 'SM4'

    def __init__(self, padding_method='pkcs5', unpadding_method=None)
```

#### 方法:

##### `set_key(key, mode)` / `sm4_set_key` / `sm4_setkey`

设置加密密钥和模式。

| 参数 | 类型 | 说明 |
|-----------|------|-------------|
| `key` | `bytes` | 16 字节（128 位）密钥 |
| `mode` | `int` | `ENCRYPT` 或 `DECRYPT` |

##### `sm4_crypt_ecb(input_data) -> bytes`

ECB 模式加解密。

| 参数 | 类型 | 说明 |
|-----------|------|-------------|
| `input_data` | iterable | 输入数据字节 |

##### `sm4_crypt_cbc(iv, input_data) -> bytes`

CBC 模式加解密。

| 参数 | 类型 | 说明 |
|-----------|------|-------------|
| `iv` | `bytes` | 16 字节初始化向量 |
| `input_data` | iterable | 输入数据字节 |

##### `sm4_crypt_pcbc(iv, input_data) -> bytes`

PCBC（传播 CBC）模式。

##### `sm4_crypt_cfb(iv, input_data) -> bytes`

CFB（密文反馈）模式。

##### `sm4_crypt_ofb(iv, input_data) -> bytes`

OFB（输出反馈）模式。

##### `one_round(sk, in_put) -> bytes`

对 16 字节输入执行单轮 SM4 运算，使用 32 个轮密钥。

**使用示例:**

```python
from pysmx.SM4 import Sm4, ENCRYPT, DECRYPT

key = b'hello word errrr...'  # 必须为 16 字节

# 加密
sm4 = Sm4()
sm4.sm4_set_key(key, ENCRYPT)
ciphertext = sm4.sm4_crypt_ecb([1, 2, 3])

# 解密
sm4.sm4_set_key(key, DECRYPT)
plaintext = sm4.sm4_crypt_ecb(ciphertext)
```

### 3.3 模块级便捷函数

以下函数在内部创建临时 `Sm4` 实例用于单次操作。

| 函数 | 签名 |
|----------|-----------|
| `sm4_crypt_ecb(mode, key, data) -> bytes` | ECB 模式加解密 |
| `sm4_crypt_cbc(mode, key, iv, data) -> bytes` | CBC 模式加解密 |
| `sm4_crypt_pcbc(mode, key, iv, data) -> bytes` | PCBC 模式加解密 |
| `sm4_crypt_cfb(mode, key, iv, data) -> bytes` | CFB 模式加解密 |
| `sm4_crypt_ofb(mode, key, iv, data) -> bytes` | OFB 模式加解密 |

| 参数 | 类型 | 说明 |
|-----------|------|-------------|
| `mode` | `int` | `ENCRYPT` 或 `DECRYPT` |
| `key` | `bytes` | 16 字节密钥 |
| `iv` | `bytes` | 16 字节 IV（用于 CBC/PCBC/CFB/OFB） |
| `data` | `bytes` | 输入数据 |

### 3.4 `SM4BlockCyphers` 类

另一种 SM4 实现，接口与 `Sm4` 相同，但构造函数直接接收密钥和 IV。

```python
class SM4BlockCyphers(BlockCyphers):
    block_size = 16
    name = 'SM4'

    def __init__(self, key, iv=None, mode=ENCRYPT,
                 padding_method='pkcs5', unpadding_method=None)
```

---

## 4. ZUC - 祖冲之序列密码算法

`from pysmx.ZUC import ZUC`

ZUC 是面向字的序列密码，用于 3GPP LTE 机密性和完整性算法（128-EEA3 和 128-EIA3）。

### 4.1 `ZUC` 类

```python
class ZUC(Iterable):
    def __init__(self, key, iv, buffer_size=100)
```

| 参数 | 类型 | 说明 |
|-----------|------|-------------|
| `key` | `list[int]` | 16 字节密钥，表示为 16 个整数的列表 |
| `iv` | `list[int]` | 16 字节 IV，表示为 16 个整数的列表 |
| `buffer_size` | `int` | 密钥流生成的缓冲区大小（默认: 100） |

#### 方法:

##### `zuc_generate_keystream() -> list`

生成一个缓冲区的密钥流字。

##### `zuc_encrypt(input) -> generator`

通过与密钥流异或来加密输入。返回生成器，逐个产生加密字节。

| 参数 | 类型 | 说明 |
|-----------|------|-------------|
| `input` | iterable | 输入明文字节 |

##### `__next__() -> int`

生成下一个密钥流字（32 位）。

##### `__iter__() -> self`

支持迭代。每次迭代产生一个 32 位密钥流字。

**使用示例:**

```python
from pysmx.ZUC import ZUC

key = [0x00] * 16
iv = [0x00] * 16
zuc = ZUC(key, iv)
key_stream = zuc.zuc_generate_keystream()
```

---

## 5. crypto - 密码学工具

`from pysmx.crypto import ...`

### 5.1 `pbkdf2_hmac(hash_name, password, salt, iterations, dklen=None) -> bytes`

PBKDF2 密钥派生函数（PKCS #5 v2.0）。

| 参数 | 类型 | 说明 |
|-----------|------|-------------|
| `hash_name` | `str` | 哈希算法名称（如 `'sm3'`、`'sha256'`） |
| `password` | `bytes` / `bytearray` | 密码 |
| `salt` | `bytes` / `bytearray` | 盐值 |
| `iterations` | `int` | 迭代次数（必须 >= 1） |
| `dklen` | `int` 或 `None` | 期望的派生密钥长度（字节），默认等于哈希摘要大小 |

| 返回值 | 类型 | 说明 |
|--------|------|-------------|
| 派生密钥 | `bytes` | 长度为 `dklen` 的派生密钥 |

### 5.2 `hashlib` 模块

`pysmx.crypto.hashlib` 扩展了 Python 标准库 `hashlib`，增加了 SM3 支持。

#### `new(name, data=b'', **kwargs) -> hash object`

创建新的哈希对象。

| 参数 | 类型 | 说明 |
|-----------|------|-------------|
| `name` | `str` | 算法名称 |
| `data` | `bytes` | 可选的初始数据 |

支持的算法: `sm3`、`md5`、`sha1`、`sha224`、`sha256`、`sha384`、`sha512`、`blake2b`、`blake2s`、`sha3_224`、`sha3_256`、`sha3_384`、`sha3_512`、`shake_128`、`shake_256`。

```python
from pysmx.crypto import hashlib
h = hashlib.new('sm3', b'hello')
print(h.hexdigest())
```

#### 模块级构造函数

每种支持的算法都可以作为模块级构造函数使用：

```python
from pysmx.crypto.hashing import sm3
h = sm3(b'hello')
```

#### 常量

| 名称 | 类型 | 说明 |
|------|------|-------------|
| `algorithms_guaranteed` | `set` | 始终可用的算法集合 |
| `algorithms_available` | `set` | 所有可用算法的集合 |

---

## 6. 版本信息

```python
from pysmx import VERSION, __version__

print(__version__)  # "0.3.2-alpha.1"
print(VERSION)      # (0, 3, 2, 'alpha', 1)
```

---

## 7. 快速参考

### SM2 签名与验签

```python
from pysmx.SM2 import generate_keypair, Sign, Verify

kp = generate_keypair()
sig = Sign("hello", kp.privateKey, '12345678abcdef', 64)
valid = Verify(sig, "hello", kp.publicKey, 64)
```

### SM2 加密与解密

```python
from pysmx.SM2 import generate_keypair, Encrypt, Decrypt

kp = generate_keypair()
cipher = Encrypt(b'secret message', kp.publicKey, 64, 0)
plain = Decrypt(cipher, kp.privateKey, 64)
```

### SM3 哈希

```python
from pysmx.SM3 import hash_msg, SM3

print(hash_msg('abc'))

sm3 = SM3()
sm3.update(b'abc')
print(sm3.hexdigest())
```

### SM4 加密与解密

```python
from pysmx.SM4 import Sm4, ENCRYPT, DECRYPT

key = b'0123456789abcdef'  # 恰好 16 字节
sm4 = Sm4()
sm4.sm4_set_key(key, ENCRYPT)
cipher = sm4.sm4_crypt_ecb(b'Hello World!')
sm4.sm4_set_key(key, DECRYPT)
plain = sm4.sm4_crypt_ecb(cipher)
```

### ZUC 序列密码

```python
from pysmx.ZUC import ZUC

zuc = ZUC(key=[0]*16, iv=[0]*16)
keystream = zuc.zuc_generate_keystream()
```
