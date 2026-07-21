# snowland-smx API 文档

## 概述

`snowland-smx` (版本 1.0.1) 是国密算法（GM/T 标准）的纯 Python 实现，包含 SM2、SM3、SM4、SM9 和 ZUC 算法。

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

### 3.5 `SM4Stream` 类（流式加解密）

提供 `update()` / `finalize()` 增量处理接口，适用于大文件/流式数据，无需一次性加载全部数据到内存。支持全部 5 种模式。

```python
class SM4Stream:
    block_size = 16

    def __init__(self, key, mode, iv=None, method='ecb',
                 padding_method='pkcs5')
```

| 参数 | 类型 | 默认值 | 说明 |
|-----------|------|---------|-------------|
| `key` | `bytes` | — | 16 字节密钥 |
| `mode` | `int` | — | `ENCRYPT` 或 `DECRYPT` |
| `iv` | `bytes` | `None` | 16 字节 IV（ECB 模式忽略） |
| `method` | `str` | `'ecb'` | 模式: `'ecb'`、`'cbc'`、`'cfb'`、`'ofb'`、`'pcbc'` |
| `padding_method` | `str` | `'pkcs5'` | 填充方案: `'pkcs5'` 或 `'pkcs7'` |

#### 方法:

##### `update(data) -> bytes`

增量输入数据，返回已处理输出的字节。可能返回空字节（不足一个完整块时）。

| 参数 | 类型 | 说明 |
|-----------|------|-------------|
| `data` | `bytes` | 输入数据块 |

##### `finalize() -> bytes`

结束流处理，返回剩余输出。加密时进行填充并处理最后块；解密时去除填充。

**使用示例:**

```python
from pysmx.SM4 import SM4Stream, ENCRYPT, DECRYPT

key = b'0123456789abcdef'
iv = b'abcdef0123456789'

# 加密
stream = SM4Stream(key, ENCRYPT, iv, method='cbc')
ct = b''
with open('large_file.bin', 'rb') as f:
    while True:
        chunk = f.read(64 * 1024)
        if not chunk:
            break
        ct += stream.update(chunk)
ct += stream.finalize()

# 解密
stream = SM4Stream(key, DECRYPT, iv, method='cbc')
pt = stream.update(ct)
pt += stream.finalize()
```

### 3.6 `SM4StreamCipher` 类（cryptography 封装层流式接口）

位于 `pysmx.SM4._cryptography`，与 `SM4Stream` 功能等同，作为 cryptography 兼容层的流式 API。

```python
class SM4StreamCipher:
    def __init__(self, key, direction, iv=None, mode='cbc',
                 padding_method='pkcs5')
```

| 参数 | 类型 | 默认值 | 说明 |
|-----------|------|---------|-------------|
| `key` | `bytes` | — | 16 字节密钥 |
| `direction` | `int` | — | `ENCRYPT` 或 `DECRYPT` |
| `iv` | `bytes` | `None` | 16 字节 IV |
| `mode` | `str` | `'cbc'` | 模式: `'ecb'`、`'cbc'`、`'cfb'`、`'ofb'`、`'pcbc'` |
| `padding_method` | `str` | `'pkcs5'` | 填充方案 |

方法: `update(data) -> bytes`、`finalize() -> bytes`，与 `SM4Stream` 相同。

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

## 5. SM9 - 基于标识的密码算法

`from pysmx.SM9 import ...`

SM9 是基于标识的密码体制（IBC），使用 BN 曲线上的双线性配对，支持数字签名、加密和 KEM。

### 5.1 `generate_master_key() -> Tuple[bytes, bytes]`

生成主密钥对。

| 返回值 | 类型 | 说明 |
|--------|------|-------------|
| `(ks, P_pub_s)` | `(bytes, bytes)` | 主私钥和主公钥 |

### 5.2 `generate_user_sign_key(ks, ID_A, hid=1) -> bytes`

从主密钥派生用户签名私钥。

| 参数 | 类型 | 默认值 | 说明 |
|-----------|------|---------|-------------|
| `ks` | `bytes` | — | 主签名私钥 |
| `ID_A` | `bytes` | — | 用户标识 |
| `hid` | `int` | `1` | 哈希标识（0x01 表示签名） |

| 返回值 | 类型 | 说明 |
|--------|------|-------------|
| `d_A` | `bytes` | 用户签名私钥 |

### 5.3 `Sign(M, d_A, P_pub_s, hid=1) -> bytes`

使用 SM9 对消息签名。

| 参数 | 类型 | 默认值 | 说明 |
|-----------|------|---------|-------------|
| `M` | `bytes` | — | 待签名消息 |
| `d_A` | `bytes` | — | 用户签名私钥 |
| `P_pub_s` | `bytes` | — | 主公钥 |
| `hid` | `int` | `1` | 哈希标识 |

| 返回值 | 类型 | 说明 |
|--------|------|-------------|
| 签名 | `bytes` | SM9 签名 |

### 5.4 `Verify(M, signature, ID_A, P_pub_s, hid=1) -> bool`

验证 SM9 签名。

| 参数 | 类型 | 默认值 | 说明 |
|-----------|------|---------|-------------|
| `M` | `bytes` | — | 原始消息 |
| `signature` | `bytes` | — | 待验证签名 |
| `ID_A` | `bytes` | — | 签名者标识 |
| `P_pub_s` | `bytes` | — | 主公钥 |
| `hid` | `int` | `1` | 哈希标识 |

| 返回值 | 类型 | 说明 |
|--------|------|-------------|
| 结果 | `bool` | 有效返回 `True` |

### 5.5 `generate_user_enc_key(ke, ID_B, hid=3) -> bytes`

派生用户加密私钥。

| 参数 | 类型 | 默认值 | 说明 |
|-----------|------|---------|-------------|
| `ke` | `bytes` | — | 主加密私钥 |
| `ID_B` | `bytes` | — | 用户标识 |
| `hid` | `int` | `3` | 哈希标识（0x03 表示加密） |

### 5.6 `Encrypt(M, ID_B, P_pub_e, hid=3) -> bytes`

对标识加密消息。

| 参数 | 类型 | 默认值 | 说明 |
|-----------|------|---------|-------------|
| `M` | `bytes` | — | 明文 |
| `ID_B` | `bytes` | — | 接收方标识 |
| `P_pub_e` | `bytes` | — | 主公钥 |
| `hid` | `int` | `3` | 哈希标识 |

### 5.7 `Decrypt(C, d_B, ID_B, hid=3) -> bytes`

解密 SM9 密文。

| 参数 | 类型 | 默认值 | 说明 |
|-----------|------|---------|-------------|
| `C` | `bytes` | — | 密文 |
| `d_B` | `bytes` | — | 用户加密私钥 |
| `ID_B` | `bytes` | — | 接收方标识 |
| `hid` | `int` | `3` | 哈希标识 |

### 5.8 `KEM_Encapsulate(ID_B, P_pub_e, klen, hid=2) -> Tuple[bytes, bytes]`

SM9 密钥封装 — 封装共享秘密。

| 参数 | 类型 | 说明 |
|-----------|------|-------------|
| `ID_B` | `bytes` | 接收方标识 |
| `P_pub_e` | `bytes` | 主公钥 |
| `klen` | `int` | 期望密钥长度（字节） |
| `hid` | `int` | 哈希标识（默认: `2`） |

| 返回值 | 类型 | 说明 |
|--------|------|-------------|
| `(K, C)` | `(bytes, bytes)` | 共享密钥和密文 |

### 5.9 `KEM_Decapsulate(C1, d_B, ID_B, klen, hid=2) -> bytes`

SM9 密钥封装 — 解封装共享秘密。

| 参数 | 类型 | 说明 |
|-----------|------|-------------|
| `C1` | `bytes` | 封装返回的密文 |
| `d_B` | `bytes` | 用户加密私钥 |
| `ID_B` | `bytes` | 接收方标识 |
| `klen` | `int` | 期望密钥长度（字节） |
| `hid` | `int` | 哈希标识 |

### 5.10 工具函数

| 函数 | 说明 |
|----------|-------------|
| `sm9_hex(data) -> str` | 字节转十六进制字符串 |
| `sm9_unhex(data) -> bytes` | 十六进制字符串转字节 |

**使用示例:**

```python
from pysmx.SM9 import (
    Sign, Verify, Encrypt, Decrypt,
    generate_master_key,
    generate_user_sign_key,
    generate_user_enc_key,
    KEM_Encapsulate, KEM_Decapsulate,
)

# 签名与验签
ks, P_pub_s = generate_master_key()
d_A = generate_user_sign_key(ks, b'alice', hid=1)
sig = Sign(b'hello', d_A, P_pub_s, hid=1)
assert Verify(b'hello', sig, b'alice', P_pub_s, hid=1)

# 加密与解密
ke, P_pub_e = generate_master_key()
d_B = generate_user_enc_key(ke, b'bob', hid=3)
c = Encrypt(b'secret', b'bob', P_pub_e, hid=3)
m = Decrypt(c, d_B, b'bob', hid=3)

# 密钥封装
K_enc, C = KEM_Encapsulate(b'bob', P_pub_e, 32, hid=2)
K_dec = KEM_Decapsulate(C, d_B, b'bob', 32, hid=2)
assert K_enc == K_dec
```

---

## 6. 数字信封 (GM/T 0010-2012)

`from pysmx.extra.envelope import ...` 或 `from pysmx.extra import ...`（`pysmx.extra` 已顶层导出数字信封 API，无需再深入子模块）

数字信封结合 SM2（非对称）和 SM4-CBC（对称）加密。SM4 对称密钥用接收方 SM2 公钥加密；载荷用 SM4 密钥加密。

### 6.1 `EnvelopeResult`

```python
EnvelopeResult = namedtuple('EnvelopeResult',
    ['encrypted_key', 'iv', 'ciphertext', 'sm2_keypair'])
```

| 字段 | 类型 | 说明 |
|-------|------|-------------|
| `encrypted_key` | `bytes` | SM2 加密的 SM4 密钥 |
| `iv` | `bytes` | SM4-CBC 初始化向量 |
| `ciphertext` | `bytes` | SM4-CBC 密文 |
| `sm2_keypair` | `KeyPair` | 使用的 SM2 密钥对（可能自动生成） |

### 6.2 `envelope_encrypt(plaintext, *, public_key=None, sm2_keypair=None, sm4_key=None, iv=None) -> EnvelopeResult`

数字信封加密。

| 参数 | 类型 | 默认值 | 说明 |
|-----------|------|---------|-------------|
| `plaintext` | `bytes` | — | 待加密数据 |
| `public_key` | `bytes` | `None` | 接收方 SM2 公钥 |
| `sm2_keypair` | `KeyPair` | `None` | SM2 密钥对（None 时自动生成） |
| `sm4_key` | `bytes` | `None` | 16 字节 SM4 密钥（None 时自动生成） |
| `iv` | `bytes` | `None` | 16 字节 IV（None 时自动生成） |

### 6.3 `envelope_decrypt(encrypted_key, iv, ciphertext, private_key) -> bytes`

数字信封解密。

| 参数 | 类型 | 说明 |
|-----------|------|-------------|
| `encrypted_key` | `bytes` | SM2 加密的 SM4 密钥 |
| `iv` | `bytes` | 16 字节 IV |
| `ciphertext` | `bytes` | SM4-CBC 密文 |
| `private_key` | `KeyPair` / `bytes` | 接收方 SM2 私钥 |

### 6.4 便捷函数

| 函数 | 说明 |
|----------|-------------|
| `envelope_seal(plaintext, public_key) -> EnvelopeResult` | 为指定接收方加密 |
| `envelope_open(encrypted_key, iv, ciphertext, private_key) -> bytes` | 使用私钥解密 |

---

## 7. 公共工具 (Common Utilities)

`from pysmx.common import ...` / `from pysmx.common.random import ...`

`pysmx.common` 提供分组密码填充方案以及全仓库统一的密码学安全随机源。

### 7.1 填充工具

分组密码填充方案。

| 类 | 输入 | 输出 |
|-------|-------|--------|
| `PKCS5Padding` | `data, block_size` | 填充后字节 |
| `PKCS5UnPadding` | `data` | 去填充后字节 |
| `PKCS7Padding` | `data, block_size` | 填充后字节 |
| `PKCS7UnPadding` | `data` | 去填充后字节 |
| `ZeroPadding` | `data, block_size` | 填充后字节 |
| `ZeroUnPadding` | `data` | 去填充后字节 |
| `ISO10126Padding` | `data, block_size` | 填充后字节 |
| `ISO10126UnPadding` | `data` | 去填充后字节 |
| `NoPadding` | `data, block_size` | 填充后字节 |
| `NoUnPadding` | `data` | 去填充后字节 |

```python
from pysmx.common import PKCS7Padding, PKCS7UnPadding

padder = PKCS7Padding()
padded = padder.pad(b'hello', block_size=16)

unpadder = PKCS7UnPadding()
original = unpadder.unpad(padded)
```

### 7.2 随机源工具 (CSPRNG)

`from pysmx.common.random import random_bytes, random_int, random_hex`

这是全仓库随机源的**唯一来源**，底层基于 `secrets` / `os.urandom`，输出可用于 SM2 私钥、SM2/SM9 临时值等密码学材料，符合 GM/T 0003 / GM/T 0009（随机值须落在 `[1, n-1]`）。SM2、SM9、数字信封均复用此模块，避免散落的不可预测 PRNG 用法。

#### `random_bytes(n) -> bytes`

返回 `n` 个密码学安全随机字节；`n` 为负数时抛出 `ValueError`。

#### `random_int(upper) -> int`

返回位于 `[1, upper - 1]` 的密码学安全随机整数，可直接作为素阶群的标量（私钥 / 临时值）；`upper` 不大于 2 时抛出 `ValueError`。

#### `random_hex(n) -> str`

返回 `2n` 位小写十六进制随机字符串（即 `random_bytes(n)` 的十六进制编码）。

**使用示例:**

```python
from pysmx.common.random import random_bytes, random_int, random_hex
from pysmx.SM2 import sm2_N

iv = random_bytes(16)     # 16 字节 SM4-CBC IV
k = random_int(sm2_N)     # SM2 私钥 / 加密临时值（[1, sm2_N-1]）
seed = random_hex(16)     # 32 位小写十六进制随机串
```

---

## 8. Cryptography Hazmat 底层原语

`from pysmx.SM2._cryptography import ...`
`from pysmx.SM9._cryptography import ...`

底层密码原语（兼容 `cryptography.hazmat` 模式）。

### 8.1 SM2 椭圆曲线

```python
from pysmx.SM2._cryptography import (
    SM2EllipticCurve,
    SM2EllipticCurvePrivateKey,
    SM2SM3SignatureAlgorithm,
)

curve = SM2EllipticCurve()
sk = SM2EllipticCurvePrivateKey.generate(curve)
pk = sk.public_key()
sig = sk.sign(b'hello', SM2SM3SignatureAlgorithm())
pk.verify(sig, b'hello', SM2SM3SignatureAlgorithm())
c = sk.encrypt_sm2(b'hello')
m = sk.decrypt_sm2(c)
```

### 8.2 SM9 椭圆曲线

```python
from pysmx.SM9._cryptography import (
    SM9EllipticCurve,
    SM9EllipticCurvePrivateKey,
    SM9EllipticCurvePublicKey,
    SM9SM3SignatureAlgorithm,
)
```

---

## 9. crypto - 密码学工具

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

## 10. 版本信息

```python
from pysmx import VERSION, __version__

print(__version__)  # "1.0.1"
print(VERSION)      # (1, 0, 1)
```

---

## 11. 快速参考

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

### SM4 流式加解密

```python
from pysmx.SM4 import SM4Stream, ENCRYPT, DECRYPT

key = b'0123456789abcdef'
iv = b'abcdef0123456789'

# 加密
stream = SM4Stream(key, ENCRYPT, iv, method='cbc')
ct = stream.update(data_chunk1) + stream.update(data_chunk2)
ct += stream.finalize()

# 解密
stream = SM4Stream(key, DECRYPT, iv, method='cbc')
pt = stream.update(ct) + stream.finalize()
```

### ZUC 序列密码

```python
from pysmx.ZUC import ZUC

zuc = ZUC(key=[0]*16, iv=[0]*16)
keystream = zuc.zuc_generate_keystream()
```

### SM9 签名与验签

```python
from pysmx.SM9 import (
    Sign, Verify, generate_master_key, generate_user_sign_key,
)

ks, P_pub_s = generate_master_key()
d_A = generate_user_sign_key(ks, b'alice', hid=1)
sig = Sign(b'hello', d_A, P_pub_s, hid=1)
assert Verify(b'hello', sig, b'alice', P_pub_s, hid=1)
```

### SM9 加密与解密

```python
from pysmx.SM9 import (
    Encrypt, Decrypt, generate_master_key, generate_user_enc_key,
)

ke, P_pub_e = generate_master_key()
d_B = generate_user_enc_key(ke, b'bob', hid=3)
c = Encrypt(b'secret', b'bob', P_pub_e, hid=3)
m = Decrypt(c, d_B, b'bob', hid=3)
```

### 数字信封

```python
from pysmx.extra import envelope_seal, envelope_open
from pysmx.SM2 import generate_keypair

kp = generate_keypair()
result = envelope_seal(b'data', kp.publicKey)
plain = envelope_open(result.encrypted_key, result.iv,
                      result.ciphertext, kp.privateKey)
```
