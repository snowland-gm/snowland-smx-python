# snowland-smx

[![version](https://img.shields.io/pypi/v/snowland-smx.svg)](https://pypi.python.org/pypi/snowland-smx)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FASTARCHEN%2Fsnowland-smx-python.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2FASTARCHEN%2Fsnowland-smx-python?ref=badge_shield)
[![gitee](https://gitee.com/snowlandltd/snowland-smx-python/badge/star.svg)](https://gitee.com/snowlandltd/snowland-smx-python/stargazers)
[![github](https://img.shields.io/github/stars/ASTARCHEN/snowland-smx-python)](https://img.shields.io/github/stars/ASTARCHEN/snowland-smx-python)
[![download](https://img.shields.io/pypi/dm/snowland-smx.svg?cacheSeconds=43200)](https://pypi.org/project/snowland-smx)
[![wheels](https://img.shields.io/pypi/wheel/snowland-smx.svg)](https://pypi.python.org/pypi/snowland-smx)
[![CodeFactor](https://www.codefactor.io/repository/github/astarchen/astartool/badge/master)](https://www.codefactor.io/repository/github/astarchen/astartool/overview/master)

Python implementation of Chinese national cryptographic algorithms (GM/T):
SM2, SM3, SM4, ZUC.

## Installation

```bash
pip install snowland-smx
```

Or install from source:

```bash
python setup.py install
```

---

## SM2 - Elliptic Curve Public Key Cryptography

SM2 asymmetric encryption, decryption, signing, and verification.

### Key Generation

```python
from pysmx.SM2 import generate_keypair

kp = generate_keypair()
print(kp.publicKey)   # bytes
print(kp.privateKey)  # bytes
```

### Sign & Verify

```python
from pysmx.SM2 import Sign, Verify

len_para = 64
sig = Sign("你好", kp.privateKey, '12345678abcdef', len_para)
assert Verify(sig, "你好", kp.publicKey, len_para)
```

### Encrypt & Decrypt

```python
from pysmx.SM2 import Encrypt, Decrypt

len_para = 64
cipher = Encrypt(b'hello', kp.publicKey, len_para, Hexstr=0)
plain = Decrypt(cipher, kp.privateKey, len_para)
```

#### API Reference

| Function | Description |
|----------|-------------|
| `generate_keypair(len_param=64)` | Generate key pair, returns `KeyPair(publicKey, privateKey)` |
| `Sign(E, DA, K, len_para=64, Hexstr=0)` | Sign message, returns `r \|\| s` bytes |
| `Verify(Sign, E, PA, len_para=64, Hexstr=0)` | Verify signature, returns `bool` |
| `Encrypt(M, PA, len_para, Hexstr=0, hash_algorithm='sm3')` | Encrypt, returns `C1 \|\| C3 \|\| C2` bytes |
| `Decrypt(C, DA, len_para, Hexstr=0, hash_algorithm='sm3')` | Decrypt, returns plaintext bytes or `None` |

---

## SM3 - Cryptographic Hash Algorithm

SM3 produces a 256-bit (32-byte) digest, hashlib-compatible.

### Usage

**Method 1: Incremental hashing (hashlib-compatible)**

```python
from pysmx.SM3 import SM3

sm3 = SM3()
sm3.update('abc')
print(sm3.hexdigest())
```

**Method 2: One-shot hashing**

```python
from pysmx.SM3 import hash_msg

print(hash_msg('abc'))
```

**Method 3: With different encoding**

```python
from pysmx.SM3 import SM3

sm3 = SM3(encoding='gbk')
sm3.update('你好')
print(sm3.digest())  # raw bytes
```

### Key Derivation (KDF)

```python
from pysmx.SM3 import KDF

# Derive a 32-byte key from a hex string
derived_key = KDF('abc123', 32)
```

#### API Reference

| Function / Class | Description |
|------------------|-------------|
| `SM3(msg=b'', encoding='utf-8')` | SM3 hash object with `update()`, `digest()`, `hexdigest()`, `copy()` |
| `hash_msg(msg) -> str` | One-shot hash, returns hex string |
| `Hash_sm3(msg, Hexstr=0) -> str` | Hash with optional hex input |
| `digest(msg, Hexstr=0) -> bytes` | One-shot hash, returns raw bytes |
| `KDF(Z, klen) -> str` | Key derivation, `klen` in bytes |

---

## SM4 - Block Cipher

SM4 block cipher: 128-bit block size, 128-bit key. Supports ECB, CBC, PCBC, CFB, OFB modes.

### ECB Mode

```python
from pysmx.SM4 import Sm4, ENCRYPT, DECRYPT

key = b'0123456789abcdef'  # Must be exactly 16 bytes
sm4 = Sm4()

# Encrypt
sm4.sm4_set_key(key, ENCRYPT)
ciphertext = sm4.sm4_crypt_ecb(b'Hello World!')

# Decrypt
sm4.sm4_set_key(key, DECRYPT)
plaintext = sm4.sm4_crypt_ecb(ciphertext)
```

### CBC Mode

```python
from pysmx.SM4 import Sm4, ENCRYPT, DECRYPT

key = b'0123456789abcdef'
iv = b'abcdef0123456789'

sm4 = Sm4()
sm4.sm4_set_key(key, ENCRYPT)
ciphertext = sm4.sm4_crypt_cbc(iv, b'Hello World!')
```

### Using Module-Level Convenience Functions

```python
from pysmx.SM4 import sm4_crypt_ecb, sm4_crypt_cbc, ENCRYPT, DECRYPT

cipher = sm4_crypt_ecb(ENCRYPT, key, data)
cipher = sm4_crypt_cbc(ENCRYPT, key, iv, data)
```

#### API Reference

| Class / Function | Description |
|------------------|-------------|
| `Sm4(padding_method='pkcs5')` | SM4 cipher with `set_key()`, ECB/CBC/PCBC/CFB/OFB methods |
| `sm4_crypt_ecb(mode, key, data) -> bytes` | Convenience: ECB mode |
| `sm4_crypt_cbc(mode, key, iv, data) -> bytes` | Convenience: CBC mode |
| `sm4_crypt_cfb(mode, key, iv, data) -> bytes` | Convenience: CFB mode |
| `sm4_crypt_ofb(mode, key, iv, data) -> bytes` | Convenience: OFB mode |
| `sm4_crypt_pcbc(mode, key, iv, data) -> bytes` | Convenience: PCBC mode |

Constants: `ENCRYPT`, `DECRYPT`

---

## ZUC - Stream Cipher

ZUC stream cipher, used in 3GPP LTE 128-EEA3 / 128-EIA3.

```python
from pysmx.ZUC import ZUC

key = [0x00] * 16  # 16-byte key as list of ints
iv = [0x00] * 16   # 16-byte IV as list of ints

zuc = ZUC(key, iv)

# Generate key stream
keystream = zuc.zuc_generate_keystream()

# Encrypt by XOR with key stream
encrypted = list(zuc.zuc_encrypt(b'hello'))
```

#### API Reference

| Method | Description |
|--------|-------------|
| `ZUC(key, iv, buffer_size=100)` | Initialize ZUC with 16-byte key and IV (as `list[int]`) |
| `zuc_generate_keystream() -> list` | Generate a buffer of key stream words |
| `zuc_encrypt(input) -> generator` | Encrypt/decrypt by XOR with key stream |

---

## crypto - Utilities

### hashlib with SM3 Support

```python
from pysmx.crypto import hashlib

h = hashlib.new('sm3', b'hello')
print(h.hexdigest())

# Also works with standard hashlib algorithms
h = hashlib.sha256(b'hello')
```

### PBKDF2 Key Derivation

```python
from pysmx.crypto import pbkdf2_hmac

dk = pbkdf2_hmac('sm3', b'password', b'salt', iterations=100000, dklen=32)
```

#### API Reference

| Function | Description |
|----------|-------------|
| `hashlib.new(name, data=b'')` | Create hash object (supports sm3, sha256, etc.) |
| `pbkdf2_hmac(hash_name, password, salt, iterations, dklen=None)` | PKCS#5 PBKDF2 derivation |

---

## SM9

Under development.

---

## License

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FASTARCHEN%2Fsnowland-smx-python.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2FASTARCHEN%2Fsnowland-smx-python?ref=badge_large)
