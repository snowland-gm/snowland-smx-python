# snowland-smx API Documentation

## Overview

`snowland-smx` (version 0.3.2-alpha.1) is a pure Python implementation of Chinese national cryptographic algorithms (GM/T standards), including SM2, SM3, SM4, and ZUC.

Package name: `pysmx`

---

## 1. SM2 - Elliptic Curve Public Key Cryptography

`from pysmx.SM2 import ...`

SM2 is an elliptic curve public key algorithm based on the SM2 curve (256-bit prime field), supporting digital signature, verification, encryption, and decryption.

### 1.1 `generate_keypair(len_param=64) -> KeyPair`

Generate a public/private key pair.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `len_param` | `int` | `64` | Key length in hex characters |

| Return | Type | Description |
|--------|------|-------------|
| `KeyPair` | `namedtuple` | `KeyPair(publicKey, privateKey)`, both are `bytes` |

```python
from pysmx.SM2 import generate_keypair
kp = generate_keypair()
print(kp.publicKey)   # bytes
print(kp.privateKey)  # bytes
```

### 1.2 `Sign(E, DA, K, len_para=64, Hexstr=0, encoding='utf-8') -> bytes`

Sign a message using SM2.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `E` | `str` / `bytes` | — | Message or its hash. If it is a hex string, set `Hexstr=1` |
| `DA` | `str` / `bytes` | — | Private key (hex string or bytes) |
| `K` | `str` | — | Random number (hex string) |
| `len_para` | `int` | `64` | Fixed value, length parameter |
| `Hexstr` | `int` | `0` | `1` if `E` is a hex string, `0` otherwise |
| `encoding` | `str` | `'utf-8'` | Character encoding when `E` is `str` and `Hexstr=0` |

| Return | Type | Description |
|--------|------|-------------|
| Signature | `bytes` or `None` | Format: `r || s`; returns `None` on failure |

### 1.3 `Verify(Sign, E, PA, len_para=64, Hexstr=0, encoding='utf-8') -> bool`

Verify a SM2 signature.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `Sign` | `str` / `bytes` | — | Signature in `r || s` format |
| `E` | `str` / `bytes` | — | Message to verify |
| `PA` | `str` / `bytes` | — | Public key |
| `len_para` | `int` | `64` | Fixed value |
| `Hexstr` | `int` | `0` | `1` if `E` is a hex string |
| `encoding` | `str` | `'utf-8'` | Encoding when `E` is `str` and `Hexstr=0` |

| Return | Type | Description |
|--------|------|-------------|
| Result | `bool` | `True` if valid, `False` otherwise |

### 1.4 `Encrypt(M, PA, len_para, Hexstr=0, encoding='utf-8', hash_algorithm='sm3') -> bytes`

Encrypt a message using SM2.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `M` | `str` / `bytes` | — | Plaintext. If hex string, set `Hexstr=1` |
| `PA` | `str` / `bytes` | — | Public key |
| `len_para` | `int` | — | Fixed value `64` |
| `Hexstr` | `int` | `0` | `1` if `M` is a hex string |
| `encoding` | `str` | `'utf-8'` | Encoding when `M` is `str` and `Hexstr=0` |
| `hash_algorithm` | `str` | `'sm3'` | Hash algorithm name (supports all hashlib algorithms) |

| Return | Type | Description |
|--------|------|-------------|
| Ciphertext | `bytes` or `None` | Format: `C1 || C3 || C2`; returns `None` on failure |

### 1.5 `Decrypt(C, DA, len_para, Hexstr=0, encoding='utf-8', hash_algorithm='sm3') -> bytes`

Decrypt a SM2 ciphertext.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `C` | `str` / `bytes` | — | Ciphertext. If hex string, set `Hexstr=1` |
| `DA` | `str` / `bytes` | — | Private key |
| `len_para` | `int` | — | Fixed value `64` |
| `Hexstr` | `int` | `0` | `1` if `C` is a hex string |
| `encoding` | `str` | `'utf-8'` | Encoding |
| `hash_algorithm` | `str` / `callable` | `'sm3'` | Hash algorithm (name or callable) |

| Return | Type | Description |
|--------|------|-------------|
| Plaintext | `bytes` or `None` | Returns `None` if integrity check fails |

### 1.6 `SM2` Class

A higher-level class inheriting from `ECCAlgorithm`.

```python
class SM2(ECCAlgorithm):
    name = 'sm2'
    key_size = 64

    def __init__(self, pk=None, sk=None, key=None, curve=CurveSM2)
    def sign(self, message)       # stub (not yet implemented)
    def verify(self, message)     # stub
    def encrypt(self, message)    # stub
    def decrypt(self, message)    # stub
```

---

## 2. SM3 - Cryptographic Hash Algorithm

`from pysmx.SM3 import ...`

SM3 is a cryptographic hash function producing a 256-bit (32-byte) digest.

### 2.1 `SM3Type` / `SM3` Class

`SM3` is an alias for `SM3Type`. It provides a hashlib-compatible interface.

```python
class SM3Type:
    name = 'SM3'
    digest_size = 32    # 32 bytes (256 bits)
    block_size = 64     # 64 bytes

    def __init__(self, msg=b'', encoding='utf-8')
    def update(self, msg)        # Feed data incrementally
    def digest(self) -> bytes    # Get raw digest, resets state
    def hexdigest(self) -> str   # Get hex digest string
    def copy(self)               # Return a copy of the hash object
```

**Usage:**

```python
from pysmx.SM3 import SM3

# Method 1: One-shot
sm3 = SM3(b'abc')
print(sm3.hexdigest())

# Method 2: Incremental
sm3 = SM3()
sm3.update(b'abc')
print(sm3.hexdigest())
```

### 2.2 `hash_msg(msg) -> str`

Compute SM3 hash of a message and return hex string.

| Parameter | Type | Description |
|-----------|------|-------------|
| `msg` | `str` / `bytes` | Input message |

| Return | Type | Description |
|--------|------|-------------|
| Hash | `str` | 64-character hex string |

### 2.3 `Hash_sm3(msg, Hexstr=0) -> str`

Compute SM3 hash with optional hex input.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `msg` | `str` | — | Input message |
| `Hexstr` | `int` | `0` | `1` if `msg` is a hex string |

| Return | Type | Description |
|--------|------|-------------|
| Hash | `str` | Hex digest |

> `hexdigest` is an alias for `Hash_sm3`.

### 2.4 `digest(msg, Hexstr=0) -> bytes`

Compute SM3 hash and return raw bytes.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `msg` | `list` / `str` | — | Input as byte list or string |
| `Hexstr` | `int` | `0` | `1` if `msg` is a hex string |

| Return | Type | Description |
|--------|------|-------------|
| Digest | `bytes` | 32-byte raw digest |

### 2.5 `KDF(Z, klen) -> str`

SM3-based Key Derivation Function.

| Parameter | Type | Description |
|-----------|------|-------------|
| `Z` | `str` | Input bit string in hex |
| `klen` | `int` | Desired key length in **bytes** |

| Return | Type | Description |
|--------|------|-------------|
| Derived key | `str` | Hex string of length `klen * 2` |

### 2.6 Utility Functions

| Function | Description |
|----------|-------------|
| `str2bytes(msg, encoding='utf-8')` | Convert string to byte list |
| `byte2str(msg, decode='utf-8')` | Convert byte list to string |
| `hex2byte(msg)` | Convert hex string to byte list |
| `rotate_left(a, k)` | 32-bit rotate left |

---

## 3. SM4 - Block Cipher

`from pysmx.SM4 import ...`

SM4 is a block cipher with 128-bit (16-byte) block size and 128-bit key.

### 3.1 Constants

```python
from pysmx.SM4 import ENCRYPT, DECRYPT
```

- `ENCRYPT` — Encryption mode
- `DECRYPT` — Decryption mode

### 3.2 `Sm4` Class (also exported as `SM4`)

Inherits from `BlockCyphers`. Supports multiple block cipher modes with automatic padding.

```python
class Sm4(BlockCyphers):
    block_size = 16
    name = 'SM4'

    def __init__(self, padding_method='pkcs5', unpadding_method=None)
```

#### Methods:

##### `set_key(key, mode)` / `sm4_set_key` / `sm4_setkey`

Set the encryption key and mode.

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `bytes` | 16-byte (128-bit) key |
| `mode` | `int` | `ENCRYPT` or `DECRYPT` |

##### `sm4_crypt_ecb(input_data) -> bytes`

ECB mode encryption/decryption.

| Parameter | Type | Description |
|-----------|------|-------------|
| `input_data` | iterable | Input data bytes |

##### `sm4_crypt_cbc(iv, input_data) -> bytes`

CBC mode encryption/decryption.

| Parameter | Type | Description |
|-----------|------|-------------|
| `iv` | `bytes` | 16-byte initialization vector |
| `input_data` | iterable | Input data bytes |

##### `sm4_crypt_pcbc(iv, input_data) -> bytes`

PCBC (Propagating CBC) mode.

##### `sm4_crypt_cfb(iv, input_data) -> bytes`

CFB (Cipher Feedback) mode.

##### `sm4_crypt_ofb(iv, input_data) -> bytes`

OFB (Output Feedback) mode.

##### `one_round(sk, in_put) -> bytes`

Single round of SM4 on 16 bytes of input with 32 round keys.

**Usage Example:**

```python
from pysmx.SM4 import Sm4, ENCRYPT, DECRYPT

key = b'hello word errrr...'  # Must be 16 bytes

# Encryption
sm4 = Sm4()
sm4.sm4_set_key(key, ENCRYPT)
ciphertext = sm4.sm4_crypt_ecb([1, 2, 3])

# Decryption
sm4.sm4_set_key(key, DECRYPT)
plaintext = sm4.sm4_crypt_ecb(ciphertext)
```

### 3.3 Module-Level Convenience Functions

These functions create a temporary `Sm4` instance for single operations.

| Function | Signature |
|----------|-----------|
| `sm4_crypt_ecb(mode, key, data) -> bytes` | ECB mode encrypt/decrypt |
| `sm4_crypt_cbc(mode, key, iv, data) -> bytes` | CBC mode encrypt/decrypt |
| `sm4_crypt_pcbc(mode, key, iv, data) -> bytes` | PCBC mode encrypt/decrypt |
| `sm4_crypt_cfb(mode, key, iv, data) -> bytes` | CFB mode encrypt/decrypt |
| `sm4_crypt_ofb(mode, key, iv, data) -> bytes` | OFB mode encrypt/decrypt |

| Parameter | Type | Description |
|-----------|------|-------------|
| `mode` | `int` | `ENCRYPT` or `DECRYPT` |
| `key` | `bytes` | 16-byte key |
| `iv` | `bytes` | 16-byte IV (for CBC/PCBC/CFB/OFB) |
| `data` | `bytes` | Input data |

### 3.4 `SM4BlockCyphers` Class

Alternative SM4 implementation with the same interface as `Sm4`, but with constructor that directly takes key and IV.

```python
class SM4BlockCyphers(BlockCyphers):
    block_size = 16
    name = 'SM4'

    def __init__(self, key, iv=None, mode=ENCRYPT,
                 padding_method='pkcs5', unpadding_method=None)
```

---

## 4. ZUC - Stream Cipher

`from pysmx.ZUC import ZUC`

ZUC is a word-oriented stream cipher, used in 3GPP LTE confidentiality and integrity algorithms (128-EEA3 and 128-EIA3).

### 4.1 `ZUC` Class

```python
class ZUC(Iterable):
    def __init__(self, key, iv, buffer_size=100)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `list[int]` | 16-byte key as list of 16 integers |
| `iv` | `list[int]` | 16-byte IV as list of 16 integers |
| `buffer_size` | `int` | Buffer size for key stream generation (default: 100) |

#### Methods:

##### `zuc_generate_keystream() -> list`

Generate a buffer of key stream words.

##### `zuc_encrypt(input) -> generator`

Encrypt input by XOR with key stream. Returns a generator yielding encrypted bytes.

| Parameter | Type | Description |
|-----------|------|-------------|
| `input` | iterable | Input plaintext bytes |

##### `__next__() -> int`

Generate next key stream word (32-bit).

##### `__iter__() -> self`

Supports iteration. Each iteration yields one 32-bit key stream word.

**Usage Example:**

```python
from pysmx.ZUC import ZUC

key = [0x00] * 16
iv = [0x00] * 16
zuc = ZUC(key, iv)
key_stream = zuc.zuc_generate_keystream()
```

---

## 5. crypto - Cryptographic Utilities

`from pysmx.crypto import ...`

### 5.1 `pbkdf2_hmac(hash_name, password, salt, iterations, dklen=None) -> bytes`

PBKDF2 key derivation function (PKCS #5 v2.0).

| Parameter | Type | Description |
|-----------|------|-------------|
| `hash_name` | `str` | Hash algorithm name (e.g., `'sm3'`, `'sha256'`) |
| `password` | `bytes` / `bytearray` | Password |
| `salt` | `bytes` / `bytearray` | Salt |
| `iterations` | `int` | Number of iterations (must be >= 1) |
| `dklen` | `int` or `None` | Desired key length in bytes (default: hash digest size) |

| Return | Type | Description |
|--------|------|-------------|
| Derived key | `bytes` | Derived key of length `dklen` |

### 5.2 `hashlib` Module

`pysmx.crypto.hashlib` extends Python's standard `hashlib` with SM3 support.

#### `new(name, data=b'', **kwargs) -> hash object`

Create a new hash object.

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | `str` | Algorithm name |
| `data` | `bytes` | Optional initial data |

Supported algorithms: `sm3`, `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`, `blake2b`, `blake2s`, `sha3_224`, `sha3_256`, `sha3_384`, `sha3_512`, `shake_128`, `shake_256`.

```python
from pysmx.crypto import hashlib
h = hashlib.new('sm3', b'hello')
print(h.hexdigest())
```

#### Module-Level Constructor Functions

Each supported algorithm is available as a module-level constructor:

```python
from pysmx.crypto.hashing import sm3
h = sm3(b'hello')
```

#### Constants

| Name | Type | Description |
|------|------|-------------|
| `algorithms_guaranteed` | `set` | Set of always-available algorithms |
| `algorithms_available` | `set` | Set of all available algorithms |

---

## 6. Version Information

```python
from pysmx import VERSION, __version__

print(__version__)  # "0.3.2-alpha.1"
print(VERSION)      # (0, 3, 2, 'alpha', 1)
```

---

## 7. Quick Reference

### SM2 Sign & Verify

```python
from pysmx.SM2 import generate_keypair, Sign, Verify

kp = generate_keypair()
sig = Sign("hello", kp.privateKey, '12345678abcdef', 64)
valid = Verify(sig, "hello", kp.publicKey, 64)
```

### SM2 Encrypt & Decrypt

```python
from pysmx.SM2 import generate_keypair, Encrypt, Decrypt

kp = generate_keypair()
cipher = Encrypt(b'secret message', kp.publicKey, 64, 0)
plain = Decrypt(cipher, kp.privateKey, 64)
```

### SM3 Hash

```python
from pysmx.SM3 import hash_msg, SM3

print(hash_msg('abc'))

sm3 = SM3()
sm3.update(b'abc')
print(sm3.hexdigest())
```

### SM4 Encrypt & Decrypt

```python
from pysmx.SM4 import Sm4, ENCRYPT, DECRYPT

key = b'0123456789abcdef'  # exactly 16 bytes
sm4 = Sm4()
sm4.sm4_set_key(key, ENCRYPT)
cipher = sm4.sm4_crypt_ecb(b'Hello World!')
sm4.sm4_set_key(key, DECRYPT)
plain = sm4.sm4_crypt_ecb(cipher)
```

### ZUC Stream Cipher

```python
from pysmx.ZUC import ZUC

zuc = ZUC(key=[0]*16, iv=[0]*16)
keystream = zuc.zuc_generate_keystream()
```
