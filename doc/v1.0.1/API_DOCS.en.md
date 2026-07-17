# snowland-smx API Documentation

## Overview

`snowland-smx` (version 1.0.1) is a pure Python implementation of Chinese national cryptographic algorithms (GM/T standards), including SM2, SM3, SM4, SM9, and ZUC.

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

### 3.5 `SM4Stream` Class (Streaming Cipher)

Provides `update()` / `finalize()` interface for incremental processing of large data without loading everything into memory. Supports all 5 modes.

```python
class SM4Stream:
    block_size = 16

    def __init__(self, key, mode, iv=None, method='ecb',
                 padding_method='pkcs5')
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `key` | `bytes` | — | 16-byte key |
| `mode` | `int` | — | `ENCRYPT` or `DECRYPT` |
| `iv` | `bytes` | `None` | 16-byte IV (ignored for ECB) |
| `method` | `str` | `'ecb'` | Mode: `'ecb'`, `'cbc'`, `'cfb'`, `'ofb'`, `'pcbc'` |
| `padding_method` | `str` | `'pkcs5'` | Padding scheme: `'pkcs5'` or `'pkcs7'` |

#### Methods:

##### `update(data) -> bytes`

Feed data incrementally. Returns processed output bytes. May return empty bytes when not enough data to form a complete block.

| Parameter | Type | Description |
|-----------|------|-------------|
| `data` | `bytes` | Input data chunk |

##### `finalize() -> bytes`

Finish stream processing and return remaining output. For encryption: pads and processes the last block(s). For decryption: removes padding.

**Usage Example:**

```python
from pysmx.SM4 import SM4Stream, ENCRYPT, DECRYPT

key = b'0123456789abcdef'
iv = b'abcdef0123456789'

# Encrypt
stream = SM4Stream(key, ENCRYPT, iv, method='cbc')
ct = b''
with open('large_file.bin', 'rb') as f:
    while True:
        chunk = f.read(64 * 1024)
        if not chunk:
            break
        ct += stream.update(chunk)
ct += stream.finalize()

# Decrypt
stream = SM4Stream(key, DECRYPT, iv, method='cbc')
pt = stream.update(ct)
pt += stream.finalize()
```

### 3.6 `SM4StreamCipher` Class (cryptography-layer streaming API)

Available from `pysmx.SM4._cryptography`. Provides the same streaming functionality as `SM4Stream` within the cryptography compatibility layer.

```python
class SM4StreamCipher:
    def __init__(self, key, direction, iv=None, mode='cbc',
                 padding_method='pkcs5')
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `key` | `bytes` | — | 16-byte key |
| `direction` | `int` | — | `ENCRYPT` or `DECRYPT` |
| `iv` | `bytes` | `None` | 16-byte IV |
| `mode` | `str` | `'cbc'` | Mode: `'ecb'`, `'cbc'`, `'cfb'`, `'ofb'`, `'pcbc'` |
| `padding_method` | `str` | `'pkcs5'` | Padding scheme |

Methods: `update(data) -> bytes`, `finalize() -> bytes` — same as `SM4Stream`.

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

## 5. SM9 - Identity-Based Cryptography

`from pysmx.SM9 import ...`

SM9 is an identity-based cryptographic (IBC) scheme using bilinear pairings on Barreto-Naehrig (BN) curves, supporting digital signature, encryption, and KEM.

### 5.1 `generate_master_key() -> Tuple[bytes, bytes]`

Generate the master key pair.

| Return | Type | Description |
|--------|------|-------------|
| `(ks, P_pub_s)` | `(bytes, bytes)` | Master private key and master public key |

### 5.2 `generate_user_sign_key(ks, ID_A, hid=1) -> bytes`

Derive a user's private signing key from the master key.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ks` | `bytes` | — | Master private signing key |
| `ID_A` | `bytes` | — | User identity |
| `hid` | `int` | `1` | Hash ID (0x01 for signing) |

| Return | Type | Description |
|--------|------|-------------|
| `d_A` | `bytes` | User private signing key |

### 5.3 `Sign(M, d_A, P_pub_s, hid=1) -> bytes`

Sign a message using SM9.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `M` | `bytes` | — | Message to sign |
| `d_A` | `bytes` | — | User private signing key |
| `P_pub_s` | `bytes` | — | Master public signing key |
| `hid` | `int` | `1` | Hash ID |

| Return | Type | Description |
|--------|------|-------------|
| Signature | `bytes` | SM9 signature |

### 5.4 `Verify(M, signature, ID_A, P_pub_s, hid=1) -> bool`

Verify an SM9 signature.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `M` | `bytes` | — | Original message |
| `signature` | `bytes` | — | Signature to verify |
| `ID_A` | `bytes` | — | Signer identity |
| `P_pub_s` | `bytes` | — | Master public signing key |
| `hid` | `int` | `1` | Hash ID |

| Return | Type | Description |
|--------|------|-------------|
| Result | `bool` | `True` if valid |

### 5.5 `generate_user_enc_key(ke, ID_B, hid=3) -> bytes`

Derive a user's private encryption key.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ke` | `bytes` | — | Master private encryption key |
| `ID_B` | `bytes` | — | User identity |
| `hid` | `int` | `3` | Hash ID (0x03 for encryption) |

### 5.6 `Encrypt(M, ID_B, P_pub_e, hid=3) -> bytes`

Encrypt a message for an identity.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `M` | `bytes` | — | Plaintext |
| `ID_B` | `bytes` | — | Recipient identity |
| `P_pub_e` | `bytes` | — | Master public encryption key |
| `hid` | `int` | `3` | Hash ID |

### 5.7 `Decrypt(C, d_B, ID_B, hid=3) -> bytes`

Decrypt an SM9 ciphertext.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `C` | `bytes` | — | Ciphertext |
| `d_B` | `bytes` | — | User private encryption key |
| `ID_B` | `bytes` | — | Recipient identity |
| `hid` | `int` | `3` | Hash ID |

### 5.8 `KEM_Encapsulate(ID_B, P_pub_e, klen, hid=2) -> Tuple[bytes, bytes]`

SM9 key encapsulation mechanism — encapsulate a shared secret.

| Parameter | Type | Description |
|-----------|------|-------------|
| `ID_B` | `bytes` | Recipient identity |
| `P_pub_e` | `bytes` | Master public encryption key |
| `klen` | `int` | Desired key length in bytes |
| `hid` | `int` | Hash ID (default: `2`) |

| Return | Type | Description |
|--------|------|-------------|
| `(K, C)` | `(bytes, bytes)` | Shared secret and ciphertext |

### 5.9 `KEM_Decapsulate(C1, d_B, ID_B, klen, hid=2) -> bytes`

SM9 key encapsulation mechanism — decapsulate a shared secret.

| Parameter | Type | Description |
|-----------|------|-------------|
| `C1` | `bytes` | Ciphertext from encapsulation |
| `d_B` | `bytes` | User private encryption key |
| `ID_B` | `bytes` | Recipient identity |
| `klen` | `int` | Desired key length in bytes |
| `hid` | `int` | Hash ID |

### 5.10 Utility Functions

| Function | Description |
|----------|-------------|
| `sm9_hex(data) -> str` | Convert bytes to hex string |
| `sm9_unhex(data) -> bytes` | Convert hex string to bytes |

**Usage Example:**

```python
from pysmx.SM9 import (
    Sign, Verify, Encrypt, Decrypt,
    generate_master_key,
    generate_user_sign_key,
    generate_user_enc_key,
    KEM_Encapsulate, KEM_Decapsulate,
)

# Signature
ks, P_pub_s = generate_master_key()
d_A = generate_user_sign_key(ks, b'alice', hid=1)
sig = Sign(b'hello', d_A, P_pub_s, hid=1)
assert Verify(b'hello', sig, b'alice', P_pub_s, hid=1)

# Encryption
ke, P_pub_e = generate_master_key()
d_B = generate_user_enc_key(ke, b'bob', hid=3)
c = Encrypt(b'secret', b'bob', P_pub_e, hid=3)
m = Decrypt(c, d_B, b'bob', hid=3)

# KEM
K_enc, C = KEM_Encapsulate(b'bob', P_pub_e, 32, hid=2)
K_dec = KEM_Decapsulate(C, d_B, b'bob', 32, hid=2)
assert K_enc == K_dec
```

---

## 6. Digital Envelope (GM/T 0010-2012)

`from pysmx.extra.envelope import ...`

A digital envelope combines SM2 (asymmetric) and SM4-CBC (symmetric) encryption. The SM4 symmetric key is encrypted with the receiver's SM2 public key; the payload is encrypted with the SM4 key.

### 6.1 `EnvelopeResult`

```python
EnvelopeResult = namedtuple('EnvelopeResult',
    ['encrypted_key', 'iv', 'ciphertext', 'sm2_keypair'])
```

| Field | Type | Description |
|-------|------|-------------|
| `encrypted_key` | `bytes` | SM2-encrypted SM4 key |
| `iv` | `bytes` | SM4-CBC initialization vector |
| `ciphertext` | `bytes` | SM4-CBC ciphertext |
| `sm2_keypair` | `KeyPair` | SM2 key pair used (may be auto-generated) |

### 6.2 `envelope_encrypt(plaintext, *, public_key=None, sm2_keypair=None, sm4_key=None, iv=None) -> EnvelopeResult`

Encrypt data with a digital envelope.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `plaintext` | `bytes` | — | Data to encrypt |
| `public_key` | `bytes` | `None` | Receiver's SM2 public key |
| `sm2_keypair` | `KeyPair` | `None` | SM2 key pair (auto-generated if None) |
| `sm4_key` | `bytes` | `None` | 16-byte SM4 key (auto-generated if None) |
| `iv` | `bytes` | `None` | 16-byte IV (auto-generated if None) |

### 6.3 `envelope_decrypt(encrypted_key, iv, ciphertext, private_key) -> bytes`

Decrypt data from a digital envelope.

| Parameter | Type | Description |
|-----------|------|-------------|
| `encrypted_key` | `bytes` | SM2-encrypted SM4 key |
| `iv` | `bytes` | 16-byte IV |
| `ciphertext` | `bytes` | SM4-CBC ciphertext |
| `private_key` | `KeyPair` / `bytes` | Receiver's SM2 private key |

### 6.4 Convenience Functions

| Function | Description |
|----------|-------------|
| `envelope_seal(plaintext, public_key) -> EnvelopeResult` | Encrypt for a specific receiver |
| `envelope_open(encrypted_key, iv, ciphertext, private_key) -> bytes` | Decrypt with private key |

---

## 7. Padding Utilities

`from pysmx.common import ...`

Block cipher padding schemes.

| Class | Input | Output |
|-------|-------|--------|
| `PKCS5Padding` | `data, block_size` | Padded bytes |
| `PKCS5UnPadding` | `data` | Unpadded bytes |
| `PKCS7Padding` | `data, block_size` | Padded bytes |
| `PKCS7UnPadding` | `data` | Unpadded bytes |
| `ZeroPadding` | `data, block_size` | Padded bytes |
| `ZeroUnPadding` | `data` | Unpadded bytes |
| `ISO10126Padding` | `data, block_size` | Padded bytes |
| `ISO10126UnPadding` | `data` | Unpadded bytes |
| `NoPadding` | `data, block_size` | Padded bytes |
| `NoUnPadding` | `data` | Unpadded bytes |

```python
from pysmx.common import PKCS7Padding, PKCS7UnPadding

padder = PKCS7Padding()
padded = padder.pad(b'hello', block_size=16)

unpadder = PKCS7UnPadding()
original = unpadder.unpad(padded)
```

---

## 8. Cryptography Hazmat Primitives

`from pysmx.SM2._cryptography import ...`
`from pysmx.SM9._cryptography import ...`

Low-level cryptography primitives (compatible with `cryptography.hazmat` patterns).

### 8.1 SM2 Elliptic Curve

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

### 8.2 SM9 Elliptic Curve

```python
from pysmx.SM9._cryptography import (
    SM9EllipticCurve,
    SM9EllipticCurvePrivateKey,
    SM9EllipticCurvePublicKey,
    SM9SM3SignatureAlgorithm,
)
```

---

## 9. crypto - Cryptographic Utilities

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

## 10. Version Information

```python
from pysmx import VERSION, __version__

print(__version__)  # "1.0.1"
print(VERSION)      # (1, 0, 1)
```

---

## 11. Quick Reference

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

### SM4 Streaming

```python
from pysmx.SM4 import SM4Stream, ENCRYPT, DECRYPT

key = b'0123456789abcdef'
iv = b'abcdef0123456789'

# Encrypt
stream = SM4Stream(key, ENCRYPT, iv, method='cbc')
ct = stream.update(data_chunk1) + stream.update(data_chunk2)
ct += stream.finalize()

# Decrypt
stream = SM4Stream(key, DECRYPT, iv, method='cbc')
pt = stream.update(ct) + stream.finalize()
```

### ZUC Stream Cipher

```python
from pysmx.ZUC import ZUC

zuc = ZUC(key=[0]*16, iv=[0]*16)
keystream = zuc.zuc_generate_keystream()
```

### SM9 Sign & Verify

```python
from pysmx.SM9 import (
    Sign, Verify, generate_master_key, generate_user_sign_key,
)

ks, P_pub_s = generate_master_key()
d_A = generate_user_sign_key(ks, b'alice', hid=1)
sig = Sign(b'hello', d_A, P_pub_s, hid=1)
assert Verify(b'hello', sig, b'alice', P_pub_s, hid=1)
```

### SM9 Encrypt & Decrypt

```python
from pysmx.SM9 import (
    Encrypt, Decrypt, generate_master_key, generate_user_enc_key,
)

ke, P_pub_e = generate_master_key()
d_B = generate_user_enc_key(ke, b'bob', hid=3)
c = Encrypt(b'secret', b'bob', P_pub_e, hid=3)
m = Decrypt(c, d_B, b'bob', hid=3)
```

### Digital Envelope

```python
from pysmx.extra.envelope import envelope_seal, envelope_open
from pysmx.SM2 import generate_keypair

kp = generate_keypair()
result = envelope_seal(b'data', kp.publicKey)
plain = envelope_open(result.encrypted_key, result.iv,
                      result.ciphertext, kp.privateKey)
```
