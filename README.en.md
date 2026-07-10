# snowland-smx

[![version](https://img.shields.io/pypi/v/snowland-smx.svg)](https://pypi.python.org/pypi/snowland-smx)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fsnowland-gm%2Fsnowland-smx-python.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fsnowland-gm%2Fsnowland-smx-python?ref=badge_shield)
[![gitee](https://gitee.com/snowlandltd/snowland-smx-python/badge/star.svg)](https://gitee.com/snowlandltd/snowland-smx-python/stargazers)
[![github](https://img.shields.io/github/stars/snowland-gm/snowland-smx-python)](https://github.com/snowland-gm/snowland-smx-python)
[![download](https://img.shields.io/pypi/dm/snowland-smx.svg?cacheSeconds=86400)](https://pypi.org/project/snowland-smx)
[![wheels](https://img.shields.io/pypi/wheel/snowland-smx.svg)](https://pypi.python.org/pypi/snowland-smx)
[![CodeFactor](https://www.codefactor.io/repository/github/astarchen/astartool/badge/master)](https://www.codefactor.io/repository/github/astarchen/astartool/overview/master)

Python implementation of Chinese national cryptographic algorithms (GM/T):
SM2, SM3, SM4, SM9, ZUC.

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
| `SM3Type` | SM3 hash object type (alias for `SM3`, for type checking) |
| `hash_msg(msg) -> str` | One-shot hash, returns hex string |
| `hexdigest(msg) -> str` | One-shot hash, returns hex string |
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

### Streaming Encryption/Decryption (Large Data)

`SM4Stream` provides an `update()` / `finalize()` interface for incremental

processing of large data without loading everything into memory:

```python
from pysmx.SM4 import SM4Stream, ENCRYPT, DECRYPT

key = b'0123456789abcdef'
iv = b'abcdef0123456789'

# Encrypt
stream = SM4Stream(key, ENCRYPT, iv, method='cbc')
ciphertext = b''
with open('large_file.bin', 'rb') as f:
    while True:
        chunk = f.read(64 * 1024)  # 64KB per chunk
        if not chunk:
            break
        ciphertext += stream.update(chunk)
ciphertext += stream.finalize()

# Decrypt
stream = SM4Stream(key, DECRYPT, iv, method='cbc')
plaintext = b''
for chunk in split_into_chunks(ciphertext, 64 * 1024):
    plaintext += stream.update(chunk)
plaintext += stream.finalize()
```

#### API Reference

| Class / Function | Description |
|------------------|-------------|
| `Sm4(padding_method='pkcs5')` | SM4 cipher with `set_key()`, ECB/CBC/PCBC/CFB/OFB methods |
| `SM4` | Alias for `Sm4` |
| `SM4Stream(key, mode, iv=None, method='ecb', padding_method='pkcs5')` | Streaming cipher: `update(data)` for incremental processing, `finalize()` to finish |
| `SM4BlockCyphers` | Block cipher wrapper for multi-block encryption/decryption |
| `sm4_crypt_ecb(mode, key, data) -> bytes` | Convenience: ECB mode |
| `sm4_crypt_cbc(mode, key, iv, data) -> bytes` | Convenience: CBC mode |
| `sm4_crypt_cfb(mode, key, iv, data) -> bytes` | Convenience: CFB mode |
| `sm4_crypt_ofb(mode, key, iv, data) -> bytes` | Convenience: OFB mode |
| `sm4_crypt_pcbc(mode, key, iv, data) -> bytes` | Convenience: PCBC mode |

Constants: `ENCRYPT`, `DECRYPT`

`SM4Stream` method parameter: `'ecb'`, `'cbc'`, `'cfb'`, `'ofb'`, `'pcbc'`.

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

## SM9 - Identity-Based Cryptography

SM9 is identity-based cryptography (GM/T 0044-2016) based on BN curve bilinear pairings. Currently experimental. API overview:

```python
from pysmx.SM9 import (
    Sign, Verify,
    Encrypt, Decrypt,
    KEM_Encapsulate, KEM_Decapsulate,
    generate_master_key,
    generate_user_sign_key,
    generate_user_enc_key,
)
# Internal helpers for computing signing master public key
from pysmx.SM9._SM9 import _g2_to_affine, _g2_scalar_mult, _sm9_P2

# Generate master key (returns encryption master public key in G1)
ke, P_pub_e = generate_master_key()

# Signing master public key must be computed from ke (G2 element)
P2 = ((_sm9_P2[0], _sm9_P2[1]), (_sm9_P2[2], _sm9_P2[3]))
P_pub_s = _g2_to_affine(_g2_scalar_mult(ke, P2))

# hid values: 0x01 for sign, 0x02 for KEM, 0x03 for encrypt
d_A = generate_user_sign_key(ke, b'alice', hid=0x01)
d_B = generate_user_enc_key(ke, b'bob', hid=0x03)

# Sign / Verify
sig = Sign(b'hello', d_A, P_pub_s, hid=0x01)
Verify(b'hello', sig, b'alice', P_pub_s, hid=0x01)

# Encrypt / Decrypt
ct = Encrypt(b'secret', b'bob', P_pub_e, hid=0x03)
pt = Decrypt(ct, d_B, b'bob', hid=0x03)

# Key Encapsulation (KEM)
K_enc, C = KEM_Encapsulate(b'bob', P_pub_e, klen=32, hid=0x02)
K_dec = KEM_Decapsulate(C, d_B, b'bob', klen=32, hid=0x02)
```

#### API Reference

| Function | Description |
|----------|-------------|
| `generate_master_key() -> (int, tuple)` | Generate master key pair: `(private, G1 public key)` |
| `generate_user_sign_key(ks, ID, hid=0x01) -> tuple` | Derive user signing key (G1 element) |
| `generate_user_enc_key(ke, ID, hid=0x03) -> tuple` | Derive user encryption key (G2 element) |
| `Sign(M, d_A, P_pub_s, hid=0x01) -> bytes` | SM9 sign |
| `Verify(M, sig, ID_A, P_pub_s, hid=0x01) -> bool` | SM9 verify |
| `Encrypt(M, ID_B, P_pub_e, hid=0x03) -> bytes` | Identity-based encrypt |
| `Decrypt(C, d_B, ID_B, hid=0x03) -> bytes` | Identity-based decrypt |
| `KEM_Encapsulate(ID_B, P_pub_e, klen, hid=0x02) -> (K, C)` | Key encapsulation |
| `KEM_Decapsulate(C1, d_B, ID_B, klen, hid=0x02) -> K` | Key decapsulation |
| `sm9_hex(data) -> str` | Convert bytes/int to hex string |
| `sm9_unhex(s) -> int` | Convert hex string to int |
| `_g2_to_affine(p) -> tuple` | G2 Jacobian to affine coordinates |
| `_g2_scalar_mult(k, p) -> tuple` | G2 scalar multiplication |

---

## Digital Envelope (GM/T 0010-2012)

Combines SM2 (asymmetric) and SM4-CBC (symmetric) for secure data transmission.

```python
from pysmx.extra.envelope import envelope_seal, envelope_open
from pysmx.SM2 import generate_keypair

kp = generate_keypair()

# Encrypt with receiver's public key
result = envelope_seal(b'my data', kp.publicKey)
# result.encrypted_key  - SM2-encrypted SM4 key
# result.iv             - SM4 initialization vector
# result.ciphertext     - SM4-CBC ciphertext

# Decrypt with receiver's private key
plaintext = envelope_open(result.encrypted_key, result.iv,
                          result.ciphertext, kp.privateKey)
```

#### API Reference

| Function | Description |
|----------|-------------|
| `envelope_encrypt(plaintext, public_key=None, sm2_keypair=None, sm4_key=None, iv=None) -> EnvelopeResult` | Full digital envelope encryption |
| `envelope_decrypt(encrypted_key, iv, ciphertext, private_key) -> bytes` | Full digital envelope decryption |
| `envelope_seal(plaintext, public_key) -> EnvelopeResult` | Convenience: encrypt for receiver |
| `envelope_open(encrypted_key, iv, ciphertext, private_key) -> bytes` | Convenience: decrypt for receiver |

---

## Padding Utilities

Block cipher padding schemes, available from `pysmx.common`.

```python
from pysmx.common import PKCS7Padding, PKCS7UnPadding

padded = PKCS7Padding(b'hello', block_size=16)
original = PKCS7UnPadding(padded)
```

#### Available Schemes

| Scheme | Padding / Unpadding Function |
|--------|------------------------------|
| PKCS5 | `PKCS5Padding()`, `PKCS5UnPadding()` |
| PKCS7 | `PKCS7Padding(text, block_size=16)`, `PKCS7UnPadding(text, block_size=16)` |
| Zero | `ZeroPadding(text, block_size=16)`, `ZeroUnPadding(text, block_size=16)` |
| ISO10126 | `ISO10126Padding(text, block_size=16)`, `ISO10126UnPadding(text, block_size=16)` |
| NoPadding | `NoPadding(text, block_size=16)`, `NoUnPadding(text, block_size=16)` |

---

## cryptography Backend Integration

When the `cryptography` library is installed, SMx algorithms are registered as standard
`cryptography` interfaces for seamless integration with TLS/SSL, X.509, etc.

### SM2

```python
from pysmx.SM2 import (
    SM2EllipticCurve, SM2EllipticCurvePublicKey,
    SM2EllipticCurvePrivateKey,
    SM2SM3SignatureAlgorithm, SM2SHA256SignatureAlgorithm,
)

# Generate key pair
curve = SM2EllipticCurve()
private_key = SM2EllipticCurvePrivateKey.generate(curve)
public_key = private_key.public_key()

# Sign & Verify
sig = private_key.sign(b'hello', SM2SM3SignatureAlgorithm())
public_key.verify(sig, b'hello', SM2SM3SignatureAlgorithm())

# Encrypt & Decrypt
cipher = private_key.encrypt_sm2(b'hello')
plain = private_key.decrypt_sm2(cipher)
```

### SM3

`SM3HashAlgorithm`, `SM3HashBackend`, `SM3HMACBackend` auto-register on import.
Use with `cryptography.hazmat.primitives.hashes.Hash` and `HMAC` directly.

### SM4

`SM4Algorithm` is powered by the pysmx native Sm4 implementation.
Provides a `BlockCipherAlgorithm` descriptor and convenience encrypt/decrypt
functions for all modes.

```python
from pysmx.SM4 import (
    SM4Algorithm, SM4ModePCBC,
    sm4_encrypt_ecb, sm4_decrypt_ecb,
    sm4_encrypt_cbc, sm4_decrypt_cbc,
)

key = b'0123456789abcdef'
iv = b'abcdef0123456789'

# ECB mode
ciphertext = sm4_encrypt_ecb(key, b'Hello World!')
plaintext = sm4_decrypt_ecb(key, ciphertext)

# CBC mode
ciphertext = sm4_encrypt_cbc(key, iv, b'Hello World!')
plaintext = sm4_decrypt_cbc(key, iv, ciphertext)
```

**Streaming API (`SM4StreamCipher`)**

```python
from pysmx.block_cyphers import ENCRYPT, DECRYPT
from pysmx.SM4 import SM4StreamCipher

# Encrypt
cipher = SM4StreamCipher(key, ENCRYPT, iv, mode='cbc')
ct1 = cipher.update(data_chunk1)
ct2 = cipher.update(data_chunk2)
ct_final = cipher.finalize()

# Decrypt
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

#### API Reference

| Module | Class / Function | Description |
|--------|------------------|-------------|
| SM2 | `SM2EllipticCurve` | SM2 elliptic curve descriptor |
| SM2 | `SM2EllipticCurvePublicKey` | SM2 public key (cryptography interface) |
| SM2 | `SM2EllipticCurvePrivateKey` | SM2 private key with `sign()` / `verify()` / `encrypt_sm2()` / `decrypt_sm2()` |
| SM2 | `SM2SM3SignatureAlgorithm` | SM2 with SM3 signature algorithm |
| SM2 | `SM2SHA256SignatureAlgorithm` | SM2 with SHA256 signature algorithm |
| SM3 | `SM3HashAlgorithm` | SM3 hash algorithm descriptor |
| SM3 | `SM3HashContext` | SM3 hash context |
| SM3 | `SM3HMACContext` | SM3 HMAC context |
| SM3 | `SM3HashBackend` | SM3 hash backend |
| SM3 | `SM3HMACBackend` | SM3 HMAC backend |
| SM4 | `SM4Algorithm` | SM4 block cipher descriptor (pysmx native Sm4 backend) |
| SM4 | `SM4ModePCBC` | SM4 PCBC mode |
| SM4 | `sm4_encrypt_ecb(key, data)` | SM4-ECB encryption |
| SM4 | `sm4_decrypt_ecb(key, data)` | SM4-ECB decryption |
| SM4 | `sm4_encrypt_cbc(key, iv, data)` | SM4-CBC encryption |
| SM4 | `sm4_decrypt_cbc(key, iv, data)` | SM4-CBC decryption |
| SM4 | `sm4_encrypt_cfb(key, iv, data)` | SM4-CFB encryption |
| SM4 | `sm4_decrypt_cfb(key, iv, data)` | SM4-CFB decryption |
| SM4 | `sm4_encrypt_ofb(key, iv, data)` | SM4-OFB encryption |
| SM4 | `sm4_decrypt_ofb(key, iv, data)` | SM4-OFB decryption |
| SM4 | `sm4_encrypt_pcbc(key, iv, data)` | SM4-PCBC encryption |
| SM4 | `sm4_decrypt_pcbc(key, iv, data)` | SM4-PCBC decryption |
| SM4 | `SM4StreamCipher(key, direction, iv, mode, padding_method)` | Streaming cipher: `update(data)` for incremental processing, `finalize()` to finish |
| SM9 | `SM9EllipticCurve` | SM9 BN curve descriptor |
| SM9 | `SM9EllipticCurvePublicKey` | SM9 public key (cryptography interface) |
| SM9 | `SM9EllipticCurvePrivateKey` | SM9 private key (cryptography interface) |
| SM9 | `SM9SM3SignatureAlgorithm` | SM9 with SM3 signature algorithm |
| ZUC | `ZUCAlgorithm` | ZUC stream cipher algorithm descriptor |
| ZUC | `zuc_encrypt(key, iv, data)` | ZUC encryption |
| ZUC | `zuc_decrypt(key, iv, ciphertext)` | ZUC decryption |

---

## License

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fsnowland-gm%2Fsnowland-smx-python.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fsnowland-gm%2Fsnowland-smx-python?ref=badge_large)
