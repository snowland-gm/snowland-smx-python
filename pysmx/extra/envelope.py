#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @file: envelope.py
# @time: 2020/7/18 19:54
#
# Digital Envelope (GM/T 0010-2012)
#
# A digital envelope combines asymmetric encryption (SM2) and symmetric
# encryption (SM4) for secure data transmission.  The symmetric key is
# encrypted with the receiver's public key; the payload is encrypted
# with the symmetric key.
#
# Flow:
#   encrypt:  plaintext  --SM4-CBC(key, iv)--> ciphertext
#             SM4 key    --SM2(pubkey)--------> encrypted_key
#   decrypt:  encrypted_key --SM2(privkey)--> SM4 key
#             ciphertext     --SM4-CBC(key, iv)--> plaintext
#

from collections import namedtuple

from pysmx.SM2 import Encrypt as sm2_encrypt
from pysmx.SM2 import Decrypt as sm2_decrypt
from pysmx.SM2 import generate_keypair as sm2_generate_keypair
from pysmx.SM2 import KeyPair
from pysmx.SM4 import sm4_crypt_cbc, ENCRYPT, DECRYPT
from pysmx.common.random import random_bytes

# ---------------------------------------------------------------------------
# SM4 key / IV constants
# ---------------------------------------------------------------------------
SM4_KEY_LEN = 16   # 128-bit key
SM4_IV_LEN  = 16   # 128-bit IV (CBC mode)

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

EnvelopeResult = namedtuple(
    'EnvelopeResult',
    ['encrypted_key', 'iv', 'ciphertext', 'sm2_keypair'],
)


# ---------------------------------------------------------------------------
# Core API
# ---------------------------------------------------------------------------

def envelope_encrypt(
    plaintext,
    public_key=None,
    sm2_keypair=None,
    sm4_key=None,
    iv=None,
):
    """Encrypt data with a digital envelope (SM2 + SM4-CBC).

    Parameters
    ----------
    plaintext : bytes
        Data to encrypt.
    public_key :
        Receiver's SM2 public key.  If None, *sm2_keypair* must be given
        and its public key is used.
    sm2_keypair : KeyPair, optional
        SM2 key pair.  If None AND *public_key* is None, a new key pair
        is generated.
    sm4_key : bytes, optional
        16-byte SM4 symmetric key.  If None, generated from os.urandom.
    iv : bytes, optional
        16-byte initialization vector.  If None, generated from os.urandom.

    Returns
    -------
    EnvelopeResult
        Named tuple with fields:
        - encrypted_key: SM2-encrypted SM4 key (bytes)
        - iv: initialization vector (bytes)
        - ciphertext: SM4-CBC ciphertext (bytes)
        - sm2_keypair: the KeyPair used (may be newly generated)
    """
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise TypeError('plaintext must be bytes-like')

    # Resolve SM2 key pair
    if sm2_keypair is None:
        if public_key is not None:
            sm2_keypair = KeyPair(public_key, None)
        else:
            sm2_keypair = sm2_generate_keypair()
    if public_key is None:
        public_key = sm2_keypair.publicKey

    # Generate SM4 key and IV if not provided
    if sm4_key is None:
        sm4_key = random_bytes(SM4_KEY_LEN)
    if len(sm4_key) != SM4_KEY_LEN:
        raise ValueError(f'SM4 key must be {SM4_KEY_LEN} bytes')
    if iv is None:
        iv = random_bytes(SM4_IV_LEN)
    if len(iv) != SM4_IV_LEN:
        raise ValueError(f'IV must be {SM4_IV_LEN} bytes')

    # 1. Encrypt plaintext with SM4-CBC
    ciphertext = sm4_crypt_cbc(ENCRYPT, sm4_key, iv, bytes(plaintext))

    # 2. Encrypt SM4 key with SM2 (receiver's public key)
    encrypted_key = sm2_encrypt(sm4_key, public_key, len_para=64)

    return EnvelopeResult(encrypted_key, iv, ciphertext, sm2_keypair)


def envelope_decrypt(
    encrypted_key,
    iv,
    ciphertext,
    private_key,
):
    """Decrypt data from a digital envelope (SM2 + SM4-CBC).

    Parameters
    ----------
    encrypted_key : bytes
        SM2-encrypted SM4 key.
    iv : bytes
        16-byte initialization vector.
    ciphertext : bytes
        SM4-CBC ciphertext.
    private_key :
        Receiver's SM2 private key.

    Returns
    -------
    bytes
        Decrypted plaintext.
    """
    if isinstance(private_key, KeyPair):
        private_key = private_key.privateKey

    # 1. Decrypt SM4 key with SM2
    sm4_key = sm2_decrypt(encrypted_key, private_key, len_para=64)

    # 2. Decrypt ciphertext with SM4-CBC
    plaintext = sm4_crypt_cbc(DECRYPT, sm4_key, iv, bytes(ciphertext))

    return plaintext


# ---------------------------------------------------------------------------
# Convenience: encrypt with receiver's public key only
# ---------------------------------------------------------------------------

def envelope_seal(plaintext, public_key):
    """Encrypt data for a specific receiver (convenience wrapper).

    Equivalent to ``envelope_encrypt(plaintext, public_key=public_key)``.
    """
    return envelope_encrypt(plaintext, public_key=public_key)


def envelope_open(encrypted_key, iv, ciphertext, private_key):
    """Decrypt data from a digital envelope (convenience wrapper).

    Equivalent to ``envelope_decrypt(encrypted_key, iv, ciphertext, private_key)``.
    """
    return envelope_decrypt(encrypted_key, iv, ciphertext, private_key)
