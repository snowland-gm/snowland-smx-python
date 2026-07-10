#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @contact: astar@snowland.ltd
# @file: _algorithm.py
# @time: 2021/2/8 19:45
# @Software: PyCharm
#
# SM4 cryptography framework integration using pysmx.SM4 native backend.
# Provides SM4Algorithm (BlockCipherAlgorithm descriptor), SM4ModePCBC,
# and convenience encrypt/decrypt functions for all modes.
#

from cryptography import utils
from cryptography.hazmat.primitives.ciphers import BlockCipherAlgorithm
from cryptography.hazmat.primitives.ciphers.modes import Mode

from pysmx.SM4._SM4 import Sm4
from pysmx.block_cyphers import ENCRYPT, DECRYPT


# ---------------------------------------------------------------------------
#  PCBC mode
# ---------------------------------------------------------------------------

class _PCBC(Mode):
    """PCBC (Propagating CBC) mode for SM4."""

    name = "PCBC"

    def __init__(self, initialization_vector):
        utils._check_byteslike("initialization_vector", initialization_vector)
        if len(initialization_vector) != 16:
            raise ValueError("PCBC IV must be 16 bytes")
        self._initialization_vector = initialization_vector

    @property
    def initialization_vector(self):
        return self._initialization_vector


SM4ModePCBC = _PCBC


# ---------------------------------------------------------------------------
#  Algorithm descriptor
# ---------------------------------------------------------------------------

class SM4Algorithm(BlockCipherAlgorithm):
    """SM4 block cipher algorithm descriptor.

    Stores the key and exposes algorithm metadata (key_size, block_size).
    Not compatible with cryptography Cipher() on cryptography >= 43;
    use the convenience functions instead.
    """

    name = "SM4"
    key_sizes = frozenset([128])
    block_size = 128  # bits (16 bytes)

    def __init__(self, key):
        utils._check_byteslike("key", key)
        if len(key) != 16:
            raise ValueError("SM4 key must be 16 bytes")
        self._key = bytes(key)

    @property
    def key_size(self):
        return 128

    @property
    def key(self):
        return self._key


# ---------------------------------------------------------------------------
#  Convenience encrypt/decrypt functions (primary API)
# ---------------------------------------------------------------------------

def _sm4_crypt_ecb(key, data, for_encryption):
    sm4 = Sm4()
    sm4.set_key(key, ENCRYPT if for_encryption else DECRYPT)
    return sm4.crypt_ecb(data)


def _sm4_crypt_cbc(key, iv, data, for_encryption):
    sm4 = Sm4()
    sm4.set_key(key, ENCRYPT if for_encryption else DECRYPT)
    return sm4.crypt_cbc(iv, data)


def _sm4_crypt_cfb(key, iv, data, for_encryption):
    sm4 = Sm4()
    sm4.set_key(key, ENCRYPT if for_encryption else DECRYPT)
    return sm4.crypt_cfb(iv, data)


def _sm4_crypt_ofb(key, iv, data, for_encryption):
    sm4 = Sm4()
    sm4.set_key(key, ENCRYPT if for_encryption else DECRYPT)
    return sm4.crypt_ofb(iv, data)


def _sm4_crypt_pcbc(key, iv, data, for_encryption):
    sm4 = Sm4()
    sm4.set_key(key, ENCRYPT if for_encryption else DECRYPT)
    return sm4.crypt_pcbc(iv, data)


def sm4_encrypt_ecb(key, data):
    """Encrypt data with SM4-ECB using pysmx.SM4."""
    return _sm4_crypt_ecb(key, data, True)


def sm4_decrypt_ecb(key, data):
    """Decrypt data with SM4-ECB using pysmx.SM4."""
    return _sm4_crypt_ecb(key, data, False)


def sm4_encrypt_cbc(key, iv, data):
    """Encrypt data with SM4-CBC using pysmx.SM4."""
    return _sm4_crypt_cbc(key, iv, data, True)


def sm4_decrypt_cbc(key, iv, data):
    """Decrypt data with SM4-CBC using pysmx.SM4."""
    return _sm4_crypt_cbc(key, iv, data, False)


def sm4_encrypt_cfb(key, iv, data):
    """Encrypt data with SM4-CFB using pysmx.SM4."""
    return _sm4_crypt_cfb(key, iv, data, True)


def sm4_decrypt_cfb(key, iv, data):
    """Decrypt data with SM4-CFB using pysmx.SM4."""
    return _sm4_crypt_cfb(key, iv, data, False)


def sm4_encrypt_ofb(key, iv, data):
    """Encrypt data with SM4-OFB using pysmx.SM4."""
    return _sm4_crypt_ofb(key, iv, data, True)


def sm4_decrypt_ofb(key, iv, data):
    """Decrypt data with SM4-OFB using pysmx.SM4."""
    return _sm4_crypt_ofb(key, iv, data, False)


def sm4_encrypt_pcbc(key, iv, data):
    """Encrypt data with SM4-PCBC using pysmx.SM4."""
    return _sm4_crypt_pcbc(key, iv, data, True)


def sm4_decrypt_pcbc(key, iv, data):
    """Decrypt data with SM4-PCBC using pysmx.SM4."""
    return _sm4_crypt_pcbc(key, iv, data, False)


# ---------------------------------------------------------------------------
#  Streaming cipher with update()/finalize() interface
# ---------------------------------------------------------------------------

class SM4StreamCipher:
    """Streaming SM4 cipher with incremental update()/finalize() interface.

    Compatible with cryptography conventions for stream processing.
    Internally delegates to SM4Stream.

    Basic usage::

        cipher = SM4StreamCipher(key, ENCRYPT, iv, mode='cbc')
        ct1 = cipher.update(chunk1)
        ct2 = cipher.update(chunk2)
        ct3 = cipher.finalize()

    Args:
        key (bytes): 16-byte SM4 key.
        direction (int): ENCRYPT or DECRYPT from pysmx.block_cyphers.
        iv (bytes, optional): 16-byte initialization vector.
            Required for CBC/CFB/OFB/PCBC modes, ignored for ECB.
        mode (str): Cipher mode: 'ecb', 'cbc', 'cfb', 'ofb', 'pcbc'.
        padding_method (str): Padding scheme: 'pkcs5' or 'pkcs7'.
    """

    def __init__(self, key, direction, iv=None, mode='cbc',
                 padding_method='pkcs5'):
        from pysmx.SM4._SM4_stream import SM4Stream

        self._stream = SM4Stream(
            key=key,
            mode=direction,
            iv=iv,
            method=mode,
            padding_method=padding_method,
        )

    def update(self, data):
        """Process data incrementally.

        Args:
            data (bytes): Input data chunk.

        Returns:
            bytes: Processed output. May be empty if not enough data
                   to form a complete block yet.
        """
        return self._stream.update(data)

    def finalize(self):
        """Finish processing and return remaining output.

        For encryption: pads buffered data, processes last block(s),
        returns final ciphertext.

        For decryption: processes remaining block(s), removes padding,
        returns final plaintext.

        Returns:
            bytes: Remaining output after finalization.
        """
        return self._stream.finalize()
