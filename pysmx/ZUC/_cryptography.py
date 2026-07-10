#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @contact: astar@snowland.ltd
# @file: _cryptography.py
# @time: 2021/2/8 21:49
# @Software: PyCharm
#
# ZUC cryptography framework integration.
#
# ZUC is a stream cipher (GB/T 33133-2016).  This module provides
# an algorithm descriptor registered with the cryptography CipherAlgorithm
# interface and high-level encrypt/decrypt helpers.
#

from cryptography.hazmat.primitives.ciphers import CipherAlgorithm


def _check_bytes(name, value):
    if not isinstance(value, bytes):
        raise TypeError('{} must be bytes'.format(name))


# ============================================================
# ZUC Algorithm descriptor
# ============================================================

class ZUCAlgorithm(object):
    """ZUC stream cipher algorithm descriptor (key_size: 128 bits)."""
    name = "ZUC"
    key_sizes = (16,)  # 128 bits
    key_size = 16

    def __init__(self, key):
        _check_bytes("key", key)
        if len(key) not in self.key_sizes:
            raise ValueError(
                "ZUC key must be {} bytes (got {})".format(
                    self.key_sizes, len(key)
                )
            )
        self._key = key

    @property
    def key(self):
        return self._key


try:
    CipherAlgorithm.register(ZUCAlgorithm)
except (AttributeError, TypeError):
    pass


# ============================================================
# ZUC encrypt / decrypt
# ============================================================

def zuc_encrypt(key, iv, data):
    """Encrypt data with ZUC stream cipher.

    :param key: 16-byte key
    :param iv: 16-byte initialization vector
    :param data: plaintext bytes
    :return: ciphertext bytes
    """
    _check_bytes("key", key)
    _check_bytes("iv", iv)
    _check_bytes("data", data)
    from pysmx.ZUC._ZUC import ZUC
    zuc = ZUC(
        [key[i] for i in range(16)],
        [iv[i] for i in range(16)],
    )
    zuc.zuc_generate_keystream()
    result = bytearray()
    for b in data:
        ks_word = next(zuc)
        result.append((ks_word ^ b) & 0xFF)
    return bytes(result)


def zuc_decrypt(key, iv, ciphertext):
    """Decrypt data with ZUC stream cipher (symmetric to encrypt).

    :param key: 16-byte key
    :param iv: 16-byte initialization vector
    :param ciphertext: ciphertext bytes
    :return: plaintext bytes
    """
    return zuc_encrypt(key, iv, ciphertext)
