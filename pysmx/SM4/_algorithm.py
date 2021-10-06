#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: 深圳星河软通科技有限公司 A.Star
# @contact: astar@snowland.ltd
# @site: www.astar.ltd
# @file: _algorithm.py .py
# @time: 2021/2/8 21:49
# @Software: PyCharm

from cryptography import utils

from cryptography.hazmat.primitives.ciphers import BlockCipherAlgorithm, CipherAlgorithm


def _verify_key_size(algorithm, key):
    # Verify that the key is instance of bytes
    utils._check_byteslike("key", key)

    # Verify that the key size matches the expected key size
    if len(key) * 8 not in algorithm.key_sizes:
        raise ValueError(
            "Invalid key size ({}) for {}.".format(
                len(key) * 8, algorithm.name
            )
        )
    return key


@utils.register_interface(BlockCipherAlgorithm)
@utils.register_interface(CipherAlgorithm)
class SM4Algorithm(object):
    name = "sm4"
    block_size = 64
    key_sizes = frozenset([64])

    def __init__(self, key):
        self.key = _verify_key_size(self, key)

    @property
    def key_size(self):
        return len(self.key) * 8
