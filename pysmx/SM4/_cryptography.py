#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @contact: astar@snowland.ltd
# @file: _cryptography.py
# @time: 2021/2/8 21:49
# @Software: PyCharm
#
# SM4 cryptography framework integration.
# Re-exports from pysmx.ciphers.algorithm._algorithm (pysmx.SM4 native backend).
#
# Note: The SM4Algorithm descriptor implements BlockCipherAlgorithm but is not
# compatible with Cipher() on cryptography >= 43 (which removed pluggable
# CipherBackend). Use the convenience functions (sm4_encrypt_* / sm4_decrypt_*)
# as the primary API instead.
#

from pysmx.ciphers.algorithm._algorithm import (
    SM4Algorithm,
    SM4ModePCBC,
    SM4StreamCipher,
    sm4_encrypt_ecb,
    sm4_decrypt_ecb,
    sm4_encrypt_cbc,
    sm4_decrypt_cbc,
    sm4_encrypt_cfb,
    sm4_decrypt_cfb,
    sm4_encrypt_ofb,
    sm4_decrypt_ofb,
    sm4_encrypt_pcbc,
    sm4_decrypt_pcbc,
)
