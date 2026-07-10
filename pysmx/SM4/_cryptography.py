#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @contact: astar@snowland.ltd
# @file: _cryptography.py
# @time: 2021/2/8 21:49
# @Software: PyCharm
#
# SM4 cryptography framework integration.
#
# cryptography (>= 3.0) has built-in SM4 support.  For standard modes
# (ECB, CBC, CFB, OFB) use Cipher(SM4(key), mode, backend=default_backend()).
# For PCBC mode the pysmx Sm4 implementation is used.
#

from cryptography import utils
from cryptography.hazmat.primitives.ciphers.algorithms import SM4 as SM4Algorithm
from cryptography.hazmat.primitives.ciphers import (
    BlockCipherAlgorithm, CipherAlgorithm,
)
from cryptography.hazmat.primitives.ciphers.modes import Mode, ECB, CBC

# CFB/OFB moved to decrepit in cryptography 43+
try:
    from cryptography.hazmat.decrepit.ciphers.modes import CFB, OFB
except ImportError:
    from cryptography.hazmat.primitives.ciphers.modes import CFB, OFB


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
