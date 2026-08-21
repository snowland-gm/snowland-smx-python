#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @contact: astar@snowland.ltd
# @file: __init__.py
# @time: 2018/9/21 22:04
# @Software: PyCharm

from pysmx import SM2
from pysmx import SM3
from pysmx import SM4
from pysmx import SM9
from pysmx import ZUC
from pysmx import crypto
from pysmx import ecc
from pysmx import common
from pysmx import block_cyphers
from pysmx import extra

VERSION = (1, 1, 0)
__version__ = "1.1.0"


# ---------------------------------------------------------------------------
# Unified, Pythonic SM4 high-level API.
#
# The historical SM4 entry points are inconsistent: there are bare module
# functions (``sm4_crypt_ecb(mode, key, data)`` with global ``ENCRYPT``/
# ``DECRYPT`` constants), the legacy ``CryptSM4`` class and the ``SM4`` class.
# This facade converges them behind a single, intuitive function so callers do
# not need to know about internal mode constants.
# ---------------------------------------------------------------------------

def sm4_encrypt(mode, key, data, iv=None):
    """Encrypt ``data`` with SM4 in ``mode`` ('ecb'/'cbc'/'cfb'/'ofb'/'pcbc').

    ``iv`` is required for any mode other than 'ecb'.
    """
    return _sm4_crypt(mode, key, data, iv, encrypt=True)


def sm4_decrypt(mode, key, data, iv=None):
    """Decrypt ``data`` with SM4 in ``mode`` ('ecb'/'cbc'/'cfb'/'ofb'/'pcbc').

    ``iv`` is required for any mode other than 'ecb'.
    """
    return _sm4_crypt(mode, key, data, iv, encrypt=False)


def _sm4_crypt(mode, key, data, iv, encrypt):
    from pysmx import block_cyphers
    from pysmx.SM4 import (
        sm4_crypt_ecb, sm4_crypt_cbc, sm4_crypt_cfb,
        sm4_crypt_ofb, sm4_crypt_pcbc,
    )

    op = block_cyphers.ENCRYPT if encrypt else block_cyphers.DECRYPT
    mode = mode.lower()
    if mode == 'ecb':
        return sm4_crypt_ecb(op, key, data)
    if mode == 'cbc':
        return sm4_crypt_cbc(op, key, iv, data)
    if mode == 'cfb':
        return sm4_crypt_cfb(op, key, iv, data)
    if mode == 'ofb':
        return sm4_crypt_ofb(op, key, iv, data)
    if mode == 'pcbc':
        return sm4_crypt_pcbc(op, key, iv, data)
    raise ValueError("unsupported SM4 mode: %r" % (mode,))