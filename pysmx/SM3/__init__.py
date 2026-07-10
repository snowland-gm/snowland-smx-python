#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @contact: astar@snowland.ltd
# @file: __init__.py.py
# @time: 2018/11/18 22:31
# @Software: PyCharm


from ._SM3 import (
    SM3, SM3Type, Hash_sm3, hash_msg, digest, hexdigest, KDF
)

try:
    from ._cryptography import (
        SM3HashAlgorithm,
        SM3HashContext,
        SM3HMACContext,
        SM3HashBackend,
        SM3HMACBackend,
    )
except ImportError:
    pass
