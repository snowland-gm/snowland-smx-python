#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @contact: astar@snowland.ltd
# @file: _backend .py
# @time: 2021/2/9 1:41
# @Software: PyCharm

_HAS_BACKEND_INTERFACES = False
try:
    from cryptography.hazmat.backends.interfaces import HashBackend
    _HAS_BACKEND_INTERFACES = True
except ImportError:
    try:
        from cryptography.hazmat.backends import HashBackend
        _HAS_BACKEND_INTERFACES = True
    except ImportError:
        pass

from pysmx.SM3._backend import SM3HashBackend


class PysmxBackend():
    name = "pysmx"


# Only register backends that are actually implemented. PysmxBackend provides
# the SM3 hash backend via SM3HashBackend; it does NOT implement the generic
# Cipher/HMAC backend interfaces, so registering those would mislead callers
# into thinking pysmx offers a general symmetric-encryption / HMAC backend.
if _HAS_BACKEND_INTERFACES:
    HashBackend.register(PysmxBackend)
