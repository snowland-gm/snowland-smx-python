#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @contact: astar@snowland.ltd
# @file: _backend .py
# @time: 2021/2/9 1:41
# @Software: PyCharm

_HAS_BACKEND_INTERFACES = False
try:
    from cryptography.hazmat.backends.interfaces import (
        HashBackend, CipherBackend, HMACBackend,
    )
    _HAS_BACKEND_INTERFACES = True
except ImportError:
    try:
        from cryptography.hazmat.backends import (
            HashBackend, CipherBackend, HMACBackend,
        )
        _HAS_BACKEND_INTERFACES = True
    except ImportError:
        pass

from pysmx.SM3._backend import SM3HashBackend


class PysmxBackend():
    name = "pysmx"


if _HAS_BACKEND_INTERFACES:
    HashBackend.register(PysmxBackend)
    CipherBackend.register(PysmxBackend)
    HMACBackend.register(PysmxBackend)
