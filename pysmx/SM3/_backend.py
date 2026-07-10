#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @contact: astar@snowland.ltd
# @file: _backend .py
# @time: 2021/2/9 0:44
# @Software: PyCharm

from cryptography import utils
from cryptography.hazmat.primitives.hashes import HashAlgorithm, HashContext
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.exceptions import InvalidSignature
import hmac
from pysmx.crypto import hashlib
from pysmx.SM3._SM3 import SM3Type

# MACContext was removed in cryptography >= 43.
try:
    from cryptography.hazmat.primitives.mac import MACContext
except ImportError:
    MACContext = None

# Backend interfaces were removed in cryptography >= 43.
_HAS_BACKEND_INTERFACES = False
try:
    from cryptography.hazmat.backends.interfaces import HashBackend, HMACBackend
    _HAS_BACKEND_INTERFACES = True
except ImportError:
    try:
        from cryptography.hazmat.backends import HashBackend, HMACBackend
        _HAS_BACKEND_INTERFACES = True
    except ImportError:
        pass


class SM3HMACContext(object):
    def __init__(self, backend, key, algorithm, ctx=None):
        self._algorithm = algorithm
        self._backend = backend
        if ctx is None:
            self._lib = hmac.HMAC(key, digestmod=algorithm)
        else:
            self._lib = ctx._lib
        self._key = key

    @property
    def algorithm(self):
        return self._algorithm

    def copy(self):
        return SM3HMACContext(
            self._backend, self._key, self.algorithm, ctx=self
        )

    def update(self, data):
        res = self._lib.update(data)
        return res

    def finalize(self):
        res = self._lib.digest()
        return res

    def verify(self, signature):
        digest = self.finalize()
        if not bytes_eq(digest, signature):
            raise InvalidSignature("Signature did not match digest.")


class SM3HashContext(object):
    def __init__(self, backend, algorithm, ctx: "SM3Type" = None):
        self._algorithm = algorithm
        self._backend = backend
        if ctx is None:
            self._lib = SM3Type()
        else:
            self._lib = ctx

    @property
    def algorithm(self):
        return self._algorithm

    def copy(self):
        return SM3HashContext(self._backend, self.algorithm, ctx=self._lib)

    def update(self, data):
        return self._lib.update(data)

    def finalize(self):
        return self._lib.digest()


class SM3HMACBackend(object):
    name = "pysmx-hmac"

    def create_hmac_ctx(self, key, algorithm):
        """
        Create a HashContext for calculating a message digest.
        """
        if isinstance(algorithm, HashAlgorithm):
            algorithm = algorithm.name
        elif isinstance(algorithm, str):
            pass
        else:
            raise ValueError("error algorithm in pysm3")
        degist = getattr(hashlib, algorithm)
        return SM3HMACContext(self, key, degist)

    def hmac_supported(self, algorithm):
        if isinstance(algorithm, callable):
            algorithm = algorithm
        elif isinstance(algorithm, HashAlgorithm):
            algorithm = getattr(hashlib, algorithm.name)
        elif isinstance(algorithm, str):
            algorithm = getattr(hashlib, algorithm)
        else:
            raise ValueError("error algorithm in pysm3")
        return hasattr(hashlib, algorithm)


if _HAS_BACKEND_INTERFACES:
    HMACBackend.register(SM3HMACBackend)


class SM3HashBackend(object):
    name = "pysmx-sm3"

    def create_hash_ctx(self, algorithm):
        """
        Create a HashContext for calculating a message digest.
        """
        if isinstance(algorithm, HashAlgorithm):
            algorithm = algorithm.name
        elif isinstance(algorithm, str):
            pass
        else:
            raise ValueError("error algorithm in pysm3")
        return SM3HashContext(self, algorithm)

    def hash_supported(self, algorithm):
        if isinstance(algorithm, HashAlgorithm):
            algorithm = algorithm.name
        elif isinstance(algorithm, str):
            pass
        else:
            raise ValueError("error algorithm in pysm3")
        return hasattr(hashlib, algorithm)


if _HAS_BACKEND_INTERFACES:
    HashBackend.register(SM3HashBackend)

if MACContext is not None:
    MACContext.register(SM3HMACContext)
HashContext.register(SM3HMACContext)
HashContext.register(SM3HashContext)
