#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @contact: astar@snowland.ltd
# @file: _cryptography.py
# @time: 2021/2/8 21:49
# @Software: PyCharm
#
# SM3 cryptography framework integration.
# Consolidates SM3HashAlgorithm (algorithm descriptor),
# SM3HashBackend (hash backend), and SM3HMACBackend (HMAC backend).
#

from pysmx.SM3._algorithm import SM3HashAlgorithm
from pysmx.SM3._backend import (
    SM3HashContext,
    SM3HMACContext,
    SM3HashBackend,
    SM3HMACBackend,
)

# All registrations already happen in the source modules:
#   _algorithm.py: HashAlgorithm.register(SM3HashAlgorithm)
#   _backend.py:   HMACBackend.register(SM3HMACBackend)
#                  HashBackend.register(SM3HashBackend)
#                  MACContext.register(SM3HMACContext)
#                  HashContext.register(SM3HMACContext)
#                  HashContext.register(SM3HashContext)
