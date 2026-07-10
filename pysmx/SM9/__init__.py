#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @contact: astar@snowland.ltd
# @file: __init__.py
# @time: 2018/11/18 22:31
# @Software: PyCharm

from ._SM9 import (
    Sign, Verify, Encrypt, Decrypt,
    KEM_Encapsulate, KEM_Decapsulate,
    generate_master_key,
    generate_user_sign_key,
    generate_user_enc_key,
    sm9_hex, sm9_unhex,
)

try:
    from ._cryptography import (
        SM9EllipticCurve,
        SM9SM3SignatureAlgorithm,
        SM9EllipticCurvePublicKey,
        SM9EllipticCurvePrivateKey,
    )
except ImportError:
    pass
