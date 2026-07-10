#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @contact: astar@snowland.ltd
# @file: _cryptography.py
# @time: 2020/10/25 2:52
# @Software: PyCharm


from astartool.string import force_bytes
from pysmx.crypto import hashlib

import six

try:
    import simplejson as json
except ImportError:
    import json

try:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurve,
        EllipticCurveSignatureAlgorithm,
        EllipticCurvePrivateKey,
        EllipticCurvePublicKey,
        EllipticCurvePrivateNumbers,
        EllipticCurvePublicNumbers,
    )
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature

    from ._SM2 import (
        Sign, Verify, generate_keypair,
        get_random_str, get_hash as _sm2_get_hash,
    )

    has_crypto = True
except ImportError:
    has_crypto = False


def _check_bytes(name, value):
    if not isinstance(value, bytes):
        raise TypeError('{} must be bytes'.format(name))


# ============================================================
# SM2 Elliptic Curve
# ============================================================

class SM2EllipticCurve(object):
    name = 'sm2sm364'
    key_size = 64


# ============================================================
# SM2 Signature Algorithms
# ============================================================

class SM2SM3SignatureAlgorithm(object):
    name = 'sm2sm3'

    def __init__(self, algorithm=None):
        if algorithm is None:
            self._algorithm = 'sm3'
        else:
            self._algorithm = algorithm

    @property
    def algorithm(self):
        return self._algorithm


class SM2SHA256SignatureAlgorithm(object):
    name = 'sm2sha256'
    algorithm = 'sha256'


def _resolve_hash_name(signature_algorithm):
    alg = getattr(signature_algorithm, 'algorithm', 'sm3')
    if hasattr(alg, 'name'):
        return alg.name
    return str(alg)


# ============================================================
# SM2 Public Key
# ============================================================

class SM2EllipticCurvePublicKey(object):
    def __init__(self, curve, public_key_bytes):
        if not isinstance(curve, SM2EllipticCurve):
            raise TypeError("curve must be an SM2EllipticCurve instance")
        _check_bytes("public_key_bytes", public_key_bytes)
        self._curve = curve
        self._public_key = public_key_bytes

    @classmethod
    def from_encoded_point(cls, curve, data):
        _check_bytes("data", data)
        if not isinstance(curve, SM2EllipticCurve):
            raise TypeError("curve must be an SM2EllipticCurve instance")
        if len(data) == 0:
            raise ValueError("data must not be an empty byte string")
        if six.indexbytes(data, 0) not in (0x02, 0x03, 0x04):
            raise ValueError("Unsupported elliptic curve point type")
        from cryptography.hazmat.backends.openssl.backend import backend
        return backend.load_elliptic_curve_public_bytes(curve, data)

    @property
    def curve(self):
        return self._curve

    @property
    def key_size(self):
        return self._curve.key_size * 8

    def public_bytes(self, encoding, format):
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat
        )
        if format is PublicFormat.CompressedPoint:
            y_byte = six.indexbytes(self._public_key, self._curve.key_size)
            prefix = b'\x02' if (y_byte & 1) == 0 else b'\x03'
            return prefix + self._public_key[:self._curve.key_size]
        elif format is PublicFormat.UncompressedPoint:
            return b'\x04' + self._public_key
        else:
            raise ValueError("Unsupported public key format")

    def public_numbers(self):
        len_para = self._curve.key_size
        key_hex = self._public_key.hex()
        x = int(key_hex[:len_para], 16)
        y = int(key_hex[len_para:2 * len_para], 16)
        return EllipticCurvePublicNumbers(x, y, self._curve)

    def verify(self, signature, data, signature_algorithm):
        _check_bytes("data", data)
        _check_bytes("signature", signature)
        hash_name = _resolve_hash_name(signature_algorithm)
        data_hash = _sm2_get_hash(hash_name, data, Hexstr=0)
        result = Verify(
            signature, data_hash, self._public_key,
            len_para=self._curve.key_size, Hexstr=1
        )
        if not result:
            raise InvalidSignature("SM2 signature verification failed.")

    def verifier(self, signature, signature_algorithm):
        raise NotImplementedError(
            "SM2 does not support incremental verification contexts."
        )


# ============================================================
# SM2 Private Key
# ============================================================

class SM2EllipticCurvePrivateKey(object):
    def __init__(self, curve, private_key_bytes, public_key_bytes):
        if not isinstance(curve, SM2EllipticCurve):
            raise TypeError("curve must be an SM2EllipticCurve instance")
        _check_bytes("private_key_bytes", private_key_bytes)
        _check_bytes("public_key_bytes", public_key_bytes)
        self._curve = curve
        self._private_key = private_key_bytes
        self._public_key = SM2EllipticCurvePublicKey(curve, public_key_bytes)

    @classmethod
    def generate(cls, curve=None):
        if curve is None:
            curve = SM2EllipticCurve()
        if not isinstance(curve, SM2EllipticCurve):
            raise TypeError("curve must be an SM2EllipticCurve instance")
        kp = generate_keypair(curve.key_size)
        return cls(curve, kp.privateKey, kp.publicKey)

    @property
    def curve(self):
        return self._curve

    @property
    def key_size(self):
        return self._curve.key_size * 8

    def public_key(self):
        return self._public_key

    def sign(self, data, signature_algorithm):
        _check_bytes("data", data)
        hash_name = _resolve_hash_name(signature_algorithm)
        data_hash = _sm2_get_hash(hash_name, data, Hexstr=0)
        K = get_random_str(self._curve.key_size)
        sig = Sign(
            data_hash, self._private_key, K,
            len_para=self._curve.key_size, Hexstr=1
        )
        if sig is None:
            raise ValueError("SM2 signing failed (retry with a different K)")
        return sig

    def signer(self, signature_algorithm):
        raise NotImplementedError(
            "SM2 does not support incremental signing contexts."
        )

    def exchange(self, algorithm, peer_public_key):
        raise NotImplementedError("SM2 key exchange is not yet implemented.")

    # ---------- SM2 encrypt / decrypt ----------

    def encrypt_sm2(self, data, hash_algorithm='sm3', mode='C1C3C2'):
        if isinstance(data, str):
            data = data.encode('utf-8')
        from ._SM2 import Encrypt
        return Encrypt(
            data, self._public_key._public_key,
            len_para=self._curve.key_size,
            Hexstr=0, hash_algorithm=hash_algorithm,
            mode=mode
        )

    def decrypt_sm2(self, cipher, hash_algorithm='sm3', mode='C1C3C2'):
        from ._SM2 import Decrypt
        return Decrypt(
            cipher, self._private_key,
            len_para=self._curve.key_size,
            Hexstr=0, hash_algorithm=hash_algorithm,
            mode=mode
        )

    # ---------- Serialization ----------

    def private_numbers(self):
        pub_nums = self._public_key.public_numbers()
        d = int(self._private_key.hex(), 16)
        return EllipticCurvePrivateNumbers(d, pub_nums)

    def private_bytes(self, encoding, format, encryption_algorithm):
        from cryptography.hazmat.primitives.serialization import (
            NoEncryption
        )
        if not isinstance(encryption_algorithm, NoEncryption):
            raise NotImplementedError(
                "Encrypted private key serialization not supported for SM2"
            )
        from cryptography.hazmat.backends.openssl.backend import backend
        return backend._private_key_bytes(
            self._curve,
            self.public_key(),
            self._private_key,
            self._public_key._public_key,
            encoding,
            format,
            encryption_algorithm,
        )


# ============================================================
# Backward-compat alias
# ============================================================

class EllipticCurvePrivateKeyWithSerialization(SM2EllipticCurvePrivateKey):
    pass


EllipticCurve.register(SM2EllipticCurve)
EllipticCurveSignatureAlgorithm.register(SM2SM3SignatureAlgorithm)
EllipticCurveSignatureAlgorithm.register(SM2SHA256SignatureAlgorithm)
EllipticCurvePublicKey.register(SM2EllipticCurvePublicKey)
EllipticCurvePrivateKey.register(SM2EllipticCurvePrivateKey)
