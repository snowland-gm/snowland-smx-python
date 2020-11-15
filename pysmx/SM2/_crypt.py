#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: 深圳星河软通科技有限公司 A.Star
# @contact: astar@snowland.ltd
# @site: www.astar.ltd
# @file: _crypt .py
# @time: 2020/10/25 2:52
# @Software: PyCharm


from astartool.string import force_bytes
from pysmx.crypto import hashlib
import hmac

import six
try:
    import simplejson as json
except:
    import json
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve, EllipticCurveSignatureAlgorithm, _CURVE_TYPES
from cryptography.utils import register_interface, read_only_property, _check_bytes
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key,
        load_pem_public_key,
        load_ssh_public_key,
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPrivateKey,
        RSAPublicKey,
        RSAPrivateNumbers,
        RSAPublicNumbers,
        rsa_recover_prime_factors,
        rsa_crt_dmp1,
        rsa_crt_dmq1,
        rsa_crt_iqmp,
    )
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePrivateKey,
        EllipticCurvePublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature

    import cryptography.exceptions
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.utils import int_from_bytes

    has_crypto = True
except ImportError:
    has_crypto = False

@register_interface(EllipticCurve)
class SM2EllipticCurve:
    name = 'sm2sm364'
    key_size = 64


@register_interface(EllipticCurveSignatureAlgorithm)
class SM2SM3EllipticCurveSignatureAlgorithm:
    def __init__(self, algorithm):
        self._algorithm = algorithm
    algorithm = read_only_property("_algorithm")

@register_interface(EllipticCurveSignatureAlgorithm)
class SM2SHA256EllipticCurveSignatureAlgorithm:
    algorithm='sm2sm364'




@register_interface(EllipticCurveSignatureAlgorithm)
class EllipticCurvePrivateKey(object):
    def signer(self, signature_algorithm):
        """
        Returns an AsymmetricSignatureContext used for signing data.
        """

    def exchange(self, algorithm, peer_public_key):
        """
        Performs a key exchange operation using the provided algorithm with the
        provided peer's public key.
        """

    def public_key(self):
        """
        The EllipticCurvePublicKey for this private key.
        """

    def curve(self):
        """
        The EllipticCurve that this key is on.
        """
        return
    def key_size(self):
        """
        Bit size of a secret scalar for the curve.
        """

    def sign(self, data, signature_algorithm):
        """
        Signs the data
        """


class EllipticCurvePrivateKeyWithSerialization(EllipticCurvePrivateKey):
    def private_numbers(self):
        """
        Returns an EllipticCurvePrivateNumbers.
        """

    def private_bytes(self, encoding, format, encryption_algorithm):
        """
        Returns the key serialized as bytes.
        """

@register_interface(EllipticCurvePublicKey)
class SM2EllipticCurvePublicKey(object):
    def verifier(self, signature, signature_algorithm):
        """
        Returns an AsymmetricVerificationContext used for signing data.
        """

    def curve(self):
        """
        The EllipticCurve that this key is on.
        """

    key_size=64*3

    def public_numbers(self):
        """
        Returns an EllipticCurvePublicNumbers.
        """

    def public_bytes(self, encoding, format):
        """
        Returns the key serialized as bytes.
        """

    def verify(self, signature, data, signature_algorithm):
        """
        Verifies the signature of the data.
        """

    @classmethod
    def from_encoded_point(cls, curve, data):
        _check_bytes("data", data)

        if not isinstance(curve, EllipticCurve):
            raise TypeError("curve must be an EllipticCurve instance")

        if len(data) == 0:
            raise ValueError("data must not be an empty byte string")

        if six.indexbytes(data, 0) not in [0x02, 0x03, 0x04]:
            raise ValueError("Unsupported elliptic curve point type")

        from cryptography.hazmat.backends.openssl.backend import backend
        return backend.load_elliptic_curve_public_bytes(curve, data)
