#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @contact: astar@snowland.ltd
# @file: _cryptography.py
# @time: 2021/2/8 21:48
# @Software: PyCharm
#
# SM9 cryptography framework integration.
#

import six

try:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurve,
        EllipticCurveSignatureAlgorithm,
        EllipticCurvePrivateKey,
        EllipticCurvePublicKey,
    )
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature

    from pysmx.SM9._SM9 import (
        Sign as _sm9_sign,
        Verify as _sm9_verify,
        generate_master_key,
        generate_user_sign_key,
    )

    has_crypto = True
except ImportError:
    has_crypto = False


def _check_bytes(name, value):
    if not isinstance(value, bytes):
        raise TypeError('{} must be bytes'.format(name))


# ============================================================
# SM9 Elliptic Curve descriptor
# ============================================================

class SM9EllipticCurve(object):
    name = 'sm9bn256'
    key_size = 32  # 256 bits / 8


# ============================================================
# SM9 Signature Algorithm
# ============================================================

class SM9SM3SignatureAlgorithm(object):
    name = 'sm9sm3'

    def __init__(self, algorithm=None):
        if algorithm is None:
            self._algorithm = 'sm3'
        else:
            self._algorithm = algorithm

    @property
    def algorithm(self):
        return self._algorithm


def _resolve_hash_name(signature_algorithm):
    alg = getattr(signature_algorithm, 'algorithm', 'sm3')
    if hasattr(alg, 'name'):
        return alg.name
    return str(alg)


# ============================================================
# SM9 Public Key
# ============================================================

class SM9EllipticCurvePublicKey(object):
    def __init__(self, curve, public_key_bytes, identity=None):
        if not isinstance(curve, SM9EllipticCurve):
            raise TypeError("curve must be an SM9EllipticCurve instance")
        _check_bytes("public_key_bytes", public_key_bytes)
        if identity is not None:
            _check_bytes("identity", identity)
        self._curve = curve
        self._public_key = public_key_bytes
        self._identity = identity

    @classmethod
    def from_encoded_point(cls, curve, data):
        _check_bytes("data", data)
        raise NotImplementedError("SM9 does not support from_encoded_point")

    @property
    def curve(self):
        return self._curve

    @property
    def key_size(self):
        return self._curve.key_size * 8

    @property
    def identity(self):
        return self._identity

    def verify(self, signature, data, signature_algorithm):
        _check_bytes("data", data)
        _check_bytes("signature", signature)

        if self._identity is None:
            raise ValueError("SM9 verification requires identity")

        # Parse the master public key from public_key_bytes
        # public_key_bytes contains the master public key (G2 point)
        pub_key = _parse_g2_point(self._public_key)

        result = _sm9_verify(
            data, signature,
            self._identity, pub_key,
            hid=0x01
        )
        if not result:
            raise InvalidSignature("SM9 signature verification failed.")

    def verifier(self, signature, signature_algorithm):
        raise NotImplementedError(
            "SM9 does not support incremental verification contexts."
        )


# ============================================================
# SM9 Private Key
# ============================================================

class SM9EllipticCurvePrivateKey(object):
    def __init__(self, curve, master_private_bytes, master_public_bytes, identity=None):
        if not isinstance(curve, SM9EllipticCurve):
            raise TypeError("curve must be an SM9EllipticCurve instance")
        _check_bytes("master_private_bytes", master_private_bytes)
        _check_bytes("master_public_bytes", master_public_bytes)
        if identity is not None:
            _check_bytes("identity", identity)
        self._curve = curve
        self._master_private = master_private_bytes
        self._master_public = master_public_bytes
        self._identity = identity

        # Derive user signing key from master key
        ks = int.from_bytes(master_private_bytes, 'big')
        self._master_sk = ks
        pub_key = _parse_g2_point(master_public_bytes)
        self._master_pk = pub_key

        if identity is not None:
            d_A = generate_user_sign_key(ks, identity, hid=0x01)
            self._user_sk = d_A
            self._user_sk_bytes = (
                _int_to_bytes(d_A[0], 32) + _int_to_bytes(d_A[1], 32)
            )
        else:
            self._user_sk = None
            self._user_sk_bytes = None

    @classmethod
    def generate(cls, curve=None, identity=None):
        if curve is None:
            curve = SM9EllipticCurve()
        if not isinstance(curve, SM9EllipticCurve):
            raise TypeError("curve must be an SM9EllipticCurve instance")
        if identity is None:
            raise ValueError("SM9 key generation requires an identity string")
        if isinstance(identity, str):
            identity = identity.encode('utf-8')

        ks, P_pub_e = generate_master_key()

        # Convert master public key to G2 point form
        # P_pub_s = [ks] * P2 (signature master public key)
        from pysmx.SM9._SM9 import _g2_scalar_mult, _g2_to_affine
        P2 = (
            (
                int('85AEF3D078640C98597B60277B41A01FF1DD2C190F5E93C454806C11D8806141', 16),
                int('3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B', 16),
            ),
            (
                int('17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96', 16),
                int('A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7', 16),
            ),
        )
        P_pub_s_jac = _g2_scalar_mult(ks, P2)
        P_pub_s = _g2_to_affine(P_pub_s_jac)

        master_private_bytes = _int_to_bytes(ks, 32)
        master_public_bytes = _serialize_g2_point(P_pub_s)

        return cls(curve, master_private_bytes, master_public_bytes, identity)

    @property
    def curve(self):
        return self._curve

    @property
    def key_size(self):
        return self._curve.key_size * 8

    @property
    def identity(self):
        return self._identity

    def public_key(self):
        return SM9EllipticCurvePublicKey(
            self._curve, self._master_public, self._identity
        )

    def sign(self, data, signature_algorithm):
        _check_bytes("data", data)
        if self._user_sk is None:
            raise ValueError("SM9 signing requires an identity to derive user key")

        sig = _sm9_sign(
            data, self._user_sk, self._master_pk, hid=0x01
        )
        return sig

    def signer(self, signature_algorithm):
        raise NotImplementedError(
            "SM9 does not support incremental signing contexts."
        )

    def exchange(self, algorithm, peer_public_key):
        raise NotImplementedError("SM9 key exchange is not yet implemented.")

    # ---------- SM9 encrypt / decrypt ----------

    def encrypt_sm9(self, data, recipient_identity, hid=0x03):
        if isinstance(data, str):
            data = data.encode('utf-8')
        if isinstance(recipient_identity, str):
            recipient_identity = recipient_identity.encode('utf-8')

        from pysmx.SM9._SM9 import (
            Encrypt as _sm9_encrypt,
            _g1_scalar_mult,
            _g1_to_affine,
        )
        P1 = (
            int('93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD', 16),
            int('21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616', 16),
        )
        P_pub_e_jac = _g1_scalar_mult(self._master_sk, P1)
        P_pub_e = _g1_to_affine(P_pub_e_jac)

        return _sm9_encrypt(data, recipient_identity, P_pub_e, hid=hid)

    def decrypt_sm9(self, cipher, recipient_identity=None, hid=0x03):
        if recipient_identity is None:
            recipient_identity = self._identity
        if isinstance(recipient_identity, str):
            recipient_identity = recipient_identity.encode('utf-8')

        from pysmx.SM9._SM9 import (
            Decrypt as _sm9_decrypt,
            generate_user_enc_key,
        )

        d_B = generate_user_enc_key(self._master_sk, recipient_identity, hid=hid)
        return _sm9_decrypt(cipher, d_B, recipient_identity, hid=hid)

    # ---------- Serialization ----------

    def private_bytes(self, encoding, format, encryption_algorithm):
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PrivateFormat, NoEncryption
        )
        if encoding is not Encoding.DER:
            raise ValueError("SM9 private key only supports DER encoding")
        if not isinstance(encryption_algorithm, NoEncryption):
            raise NotImplementedError(
                "Encrypted private key serialization not supported for SM9"
            )

        # Serialize as: master_private || master_public || identity_length || identity
        result = self._master_private + self._master_public
        if self._identity:
            result += _int_to_bytes(len(self._identity), 2) + self._identity
        else:
            result += b'\x00\x00'
        return result


# ============================================================
# Helper functions for point serialization
# ============================================================

def _int_to_bytes(x, length):
    return x.to_bytes(length, 'big')


def _serialize_g2_point(P):
    """Serialize G2 point (Fp2 x, Fp2 y) to bytes."""
    x, y = P
    return (
        _int_to_bytes(x[0], 32) + _int_to_bytes(x[1], 32) +
        _int_to_bytes(y[0], 32) + _int_to_bytes(y[1], 32)
    )


def _parse_g2_point(data):
    """Parse 128 bytes into G2 point (Fp2 x, Fp2 y)."""
    if len(data) != 128:
        raise ValueError("G2 point must be 128 bytes")
    x_a = int.from_bytes(data[0:32], 'big')
    x_b = int.from_bytes(data[32:64], 'big')
    y_a = int.from_bytes(data[64:96], 'big')
    y_b = int.from_bytes(data[96:128], 'big')
    return ((x_a, x_b), (y_a, y_b))


# ============================================================
# Registration with cryptography interfaces
# ============================================================

EllipticCurve.register(SM9EllipticCurve)
EllipticCurveSignatureAlgorithm.register(SM9SM3SignatureAlgorithm)
EllipticCurvePublicKey.register(SM9EllipticCurvePublicKey)
EllipticCurvePrivateKey.register(SM9EllipticCurvePrivateKey)
