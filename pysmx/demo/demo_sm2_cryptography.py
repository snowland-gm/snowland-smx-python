#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pysmx.SM2._cryptography import (
    SM2EllipticCurve, SM2SM3SignatureAlgorithm, SM2EllipticCurvePrivateKey)

def main():
    curve = SM2EllipticCurve()
    sig_alg = SM2SM3SignatureAlgorithm()
    sk = SM2EllipticCurvePrivateKey.generate(curve)
    pk = sk.public_key()
    sig = sk.sign(b'hello', sig_alg)
    pk.verify(sig, b'hello', sig_alg)
    print('SM2 sign/verify: OK')
    c = sk.encrypt_sm2(b'hello')
    m = sk.decrypt_sm2(c)
    print('SM2 encrypt/decrypt:', m.decode())

if '__main__' == __name__:
    main()
