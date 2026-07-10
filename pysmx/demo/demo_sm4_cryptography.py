#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @file: demo_sm4_cryptography.py
# SM4 cryptography framework integration demo

from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers.algorithms import SM4
from cryptography.hazmat.primitives import padding

# CFB/OFB moved to decrepit in cryptography 43+
try:
    from cryptography.hazmat.decrepit.ciphers.modes import CFB, OFB
except ImportError:
    from cryptography.hazmat.primitives.ciphers.modes import CFB, OFB

from pysmx.SM4._cryptography import SM4ModePCBC


def test_ecb(key, data):
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(SM4(key), modes.ECB())
    ct = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    pt = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
    unpadder = padding.PKCS7(128).unpadder()
    pt_unpadded = unpadder.update(pt) + unpadder.finalize()
    assert pt_unpadded == data, "ECB check fail"
    print("SM4-ECB OK")


def test_cbc(key, iv, data):
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(SM4(key), modes.CBC(iv))
    ct = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    dec = Cipher(SM4(key), modes.CBC(iv))
    pt = dec.decryptor().update(ct) + dec.decryptor().finalize()
    unpadder = padding.PKCS7(128).unpadder()
    pt_unpadded = unpadder.update(pt) + unpadder.finalize()
    assert pt_unpadded == data, "CBC check fail"
    print("SM4-CBC OK")


def test_cfb(key, iv, data):
    cipher = Cipher(SM4(key), CFB(iv))
    ct = cipher.encryptor().update(data) + cipher.encryptor().finalize()
    dec = Cipher(SM4(key), CFB(iv))
    pt = dec.decryptor().update(ct) + dec.decryptor().finalize()
    assert pt == data, "CFB check fail"
    print("SM4-CFB OK")


def test_ofb(key, iv, data):
    cipher = Cipher(SM4(key), OFB(iv))
    ct = cipher.encryptor().update(data) + cipher.encryptor().finalize()
    dec = Cipher(SM4(key), OFB(iv))
    pt = dec.decryptor().update(ct) + dec.decryptor().finalize()
    assert pt == data, "OFB check fail"
    print("SM4-OFB OK")


def test_pcbc(key, iv, data):
    from pysmx.SM4._SM4 import Sm4, ENCRYPT, DECRYPT
    sm4_enc = Sm4()
    sm4_enc.set_key(key, ENCRYPT)
    ct = sm4_enc.sm4_crypt_pcbc(iv, data)
    sm4_dec = Sm4()
    sm4_dec.set_key(key, DECRYPT)
    pt = sm4_dec.sm4_crypt_pcbc(iv, ct)
    assert pt == data, "PCBC check fail"
    print("SM4-PCBC OK")


def main():
    key = b'0123456789abcdef'
    iv = b'abcdef0123456789'
    # Use 16-byte data so no padding is needed for ECB/CBC/PCBC
    data = b'hello sm4 crypt!'

    test_ecb(key, data)
    test_cbc(key, iv, data)
    test_cfb(key, iv, data)
    test_ofb(key, iv, data)
    test_pcbc(key, iv, data)

    print("All SM4 cryptography tests passed")


if __name__ == '__main__':
    main()
