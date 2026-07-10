#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Block ciphers regression tests for CFB/OFB/PCBC decrypt padding fixes

import unittest


class TestSM4BlockCyphersDecrypt(unittest.TestCase):
    """Regression: CFB/OFB/PCBC decrypt paths correctly handle padding."""

    KEY = b'0123456789abcdef'
    IV = b'abcdef0123456789'

    def setUp(self):
        from pysmx.SM4._SM4 import Sm4
        from pysmx.block_cyphers import ENCRYPT, DECRYPT
        self.Sm4 = Sm4
        self.ENCRYPT = ENCRYPT
        self.DECRYPT = DECRYPT

    # -- CFB decrypt regression --

    def test_cfb_decrypt_does_not_raise(self):
        """CFB decrypt with padding should not raise TypeError.

        Regression: crypt_cfb decrypt path passed bytearray to
        PKCS7UnPadding which only accepts bytes.
        """
        sm4 = self.Sm4()
        sm4.set_key(self.KEY, self.ENCRYPT)
        plaintext = b'CFB decrypt regression test'
        ct = sm4.crypt_cfb(self.IV, plaintext)
        sm4.set_key(self.KEY, self.DECRYPT)
        pt = sm4.crypt_cfb(self.IV, ct)
        self.assertEqual(pt, plaintext)

    def test_cfb_decrypt_multi_block(self):
        """CFB decrypt multi-block roundtrip."""
        sm4 = self.Sm4()
        plaintext = b'C' * 64
        sm4.set_key(self.KEY, self.ENCRYPT)
        ct = sm4.crypt_cfb(self.IV, plaintext)
        sm4.set_key(self.KEY, self.DECRYPT)
        pt = sm4.crypt_cfb(self.IV, ct)
        self.assertEqual(pt, plaintext)

    def test_cfb_decrypt_non_aligned(self):
        """CFB decrypt non-aligned data roundtrip."""
        sm4 = self.Sm4()
        plaintext = b'Non-aligned CFB decrypt test'
        sm4.set_key(self.KEY, self.ENCRYPT)
        ct = sm4.crypt_cfb(self.IV, plaintext)
        sm4.set_key(self.KEY, self.DECRYPT)
        pt = sm4.crypt_cfb(self.IV, ct)
        self.assertEqual(pt, plaintext)

    # -- OFB decrypt regression --

    def test_ofb_decrypt_does_not_raise(self):
        """OFB decrypt with unpadding should not raise TypeError.

        Regression: crypt_ofb decrypt path passed bytearray to
        PKCS7UnPadding and called self.padding (should be self.unpadding).
        """
        sm4 = self.Sm4()
        sm4.set_key(self.KEY, self.ENCRYPT)
        plaintext = b'OFB decrypt regression test'
        ct = sm4.crypt_ofb(self.IV, plaintext)
        sm4.set_key(self.KEY, self.DECRYPT)
        pt = sm4.crypt_ofb(self.IV, ct)
        self.assertEqual(pt, plaintext)

    def test_ofb_decrypt_multi_block(self):
        """OFB decrypt multi-block roundtrip."""
        sm4 = self.Sm4()
        plaintext = b'O' * 80
        sm4.set_key(self.KEY, self.ENCRYPT)
        ct = sm4.crypt_ofb(self.IV, plaintext)
        sm4.set_key(self.KEY, self.DECRYPT)
        pt = sm4.crypt_ofb(self.IV, ct)
        self.assertEqual(pt, plaintext)

    def test_ofb_decrypt_non_aligned(self):
        """OFB decrypt non-aligned data roundtrip."""
        sm4 = self.Sm4()
        plaintext = b'Non-aligned OFB decrypt test'
        sm4.set_key(self.KEY, self.ENCRYPT)
        ct = sm4.crypt_ofb(self.IV, plaintext)
        sm4.set_key(self.KEY, self.DECRYPT)
        pt = sm4.crypt_ofb(self.IV, ct)
        self.assertEqual(pt, plaintext)

    # -- PCBC decrypt regression --

    def test_pcbc_decrypt_does_not_raise(self):
        """PCBC decrypt with padding should not raise TypeError.

        Regression: crypt_pcbc decrypt path passed bytearray to
        PKCS7UnPadding which only accepts bytes.
        """
        sm4 = self.Sm4()
        sm4.set_key(self.KEY, self.ENCRYPT)
        plaintext = b'PCBC decrypt regression test!!'
        ct = sm4.crypt_pcbc(self.IV, plaintext)
        sm4.set_key(self.KEY, self.DECRYPT)
        pt = sm4.crypt_pcbc(self.IV, ct)
        self.assertEqual(pt, plaintext)

    def test_pcbc_decrypt_multi_block(self):
        """PCBC decrypt multi-block roundtrip."""
        sm4 = self.Sm4()
        plaintext = b'P' * 48
        sm4.set_key(self.KEY, self.ENCRYPT)
        ct = sm4.crypt_pcbc(self.IV, plaintext)
        sm4.set_key(self.KEY, self.DECRYPT)
        pt = sm4.crypt_pcbc(self.IV, ct)
        self.assertEqual(pt, plaintext)

    def test_pcbc_decrypt_non_aligned(self):
        """PCBC decrypt non-aligned data roundtrip."""
        sm4 = self.Sm4()
        plaintext = b'Non-aligned PCBC decrypt test'
        sm4.set_key(self.KEY, self.ENCRYPT)
        ct = sm4.crypt_pcbc(self.IV, plaintext)
        sm4.set_key(self.KEY, self.DECRYPT)
        pt = sm4.crypt_pcbc(self.IV, ct)
        self.assertEqual(pt, plaintext)

    # -- Convenience functions should also work --

    def test_sm4_crypt_cfb_decrypt_roundtrip(self):
        """sm4_crypt_cfb decrypt should roundtrip correctly."""
        from pysmx.SM4._SM4 import sm4_crypt_cfb
        plaintext = b'Convenience CFB test'
        ct = sm4_crypt_cfb(self.ENCRYPT, self.KEY, self.IV, plaintext)
        pt = sm4_crypt_cfb(self.DECRYPT, self.KEY, self.IV, ct)
        self.assertEqual(pt, plaintext)

    def test_sm4_crypt_ofb_decrypt_roundtrip(self):
        """sm4_crypt_ofb decrypt should roundtrip correctly."""
        from pysmx.SM4._SM4 import sm4_crypt_ofb
        plaintext = b'Convenience OFB test'
        ct = sm4_crypt_ofb(self.ENCRYPT, self.KEY, self.IV, plaintext)
        pt = sm4_crypt_ofb(self.DECRYPT, self.KEY, self.IV, ct)
        self.assertEqual(pt, plaintext)

    def test_sm4_crypt_pcbc_decrypt_roundtrip(self):
        """sm4_crypt_pcbc decrypt should roundtrip correctly."""
        from pysmx.SM4._SM4 import sm4_crypt_pcbc
        plaintext = b'Convenience PCBC test'
        ct = sm4_crypt_pcbc(self.ENCRYPT, self.KEY, self.IV, plaintext)
        pt = sm4_crypt_pcbc(self.DECRYPT, self.KEY, self.IV, ct)
        self.assertEqual(pt, plaintext)


if __name__ == '__main__':
    unittest.main()
