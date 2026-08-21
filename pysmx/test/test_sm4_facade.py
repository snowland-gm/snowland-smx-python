#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for the unified pysmx.sm4_encrypt / sm4_decrypt facade."""

import unittest

import pysmx


KEY = bytes.fromhex("0123456789abcdeffedcba9876543210")
IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


class TestSM4Facade(unittest.TestCase):

    def test_ecb_roundtrip(self):
        for msg in (b"", b"hello", b"x" * 32):
            ct = pysmx.sm4_encrypt("ecb", KEY, msg)
            self.assertEqual(pysmx.sm4_decrypt("ecb", KEY, ct), msg)

    def test_cbc_roundtrip(self):
        msg = b"CBC mode roundtrip payload" * 3
        ct = pysmx.sm4_encrypt("cbc", KEY, msg, IV)
        self.assertEqual(pysmx.sm4_decrypt("cbc", KEY, ct, IV), msg)

    def test_cfb_roundtrip(self):
        msg = b"CFB mode stream test" * 5
        ct = pysmx.sm4_encrypt("cfb", KEY, msg, IV)
        self.assertEqual(pysmx.sm4_decrypt("cfb", KEY, ct, IV), msg)

    def test_ofb_roundtrip(self):
        msg = b"OFB mode stream test" * 5
        ct = pysmx.sm4_encrypt("ofb", KEY, msg, IV)
        self.assertEqual(pysmx.sm4_decrypt("ofb", KEY, ct, IV), msg)

    def test_pcbc_roundtrip(self):
        msg = b"PCBC mode test payload!" * 4
        ct = pysmx.sm4_encrypt("pcbc", KEY, msg, IV)
        self.assertEqual(pysmx.sm4_decrypt("pcbc", KEY, ct, IV), msg)

    def test_case_insensitive_mode(self):
        msg = b"case insensitive"
        ct = pysmx.sm4_encrypt("ECB", KEY, msg)
        self.assertEqual(pysmx.sm4_decrypt("ECB", KEY, ct), msg)

    def test_ecb_does_not_need_iv(self):
        ct = pysmx.sm4_encrypt("ecb", KEY, b"no iv needed")
        self.assertEqual(pysmx.sm4_decrypt("ecb", KEY, ct), b"no iv needed")

    def test_unsupported_mode_raises(self):
        with self.assertRaises(ValueError):
            pysmx.sm4_encrypt("xts", KEY, b"data", IV)


if __name__ == '__main__':
    unittest.main()
