#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SM3 conformance tests against GB/T 32905-2016 standard test vectors

import unittest


class TestSM3Standard(unittest.TestCase):
    """SM3 hash conformance tests using GB/T 32905-2016 test vectors."""

    def setUp(self):
        from pysmx.SM3 import hexdigest, digest
        self.hexdigest = hexdigest
        self.digest = digest

    # Test Vector 1: message "abc"
    # Expected: 66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0
    def test_tv1_abc(self):
        msg = "abc"
        expected = (
            "66c7f0f462eeedd9d1f2d46bdc10e4e2"
            "4167c4875cf2f7a2297da02b8f4ba8e0"
        )
        result = self.hexdigest(msg)
        self.assertEqual(result, expected)

    def test_tv1_abc_bytes(self):
        msg = b"abc"
        expected = (
            "66c7f0f462eeedd9d1f2d46bdc10e4e2"
            "4167c4875cf2f7a2297da02b8f4ba8e0"
        )
        result = self.hexdigest(msg)
        self.assertEqual(result, expected)

    def test_tv1_abc_digest(self):
        msg = b"abc"
        expected = bytes.fromhex(
            "66c7f0f462eeedd9d1f2d46bdc10e4e2"
            "4167c4875cf2f7a2297da02b8f4ba8e0"
        )
        result = self.digest(msg)
        self.assertEqual(result, expected)

    # Test Vector 2: message = "abcd" * 16 (64 bytes, 512 bits)
    # Expected: debe9ff9 2275b8a1 38604889 c18e5a4d
    #           6fdb70e5 387e5765 293dcba3 9c0c5732
    def test_tv2_64_byte(self):
        msg = "abcd" * 16  # 64 bytes
        expected = (
            "debe9ff92275b8a138604889c18e5a4d"
            "6fdb70e5387e5765293dcba39c0c5732"
        )
        result = self.hexdigest(msg)
        self.assertEqual(result, expected)

    # Test Vector 3: SM3Type streaming (equivalent to tv1)
    def test_sm3type_abc(self):
        from pysmx.crypto.hashlib import SM3Type
        sm3 = SM3Type()
        sm3.update(b"abc")
        expected = (
            "66c7f0f462eeedd9d1f2d46bdc10e4e2"
            "4167c4875cf2f7a2297da02b8f4ba8e0"
        )
        self.assertEqual(sm3.hexdigest(), expected)

    # Test Vector 4: SM3Type incremental update
    def test_sm3type_incremental(self):
        from pysmx.crypto.hashlib import SM3Type
        sm3 = SM3Type()
        sm3.update(b"a")
        sm3.update(b"bc")
        expected = (
            "66c7f0f462eeedd9d1f2d46bdc10e4e2"
            "4167c4875cf2f7a2297da02b8f4ba8e0"
        )
        self.assertEqual(sm3.hexdigest(), expected)

    # Test KDF
    def test_kdf(self):
        from pysmx.SM3 import KDF
        # Use a known input and check KDF output length
        xy = (
            "32c4ae2c1f1981195f9904466a39c994"
            "8fe30bbff2660be1715a4589334c74c7"
            "bc3736a2f4f6779c59bdcee36b692153"
            "d0a9877cc62a474002df32e52139f0a0"
        )
        klen = 32  # 32 hex chars = 16 bytes
        result = KDF(xy, klen)
        self.assertEqual(len(result), klen * 2)  # hex string, each byte = 2 chars

    # Consistency: digest/hexdigest should match
    def test_digest_hexdigest_consistency(self):
        msg = b"hello world"
        from pysmx.SM3 import digest, hexdigest
        d = digest(msg)
        h = hexdigest(msg)
        self.assertEqual(d.hex(), h)

    # Empty string
    def test_empty_string(self):
        result = self.hexdigest("")
        # Empty message produces a valid 256-bit hash
        self.assertEqual(len(result), 64)

    # Single character
    def test_single_char(self):
        self.assertEqual(len(self.hexdigest("a")), 64)
        self.assertEqual(len(self.digest(b"a")), 32)


if __name__ == '__main__':
    unittest.main()
