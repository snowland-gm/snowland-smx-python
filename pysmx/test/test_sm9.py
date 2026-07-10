#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SM9 identity-based crypto conformance tests

import unittest


class TestSM9Standard(unittest.TestCase):
    """SM9 identity-based crypto key generation and derivation tests."""

    def setUp(self):
        from pysmx.SM9._SM9 import (
            generate_master_key,
            generate_user_sign_key,
            generate_user_enc_key,
        )
        self.generate_master_key = generate_master_key
        self.generate_user_sign_key = generate_user_sign_key
        self.generate_user_enc_key = generate_user_enc_key

    def test_generate_master_key(self):
        ks, P_pub = self.generate_master_key()
        self.assertIsInstance(ks, int)
        self.assertGreater(ks, 0)
        self.assertIsInstance(P_pub, tuple)
        self.assertEqual(len(P_pub), 2)

    def test_generate_master_key_reproducible(self):
        """Two calls produce different random keys."""
        ks1, pp1 = self.generate_master_key()
        ks2, pp2 = self.generate_master_key()
        self.assertNotEqual(ks1, ks2)

    def test_generate_user_sign_key(self):
        ks, P_pub = self.generate_master_key()
        d_A = self.generate_user_sign_key(ks, b'a', 0x01)
        self.assertIsInstance(d_A, tuple)
        self.assertEqual(len(d_A), 2)
        self.assertIsInstance(d_A[0], int)
        self.assertIsInstance(d_A[1], int)

    def test_generate_user_enc_key(self):
        """User encryption key is a G2 point: ((xa,xb), (ya,yb))."""
        ks, P_pub = self.generate_master_key()
        d_B = self.generate_user_enc_key(ks, b'b', 0x03)
        self.assertIsInstance(d_B, tuple)
        self.assertEqual(len(d_B), 2)
        # G2 point: each coordinate is an Fp2 element (tuple of 2 ints)
        self.assertIsInstance(d_B[0], tuple)
        self.assertIsInstance(d_B[1], tuple)
        self.assertIsInstance(d_B[0][0], int)


if __name__ == '__main__':
    unittest.main()
