#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SM9 identity-based crypto conformance tests

import unittest

from pysmx.SM9._SM9 import (
    generate_master_key,
    generate_user_sign_key,
    generate_user_enc_key,
    Sign, Verify, Encrypt, Decrypt,
    KEM_Encapsulate, KEM_Decapsulate,
    _ate_pairing, _fp12_eq, _fp12_pow,
    _g1_scalar_mult, _g1_to_affine,
    _g2_scalar_mult, _g2_to_affine,
    _sm9_N, _sm9_P1x, _sm9_P1y, _sm9_P2,
)


P1 = (_sm9_P1x, _sm9_P1y)
P2 = ((_sm9_P2[0], _sm9_P2[1]), (_sm9_P2[2], _sm9_P2[3]))


class TestSM9Standard(unittest.TestCase):
    """SM9 identity-based crypto conformance tests."""

    def test_generate_master_key(self):
        ks, P_pub = generate_master_key()
        self.assertIsInstance(ks, int)
        self.assertGreater(ks, 0)
        self.assertIsInstance(P_pub, tuple)
        self.assertEqual(len(P_pub), 2)

    def test_generate_master_key_reproducible(self):
        """Two calls produce different random keys."""
        ks1, pp1 = generate_master_key()
        ks2, pp2 = generate_master_key()
        self.assertNotEqual(ks1, ks2)

    def test_generate_user_sign_key(self):
        ks, _ = generate_master_key()
        d_A = generate_user_sign_key(ks, b'a', 0x01)
        self.assertIsInstance(d_A, tuple)
        self.assertEqual(len(d_A), 2)
        self.assertIsInstance(d_A[0], int)
        self.assertIsInstance(d_A[1], int)

    def test_generate_user_enc_key(self):
        """User encryption key is a G2 point: ((xa,xb), (ya,yb))."""
        ke, _ = generate_master_key()
        d_B = generate_user_enc_key(ke, b'b', 0x03)
        self.assertIsInstance(d_B, tuple)
        self.assertEqual(len(d_B), 2)
        self.assertIsInstance(d_B[0], tuple)
        self.assertIsInstance(d_B[1], tuple)
        self.assertIsInstance(d_B[0][0], int)

    def test_pairing_bilinearity(self):
        """e([a]P1, [b]P2) == e(P1, P2)^(a*b) (and single-sided variants)."""
        a = 0x12345 + 1
        b = 0x6789A + 1
        aP = _g1_to_affine(_g1_scalar_mult(a, P1))
        bQ = _g2_to_affine(_g2_scalar_mult(b, P2))
        e11 = _ate_pairing(P1, P2)
        e_ab = _ate_pairing(aP, bQ)
        self.assertTrue(_fp12_eq(e_ab, _fp12_pow(e11, (a * b) % _sm9_N)))
        e_a1 = _ate_pairing(aP, P2)
        self.assertTrue(_fp12_eq(e_a1, _fp12_pow(e11, a % _sm9_N)))
        e_1b = _ate_pairing(P1, bQ)
        self.assertTrue(_fp12_eq(e_1b, _fp12_pow(e11, b % _sm9_N)))

    def test_sign_verify(self):
        ke, _ = generate_master_key()
        P_pub_s = _g2_to_affine(_g2_scalar_mult(ke, P2))
        ID_A = b'alice@sm9.test'
        d_A = generate_user_sign_key(ke, ID_A, hid=0x01)
        M = b'Hello SM9 pairing!'
        sig = Sign(M, d_A, P_pub_s, hid=0x01)
        self.assertEqual(len(sig), 96)
        self.assertTrue(bool(Verify(M, sig, ID_A, P_pub_s, hid=0x01)))
        # tampered message must fail
        self.assertFalse(bool(Verify(b'tampered', sig, ID_A, P_pub_s, hid=0x01)))

    def test_encrypt_decrypt_roundtrip(self):
        ke, P_pub_e = generate_master_key()
        ID_B = b'bob@sm9.test'
        d_B = generate_user_enc_key(ke, ID_B, hid=0x03)
        for msg in (b'', b'short', b'secret message for SM9 encryption roundtrip test'):
            ct = Encrypt(msg, ID_B, P_pub_e, hid=0x03)
            pt = Decrypt(ct, d_B, ID_B, hid=0x03)
            self.assertEqual(pt, msg)

    def test_kem_roundtrip(self):
        ke, P_pub_e = generate_master_key()
        ID_B = b'bob@sm9.test'
        d_B = generate_user_enc_key(ke, ID_B, hid=0x03)
        for klen in (16, 32):
            K1, C = KEM_Encapsulate(ID_B, P_pub_e, klen, hid=0x02)
            K2 = KEM_Decapsulate(C, d_B, ID_B, klen, hid=0x02)
            self.assertEqual(K1, K2)
            self.assertEqual(len(K1), klen)


if __name__ == '__main__':
    unittest.main()
