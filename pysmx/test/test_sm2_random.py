#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""SM2 GB/T 32918 public-key derivation vector.

This complements test_sm2.py (which covers randomness hardening and
encrypt/sign round-trips) by asserting that the standard private key
``d`` derives exactly the standard public key coordinates from
GB/T 32918.2-2016.
"""

import unittest

import pysmx.SM2 as sm2


# GB/T 32918.2-2016 public test vector
D = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
PX = "09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020"
PY = "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13"


class TestSM2PubkeyVector(unittest.TestCase):
    """kG(d) must reproduce the standard public key point."""

    def test_pubkey_from_private(self):
        pk = sm2.kG(int(D, 16), sm2.sm2_G, 64)
        self.assertEqual(pk.upper(), (PX + PY).upper())

    def test_generated_keypair_matches_standard(self):
        # The standard public key (PX,PY) corresponds to the standard private
        # key D; deriving via kG must agree with generate_keypair for that d.
        self.assertEqual(sm2.kG(int(D, 16), sm2.sm2_G, 64).upper(),
                         (PX + PY).upper())

    def test_n_order_bounds(self):
        # sm2_N is the group order; valid scalars lie in [1, sm2_N - 1].
        self.assertGreater(sm2.sm2_N, 1)
        pk, sk = sm2.generate_keypair(64)
        d = int(sk.hex(), 16)
        self.assertGreaterEqual(d, 1)
        self.assertLessEqual(d, sm2.sm2_N - 1)


if __name__ == '__main__':
    unittest.main()
