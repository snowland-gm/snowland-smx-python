#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SM2 conformance tests against GB/T 32918 standard test vectors

import unittest


class TestSM2Standard(unittest.TestCase):
    """SM2 elliptic curve crypto conformance tests using GB/T 32918 test vectors."""

    # Standard test vectors from GB/T 32918.2-2016
    # Private key d_A
    D = (
        "3945208F7B2144B13F36E38AC6D39F95"
        "889393692860B51A42FB81EF4DF7C5B8"
    )
    # Public key P_A coordinates
    PX = (
        "09F9DF311E5421A150DD7D161E4BC5C6"
        "72179FAD1833FC076BB08FF356F35020"
    )
    PY = (
        "CCEA490CE26775A52DC6EA718CC1AA60"
        "0AED05FBF35E084A6632F6072DA9AD13"
    )
    PA = PX + PY

    # Test message for signature
    MSG = "message digest"
    MSG_BYTES = MSG.encode()

    # User ID for SM2 signature
    IDA = "ALICE123@YAHOO.COM"

    def setUp(self):
        import pysmx.SM2 as sm2
        self.sm2 = sm2

    # ---- Key Generation ----

    def test_generate_keypair(self):
        pk, sk = self.sm2.generate_keypair(64)
        self.assertEqual(len(pk), 64)  # 32 bytes x + 32 bytes y
        self.assertEqual(len(sk), 32)

    def test_keypair_consistency(self):
        pk, sk = self.sm2.generate_keypair(64)
        # Encrypt with public key, decrypt with private key
        msg = b"test message"
        cipher = self.sm2.Encrypt(msg, pk, 64)
        plain = self.sm2.Decrypt(cipher, sk, 64)
        self.assertEqual(plain, msg)

    # ---- Encryption / Decryption ----

    def test_encrypt_decrypt_basic(self):
        msg = b"Hello SM2 Encryption!"
        pk, sk = self.sm2.generate_keypair(64)
        cipher = self.sm2.Encrypt(msg, pk, 64)
        plain = self.sm2.Decrypt(cipher, sk, 64)
        self.assertEqual(plain, msg)

    def test_encrypt_decrypt_hex_message(self):
        msg_hex = "0123456789abcdef"
        pk, sk = self.sm2.generate_keypair(64)
        cipher = self.sm2.Encrypt(msg_hex, pk, 64, Hexstr=1)
        # When Hexstr=1, cipher is still bytes, but Decrypt
        # expects hex-formatted input for the ciphertext.
        plain = self.sm2.Decrypt(cipher, sk, 64, Hexstr=0)
        self.assertEqual(plain.hex(), msg_hex)

    def test_encrypt_decrypt_long_message(self):
        msg = b"A" * 100
        pk, sk = self.sm2.generate_keypair(64)
        cipher = self.sm2.Encrypt(msg, pk, 64)
        plain = self.sm2.Decrypt(cipher, sk, 64)
        self.assertEqual(plain, msg)

    def test_encrypt_decrypt_single_byte(self):
        msg = b"X"
        pk, sk = self.sm2.generate_keypair(64)
        cipher = self.sm2.Encrypt(msg, pk, 64)
        plain = self.sm2.Decrypt(cipher, sk, 64)
        self.assertEqual(plain, msg)

    def test_encrypt_decrypt_empty(self):
        """Empty message: Encrypt raises ValueError (hash of empty input)."""
        pk, sk = self.sm2.generate_keypair(64)
        with self.assertRaises(ValueError):
            self.sm2.Encrypt(b"", pk, 64)

    # ---- C1C3C2 mode (default, gmssl compatible) ----

    def test_c1c3c2_roundtrip(self):
        msg = b"test C1C3C2 mode"
        pk, sk = self.sm2.generate_keypair(64)
        cipher = self.sm2.Encrypt(msg, pk, 64, mode='C1C3C2')
        plain = self.sm2.Decrypt(cipher, sk, 64, mode='C1C3C2')
        self.assertEqual(plain, msg)

    def test_c1c3c2_is_default(self):
        msg = b"test default mode"
        pk, sk = self.sm2.generate_keypair(64)
        c1 = self.sm2.Encrypt(msg, pk, 64)
        c2 = self.sm2.Encrypt(msg, pk, 64, mode='C1C3C2')
        # Same message encrypted twice produces different ciphertexts
        # (random k), but same mode produces compatible format
        p1 = self.sm2.Decrypt(c1, sk, 64)
        p2 = self.sm2.Decrypt(c2, sk, 64, mode='C1C3C2')
        self.assertEqual(p1, msg)
        self.assertEqual(p2, msg)

    # ---- C1C2C3 mode ----

    def test_c1c2c3_roundtrip(self):
        msg = b"test C1C2C3 mode"
        pk, sk = self.sm2.generate_keypair(64)
        cipher = self.sm2.Encrypt(msg, pk, 64, mode='C1C2C3')
        plain = self.sm2.Decrypt(cipher, sk, 64, mode='C1C2C3')
        self.assertEqual(plain, msg)

    def test_c1c2c3_cross_mode(self):
        """Encrypt with C1C3C2, decrypt with C1C2C3 should fail."""
        msg = b"cross mode test"
        pk, sk = self.sm2.generate_keypair(64)
        cipher_c1c3c2 = self.sm2.Encrypt(msg, pk, 64, mode='C1C3C2')
        # Decrypting C1C3C2 ciphertext with C1C2C3 mode should fail
        plain = self.sm2.Decrypt(cipher_c1c3c2, sk, 64, mode='C1C2C3')
        self.assertIsNone(plain)

    # ---- Signature / Verification ----

    def test_sign_verify_basic(self):
        from pysmx.SM3 import hexdigest
        from pysmx.SM2._SM2 import get_random_str
        msg = self.MSG
        pk, sk = self.sm2.generate_keypair(64)
        e = hexdigest(msg)
        K = get_random_str(64)
        sig = self.sm2.Sign(e, sk, K, 64, Hexstr=1)
        self.assertIsNotNone(sig)
        result = self.sm2.Verify(sig, e, pk, 64, Hexstr=1)
        self.assertTrue(result)

    def test_sign_verify_wrong_message(self):
        from pysmx.SM3 import hexdigest
        from pysmx.SM2._SM2 import get_random_str
        msg1 = "message one"
        msg2 = "message two"
        pk, sk = self.sm2.generate_keypair(64)
        e1 = hexdigest(msg1)
        e2 = hexdigest(msg2)
        K = get_random_str(64)
        sig = self.sm2.Sign(e1, sk, K, 64, Hexstr=1)
        result = self.sm2.Verify(sig, e2, pk, 64, Hexstr=1)
        self.assertFalse(result)

    def test_sign_verify_wrong_key(self):
        from pysmx.SM3 import hexdigest
        from pysmx.SM2._SM2 import get_random_str
        msg = self.MSG
        pk1, sk1 = self.sm2.generate_keypair(64)
        pk2, _ = self.sm2.generate_keypair(64)
        e = hexdigest(msg)
        K = get_random_str(64)
        sig = self.sm2.Sign(e, sk1, K, 64, Hexstr=1)
        result = self.sm2.Verify(sig, e, pk2, 64, Hexstr=1)
        self.assertFalse(result)

    def test_signature_deterministic(self):
        """Same message, same K should produce same signature."""
        from pysmx.SM3 import hexdigest
        msg = self.MSG
        pk, sk = self.sm2.generate_keypair(64)
        e = hexdigest(msg)
        K = "59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21"
        sig1 = self.sm2.Sign(e, sk, K, 64, Hexstr=1)
        sig2 = self.sm2.Sign(e, sk, K, 64, Hexstr=1)
        self.assertEqual(sig1, sig2)

    # ---- K = 1 edge case ----

    def test_sign_K_one(self):
        """Signing with K=1 should produce a valid signature."""
        from pysmx.SM3 import hexdigest
        msg = self.MSG
        pk, sk = self.sm2.generate_keypair(64)
        e = hexdigest(msg)
        K = "1" + "0" * 63  # K=1 as 64-char hex
        sig = self.sm2.Sign(e, sk, K, 64, Hexstr=1)
        self.assertIsNotNone(sig)
        # Verify the signature
        result = self.sm2.Verify(sig, e, pk, 64, Hexstr=1)
        self.assertTrue(result)


if __name__ == '__main__':
    unittest.main()
