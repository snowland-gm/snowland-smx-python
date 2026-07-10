#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ZUC conformance tests against GB/T 33133-2016 standard test vectors

import unittest


class TestZUCStandard(unittest.TestCase):
    """ZUC stream cipher conformance tests using GB/T 33133-2016 test vectors."""

    # Standard test vector 1 from GB/T 33133-2016
    # Key: all zeros, IV: all zeros
    # First 2 keystream words: 27bede74, 018082da
    TV1_KEY = [0x00] * 16
    TV1_IV = [0x00] * 16
    TV1_EXPECTED_WORD0 = 0x27bede74
    TV1_EXPECTED_WORD1 = 0x018082da

    # Standard test vector 2
    # Key: all FFs, IV: all FFs
    # First 2 keystream words: 0657cfa0, 7096398b
    TV2_KEY = [0xFF] * 16
    TV2_IV = [0xFF] * 16
    TV2_EXPECTED_WORD0 = 0x0657cfa0
    TV2_EXPECTED_WORD1 = 0x7096398b

    def setUp(self):
        from pysmx.ZUC import ZUC
        self.ZUC = ZUC

    # ---- Standard Test Vector 1 (via zuc_generate_keystream) ----

    def test_tv1_keystream_word0(self):
        """ZUC(all-zero key/IV) first keystream word = 0x27bede74."""
        zuc = self.ZUC(self.TV1_KEY, self.TV1_IV)
        buf = zuc.zuc_generate_keystream()
        self.assertEqual(buf[0], self.TV1_EXPECTED_WORD0)

    def test_tv1_keystream_first_two(self):
        """ZUC(all-zero key/IV) first 2 keystream words."""
        zuc = self.ZUC(self.TV1_KEY, self.TV1_IV)
        buf = zuc.zuc_generate_keystream()
        self.assertEqual(buf[0], self.TV1_EXPECTED_WORD0)
        self.assertEqual(buf[1], self.TV1_EXPECTED_WORD1)

    # ---- Standard Test Vector 2 (via zuc_generate_keystream) ----

    def test_tv2_keystream_word0(self):
        """ZUC(all-FF key/IV) first keystream word = 0x0657cfa0."""
        zuc = self.ZUC(self.TV2_KEY, self.TV2_IV)
        buf = zuc.zuc_generate_keystream()
        self.assertEqual(buf[0], self.TV2_EXPECTED_WORD0)

    def test_tv2_keystream_first_two(self):
        """ZUC(all-FF key/IV) first 2 keystream words."""
        zuc = self.ZUC(self.TV2_KEY, self.TV2_IV)
        buf = zuc.zuc_generate_keystream()
        self.assertEqual(buf[0], self.TV2_EXPECTED_WORD0)
        self.assertEqual(buf[1], self.TV2_EXPECTED_WORD1)

    # ---- Encrypt / Decrypt round-trip ----

    def test_encrypt_decrypt_roundtrip(self):
        key = [0x3D, 0x4C, 0x4B, 0xE9, 0x6A, 0x82, 0xFD, 0xAE,
               0xB5, 0x8F, 0x64, 0x1D, 0xB1, 0x7B, 0x45, 0x5B]
        iv = [0x84, 0x31, 0x9A, 0xA8, 0xDE, 0x69, 0x15, 0xCA,
              0x1F, 0x6B, 0xDA, 0x6B, 0xFB, 0xD8, 0xC7, 0x66]
        plaintext = b"Hello ZUC Stream Cipher!"
        zuc1 = self.ZUC(key, iv)
        encrypted = list(zuc1.zuc_encrypt(plaintext))
        zuc2 = self.ZUC(key, iv)
        decrypted = bytes(list(zuc2.zuc_encrypt(encrypted)))
        self.assertEqual(decrypted, plaintext)

    def test_encrypt_decrypt_empty(self):
        key = [0x00] * 16
        iv = [0x00] * 16
        zuc1 = self.ZUC(key, iv)
        encrypted = list(zuc1.zuc_encrypt(b""))
        self.assertEqual(encrypted, [])

    def test_encrypt_decrypt_long(self):
        key = [0x01] * 16
        iv = [0x02] * 16
        plaintext = b"A" * 1024
        zuc1 = self.ZUC(key, iv)
        encrypted = list(zuc1.zuc_encrypt(plaintext))
        zuc2 = self.ZUC(key, iv)
        decrypted = bytes(list(zuc2.zuc_encrypt(encrypted)))
        self.assertEqual(decrypted, plaintext)

    def test_reproducibility(self):
        """Same key/IV should produce same keystream via zuc_generate_keystream."""
        key = [0x01] * 16
        iv = [0x02] * 16
        zuc1 = self.ZUC(key, iv, buffer_size=10)
        zuc2 = self.ZUC(key, iv, buffer_size=10)
        s1 = zuc1.zuc_generate_keystream()
        s2 = zuc2.zuc_generate_keystream()
        self.assertEqual(s1, s2)

    def test_keystream_length(self):
        """Generate 2000 keystream words to test LFSR stability."""
        key = [0x3D, 0x4C, 0x4B, 0xE9, 0x6A, 0x82, 0xFD, 0xAE,
               0xB5, 0x8F, 0x64, 0x1D, 0xB1, 0x7B, 0x45, 0x5B]
        iv = [0x84, 0x31, 0x9A, 0xA8, 0xDE, 0x69, 0x15, 0xCA,
              0x1F, 0x6B, 0xDA, 0x6B, 0xFB, 0xD8, 0xC7, 0x66]
        zuc = self.ZUC(key, iv, buffer_size=2000)
        words = zuc.zuc_generate_keystream()
        self.assertEqual(len(words), 2000)
        for w in words:
            self.assertIsInstance(w, int)
            self.assertLess(w, 0x100000000)  # 32-bit range

    # ---- __iter__ / __next__ access ----

    def test_iterator_protocol(self):
        """ZUC supports __iter__/__next__ protocol."""
        key = [0x00] * 16
        iv = [0x00] * 16
        zuc = self.ZUC(key, iv)
        w = next(zuc)
        self.assertIsInstance(w, int)


class TestZUCAlgorithm(unittest.TestCase):
    """ZUC core algorithm component tests."""

    def setUp(self):
        from pysmx.ZUC import ZUC
        self.ZUC = ZUC

    def test_zuc_init(self):
        """zuc_init initializes LFSR state."""
        key = [0x00] * 16
        iv = [0x00] * 16
        zuc = self.ZUC(key, iv)
        self.assertEqual(len(zuc.lfsr), 16)

    def test_bit_reorganization(self):
        """bit_reorganization produces 4 X values."""
        key = [0x00] * 16
        iv = [0x00] * 16
        zuc = self.ZUC(key, iv)
        zuc.bit_reorganization()
        self.assertEqual(len(zuc.x), 4)

    def test_f_function(self):
        """F function produces a 32-bit word and updates R1, R2."""
        key = [0x00] * 16
        iv = [0x00] * 16
        zuc = self.ZUC(key, iv)
        zuc.bit_reorganization()
        W = zuc.f()
        self.assertIsInstance(W, int)
        self.assertLess(W, 0x100000000)

    def test_lfsr_shift(self):
        """lfsr_shift advances the LFSR state."""
        key = [0x00] * 16
        iv = [0x00] * 16
        zuc = self.ZUC(key, iv)
        old_state = list(zuc.lfsr)
        zuc.lfsr_shift()
        self.assertEqual(len(zuc.lfsr), 16)
        self.assertNotEqual(old_state, zuc.lfsr)


if __name__ == '__main__':
    unittest.main()
