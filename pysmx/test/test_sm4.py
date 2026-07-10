#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SM4 conformance tests against GB/T 32907-2016 standard test vectors

import unittest


class TestSM4Standard(unittest.TestCase):
    """SM4 block cipher conformance tests using GB/T 32907-2016 test vectors."""

    # Standard ECB test vector from GB/T 32907-2016
    # Key: 0123456789abcdeffedcba9876543210
    # Plaintext: 0123456789abcdeffedcba9876543210
    # Ciphertext: 681edf34d206965e86b3e94f536e4246
    ECB_KEY = "0123456789abcdeffedcba9876543210"
    ECB_PLAINTEXT = "0123456789abcdeffedcba9876543210"
    ECB_CIPHERTEXT = "681edf34d206965e86b3e94f536e4246"

    def setUp(self):
        from pysmx.SM4._SM4 import (
            Sm4, sm4_crypt_ecb, sm4_crypt_cbc,
            sm4F, sm4Lt, sm4CalciRK,
        )
        from pysmx.block_cyphers import ENCRYPT, DECRYPT
        self.Sm4 = Sm4
        self.sm4_crypt_ecb = sm4_crypt_ecb
        self.sm4_crypt_cbc = sm4_crypt_cbc
        self.ENCRYPT = ENCRYPT
        self.DECRYPT = DECRYPT
        self.sm4F = sm4F
        self.sm4Lt = sm4Lt
        self.sm4CalciRK = sm4CalciRK

    # ---- Sm4 Class (low-level) ----

    def test_sm4_roundtrip(self):
        """Sm4 class encrypt then decrypt = plaintext."""
        sm4_enc = self.Sm4()
        sm4_enc.set_key(bytes.fromhex(self.ECB_KEY), self.ENCRYPT)
        ciphertext = sm4_enc.crypt_ecb(bytes.fromhex(self.ECB_PLAINTEXT))

        sm4_dec = self.Sm4()
        sm4_dec.set_key(bytes.fromhex(self.ECB_KEY), self.DECRYPT)
        plaintext = sm4_dec.crypt_ecb(ciphertext)

        self.assertEqual(plaintext, bytes.fromhex(self.ECB_PLAINTEXT))

    def test_sm4_encrypt_standard_vector(self):
        """ECB encrypt: first block matches standard test vector."""
        sm4 = self.Sm4()
        sm4.set_key(bytes.fromhex(self.ECB_KEY), self.ENCRYPT)
        # Sm4.crypt_ecb applies PKCS5 padding, so output >= 16 bytes
        ciphertext = sm4.crypt_ecb(bytes.fromhex(self.ECB_PLAINTEXT))
        # First 16 bytes (1 block) should match standard vector
        self.assertEqual(
            ciphertext[:16].hex(),
            self.ECB_CIPHERTEXT[:32]
        )

    def test_sm4_decrypt_standard_vector(self):
        """ECB decrypt: roundtrip through encrypt/decrypt works."""
        sm4_enc = self.Sm4()
        sm4_enc.set_key(bytes.fromhex(self.ECB_KEY), self.ENCRYPT)
        ciphertext = sm4_enc.crypt_ecb(bytes.fromhex(self.ECB_PLAINTEXT))

        sm4_dec = self.Sm4()
        sm4_dec.set_key(bytes.fromhex(self.ECB_KEY), self.DECRYPT)
        plaintext = sm4_dec.crypt_ecb(ciphertext)

        self.assertEqual(
            plaintext.hex(),
            self.ECB_PLAINTEXT
        )

    # ---- ECB Mode (function API with padding) ----

    def test_ecb_encrypt_first_block(self):
        key = bytes.fromhex(self.ECB_KEY)
        plaintext = bytes.fromhex(self.ECB_PLAINTEXT)
        # sm4_crypt_ecb applies PKCS5 padding
        result = self.sm4_crypt_ecb(self.ENCRYPT, key, plaintext)
        # First block should match standard vector
        self.assertEqual(
            result[:16].hex(),
            self.ECB_CIPHERTEXT
        )

    def test_ecb_roundtrip(self):
        key = bytes.fromhex(self.ECB_KEY)
        plaintext = bytes.fromhex(self.ECB_PLAINTEXT)
        ciphertext = self.sm4_crypt_ecb(self.ENCRYPT, key, plaintext)
        decrypted = self.sm4_crypt_ecb(self.DECRYPT, key, ciphertext)
        self.assertEqual(decrypted, plaintext)

    def test_ecb_multi_block(self):
        key = b"0123456789abcdef"
        plaintext = b"A" * 64
        ciphertext = self.sm4_crypt_ecb(self.ENCRYPT, key, plaintext)
        decrypted = self.sm4_crypt_ecb(self.DECRYPT, key, ciphertext)
        self.assertEqual(decrypted, plaintext)

    # ---- CBC Mode ----

    def test_cbc_roundtrip(self):
        key = bytes.fromhex(self.ECB_KEY)
        iv = b'\x00' * 16
        plaintext = b"Hello SM4 CBC Mode Test!!"
        ciphertext = self.sm4_crypt_cbc(self.ENCRYPT, key, iv, plaintext)
        decrypted = self.sm4_crypt_cbc(self.DECRYPT, key, iv, ciphertext)
        self.assertEqual(decrypted, plaintext)

    def test_cbc_cross_iv(self):
        """CBC with wrong IV should produce wrong plaintext."""
        key = bytes.fromhex(self.ECB_KEY)
        iv = b'\x00' * 16
        wrong_iv = b'\xFF' * 16
        plaintext = b"test data" * 2
        ciphertext = self.sm4_crypt_cbc(self.ENCRYPT, key, iv, plaintext)
        decrypted_wrong = self.sm4_crypt_cbc(
            self.DECRYPT, key, wrong_iv, ciphertext
        )
        self.assertNotEqual(decrypted_wrong, plaintext)

    def test_cbc_multi_block(self):
        key = bytes.fromhex(self.ECB_KEY)
        iv = b'\x11' * 16
        plaintext = b"A" * 48
        ciphertext = self.sm4_crypt_cbc(self.ENCRYPT, key, iv, plaintext)
        decrypted = self.sm4_crypt_cbc(self.DECRYPT, key, iv, ciphertext)
        self.assertEqual(decrypted, plaintext)

    # ---- Algorithm components ----

    def test_sm4F_basic(self):
        """sm4F round function basic test."""
        x0, x1, x2, x3 = 0, 1, 2, 3
        rk = 0xABCDEF01
        result = self.sm4F(x0, x1, x2, x3, rk)
        self.assertIsInstance(result, int)

    def test_sm4Lt_basic(self):
        """sm4Lt linear transform basic test."""
        ka = 0x01234567
        result = self.sm4Lt(ka)
        self.assertIsInstance(result, int)

    def test_sm4CalciRK_basic(self):
        """sm4CalciRK round key calculation basic test."""
        ka = 0x01234567
        result = self.sm4CalciRK(ka)
        self.assertIsInstance(result, int)

    # ---- Key schedule ----

    def test_key_schedule_length(self):
        sm4 = self.Sm4()
        sm4.set_key(b'\x00' * 16, self.ENCRYPT)
        self.assertEqual(len(sm4.sk), 32)

    def test_key_schedule_reversibility(self):
        """Forward and reverse key schedules should be symmetric."""
        key = bytes.fromhex(self.ECB_KEY)
        sm4_enc = self.Sm4()
        sm4_enc.set_key(key, self.ENCRYPT)
        sm4_dec = self.Sm4()
        sm4_dec.set_key(key, self.DECRYPT)
        self.assertEqual(list(reversed(sm4_enc.sk)), sm4_dec.sk)

    # ---- ECB exact match (using one_round directly, no padding) ----

    def test_ecb_raw_standard_vector(self):
        """Raw single-block ECB without padding: exact match."""
        from pysmx.SM4._SM4 import (
            Sm4, ENCRYPT as E, DECRYPT as D, sm4F, sm4CalciRK,
            FK, CK, XOR, GET_UINT32_BE, PUT_UINT32_BE,
        )
        import struct

        key = bytes.fromhex(self.ECB_KEY)
        plaintext = bytes.fromhex(self.ECB_PLAINTEXT)

        # Manual key schedule
        k = [0] * 36
        MK = struct.unpack_from(">IIII", key)
        k[0:4] = list(mk ^ fk for mk, fk in zip(MK, FK))
        item = k[1] ^ k[2]
        for i in range(32):
            item ^= k[i + 3]
            k[i + 4] = k[i] ^ sm4CalciRK(item ^ CK[i])
            item ^= k[i + 1]
        sk = k[4:]

        # Manual one_round encrypt
        from functools import reduce
        item = list(struct.unpack_from(">IIII", plaintext))
        item.reverse()
        res = reduce(
            lambda x, y: [sm4F(x[3], x[2], x[1], x[0], y),
                          x[0], x[1], x[2]],
            sk, item
        )
        rev = b''.join(map(lambda i: struct.pack(">I", i), res))
        self.assertEqual(rev.hex(), self.ECB_CIPHERTEXT)


if __name__ == '__main__':
    unittest.main()
