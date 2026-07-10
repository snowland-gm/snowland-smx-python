#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SM4Stream streaming encryption/decryption conformance tests

import unittest
import os


class TestSM4Stream(unittest.TestCase):
    """SM4Stream: streaming API matches one-shot API for all 5 modes."""

    KEY = b'0123456789abcdef'
    IV = b'abcdef0123456789'

    def setUp(self):
        from pysmx.SM4 import Sm4, SM4Stream, ENCRYPT, DECRYPT
        self.Sm4 = Sm4
        self.SM4Stream = SM4Stream
        self.ENCRYPT = ENCRYPT
        self.DECRYPT = DECRYPT
        # Random non-aligned data: 12345 bytes (not multiple of 16)
        self.nonaligned_data = bytes([
            b % 256 for b in range(12345)
        ])

    # -- Helpers --

    def _one_shot_encrypt(self, key, iv, data, method):
        sm4 = self.Sm4()
        sm4.set_key(key, self.ENCRYPT)
        if method == 'ecb':
            return sm4.crypt_ecb(data)
        elif method == 'cbc':
            return sm4.crypt_cbc(iv, data)
        elif method == 'cfb':
            return sm4.crypt_cfb(iv, data)
        elif method == 'ofb':
            return sm4.crypt_ofb(iv, data)
        elif method == 'pcbc':
            return sm4.crypt_pcbc(iv, data)

    def _one_shot_decrypt(self, key, iv, data, method):
        sm4 = self.Sm4()
        sm4.set_key(key, self.DECRYPT)
        if method == 'ecb':
            return sm4.crypt_ecb(data)
        elif method == 'cbc':
            return sm4.crypt_cbc(iv, data)
        elif method == 'cfb':
            return sm4.crypt_cfb(iv, data)
        elif method == 'ofb':
            return sm4.crypt_ofb(iv, data)
        elif method == 'pcbc':
            return sm4.crypt_pcbc(iv, data)

    def _streaming_encrypt(self, key, iv, data, method, chunk_size):
        stream = self.SM4Stream(key, self.ENCRYPT, iv, method=method)
        result = b''
        for i in range(0, len(data), chunk_size):
            result += stream.update(data[i:i + chunk_size])
        result += stream.finalize()
        return result

    def _streaming_decrypt(self, key, iv, data, method, chunk_size):
        stream = self.SM4Stream(key, self.DECRYPT, iv, method=method)
        result = b''
        for i in range(0, len(data), chunk_size):
            result += stream.update(data[i:i + chunk_size])
        result += stream.finalize()
        return result

    # -- Encrypt: streaming == one-shot --

    def _test_encrypt_consistency(self, method, data, chunk_size):
        key, iv = self.KEY, self.IV
        ct_one_shot = self._one_shot_encrypt(key, iv, data, method)
        ct_stream = self._streaming_encrypt(key, iv, data, method, chunk_size)
        self.assertEqual(
            ct_stream, ct_one_shot,
            "%s encrypt mismatch (chunk=%d)" % (method.upper(), chunk_size)
        )

    def test_ecb_encrypt_consistency_1000(self):
        self._test_encrypt_consistency('ecb', self.nonaligned_data, 1000)

    def test_cbc_encrypt_consistency_1000(self):
        self._test_encrypt_consistency('cbc', self.nonaligned_data, 1000)

    def test_cfb_encrypt_consistency_1000(self):
        self._test_encrypt_consistency('cfb', self.nonaligned_data, 1000)

    def test_ofb_encrypt_consistency_1000(self):
        self._test_encrypt_consistency('ofb', self.nonaligned_data, 1000)

    def test_pcbc_encrypt_consistency_1000(self):
        self._test_encrypt_consistency('pcbc', self.nonaligned_data, 1000)

    def test_ecb_encrypt_consistency_997(self):
        self._test_encrypt_consistency('ecb', self.nonaligned_data, 997)

    def test_cbc_encrypt_consistency_997(self):
        self._test_encrypt_consistency('cbc', self.nonaligned_data, 997)

    def test_cfb_encrypt_consistency_997(self):
        self._test_encrypt_consistency('cfb', self.nonaligned_data, 997)

    def test_ofb_encrypt_consistency_997(self):
        self._test_encrypt_consistency('ofb', self.nonaligned_data, 997)

    def test_pcbc_encrypt_consistency_997(self):
        self._test_encrypt_consistency('pcbc', self.nonaligned_data, 997)

    # -- Decrypt: streaming == one-shot --

    def _test_decrypt_consistency(self, method, data, chunk_size):
        key, iv = self.KEY, self.IV
        ct = self._one_shot_encrypt(key, iv, data, method)
        pt_one_shot = self._one_shot_decrypt(key, iv, ct, method)
        pt_stream = self._streaming_decrypt(key, iv, ct, method, chunk_size)
        self.assertEqual(
            pt_stream, pt_one_shot,
            "%s decrypt mismatch (chunk=%d)" % (method.upper(), chunk_size)
        )
        self.assertEqual(
            pt_stream, data,
            "%s roundtrip failed (chunk=%d)" % (method.upper(), chunk_size)
        )

    def test_ecb_decrypt_consistency_777(self):
        self._test_decrypt_consistency('ecb', self.nonaligned_data, 777)

    def test_cbc_decrypt_consistency_777(self):
        self._test_decrypt_consistency('cbc', self.nonaligned_data, 777)

    def test_cfb_decrypt_consistency_777(self):
        self._test_decrypt_consistency('cfb', self.nonaligned_data, 777)

    def test_ofb_decrypt_consistency_777(self):
        self._test_decrypt_consistency('ofb', self.nonaligned_data, 777)

    def test_pcbc_decrypt_consistency_777(self):
        self._test_decrypt_consistency('pcbc', self.nonaligned_data, 777)

    def test_ecb_decrypt_consistency_511(self):
        self._test_decrypt_consistency('ecb', self.nonaligned_data, 511)

    def test_cbc_decrypt_consistency_511(self):
        self._test_decrypt_consistency('cbc', self.nonaligned_data, 511)

    def test_cfb_decrypt_consistency_511(self):
        self._test_decrypt_consistency('cfb', self.nonaligned_data, 511)

    def test_ofb_decrypt_consistency_511(self):
        self._test_decrypt_consistency('ofb', self.nonaligned_data, 511)

    def test_pcbc_decrypt_consistency_511(self):
        self._test_decrypt_consistency('pcbc', self.nonaligned_data, 511)

    # -- Exact block-aligned data --

    def test_aligned_data_roundtrip(self):
        """Block-aligned data (32 bytes) roundtrip for all modes."""
        data = b'Hello SM4 World!!' * 2  # 32 bytes
        for method in ('ecb', 'cbc', 'cfb', 'ofb', 'pcbc'):
            with self.subTest(method=method):
                ct = self._streaming_encrypt(
                    self.KEY, self.IV, data, method, 16)
                pt = self._streaming_decrypt(
                    self.KEY, self.IV, ct, method, 16)
                self.assertEqual(pt, data, "%s aligned roundtrip failed" % method)

    # -- Single-byte chunks (edge case) --

    def test_single_byte_chunks(self):
        """Encrypt/decrypt with 1-byte chunk size."""
        data = b'Stream test data with single byte chunks'
        for method in ('ecb', 'cbc', 'cfb', 'ofb', 'pcbc'):
            with self.subTest(method=method):
                ct = self._streaming_encrypt(
                    self.KEY, self.IV, data, method, 1)
                pt = self._streaming_decrypt(
                    self.KEY, self.IV, ct, method, 1)
                self.assertEqual(pt, data, "%s single-byte roundtrip failed" % method)

    # -- Empty data --

    def test_empty_update(self):
        """update(b'') should return b''."""
        for method in ('ecb', 'cbc', 'cfb', 'ofb', 'pcbc'):
            with self.subTest(method=method):
                stream = self.SM4Stream(self.KEY, self.ENCRYPT, self.IV, method=method)
                self.assertEqual(stream.update(b''), b'')
                result = stream.finalize()
                # Finalize with empty data: PKCS5 padding adds a full block
                self.assertEqual(len(result), 16)

    # -- Cross-mode: encrypt with one, decrypt with another should differ --

    def test_cross_iv_cfb(self):
        """CFB: wrong IV produces different decrypt output."""
        wrong_iv = b'\xFF' * 16
        data = b'Cross IV test for CFB mode!!!'
        ct = self._streaming_encrypt(self.KEY, self.IV, data, 'cfb', 10)
        pt_wrong = self._streaming_decrypt(self.KEY, wrong_iv, ct, 'cfb', 10)
        self.assertNotEqual(pt_wrong[:16], data[:16])

    def test_cross_iv_ofb(self):
        """OFB: wrong IV produces different decrypt output."""
        wrong_iv = b'\xFF' * 16
        data = b'Cross IV test for OFB mode!!!'
        ct = self._streaming_encrypt(self.KEY, self.IV, data, 'ofb', 10)
        pt_wrong = self._streaming_decrypt(self.KEY, wrong_iv, ct, 'ofb', 10)
        self.assertNotEqual(pt_wrong[:16], data[:16])

    # -- Constructor validation --

    def test_invalid_method(self):
        """Invalid method raises ValueError."""
        with self.assertRaises(ValueError):
            self.SM4Stream(self.KEY, self.ENCRYPT, self.IV, method='xxx')

    def test_ecb_ignores_iv(self):
        """ECB mode produces same result regardless of IV."""
        data = b'ECB ignores IV test!'
        ct1 = self._streaming_encrypt(self.KEY, b'\x00' * 16, data, 'ecb', 8)
        ct2 = self._streaming_encrypt(self.KEY, b'\xFF' * 16, data, 'ecb', 8)
        self.assertEqual(ct1, ct2)


if __name__ == '__main__':
    unittest.main()
