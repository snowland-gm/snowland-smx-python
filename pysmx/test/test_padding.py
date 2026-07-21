import unittest
from pysmx.common._padding import *

class TestPadding(unittest.TestCase):

    block_size=8

    def test_pcsk7(self):
        a = bytes.fromhex('FF FF FF FF FF FF FF FF FF')
        b = bytes.fromhex('FF FF FF FF FF FF FF FF')

        s1 = PKCS7Padding(a, self.block_size)
        s2 = PKCS7UnPadding(s1, self.block_size)
        self.assertEqual(s2, a)
        self.assertEqual(s1, bytes.fromhex('FF FF FF FF FF FF FF FF FF 07 07 07 07 07 07 07'))

        s1 = PKCS7Padding(b, self.block_size)
        s2 = PKCS7UnPadding(s1, self.block_size)
        self.assertEqual(s2, b)
        self.assertEqual(s1, bytes.fromhex('FF FF FF FF FF FF FF FF 08 08 08 08 08 08 08 08'))

    def test_iso10126(self):
        a = bytes.fromhex('FF FF FF FF FF FF FF FF FF')
        b = bytes.fromhex('FF FF FF FF FF FF FF FF')

        s1 = ISO10126Padding(a, self.block_size)
        s2 = ISO10126UnPadding(s1, self.block_size)
        self.assertEqual(s2, a)
        self.assertEqual(s1, bytes.fromhex('FF FF FF FF FF FF FF FF FF 00 00 00 00 00 00 07'))

        s1 = ISO10126Padding(b, self.block_size)
        s2 = ISO10126UnPadding(s1, self.block_size)
        self.assertEqual(s2, b)
        self.assertEqual(s1, bytes.fromhex('FF FF FF FF FF FF FF FF 00 00 00 00 00 00 00 08'))

    def test_zero(self):
        a = bytes.fromhex('FF FF FF FF FF FF FF FF FF')
        b = bytes.fromhex('FF FF FF FF FF FF FF FF')

        s1 = ZeroPadding(a, self.block_size)
        s2 = ZeroUnPadding(s1, self.block_size)
        self.assertEqual(s2, a)
        self.assertEqual(s1, bytes.fromhex('FF FF FF FF FF FF FF FF FF 00 00 00 00 00 00 00'))

        s1 = ZeroPadding(b, self.block_size)
        s2 = ZeroUnPadding(s1, self.block_size)
        self.assertEqual(s2, b)
        self.assertEqual(s1, bytes.fromhex('FF FF FF FF FF FF FF FF'))
