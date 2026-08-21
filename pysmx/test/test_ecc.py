#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for pysmx.ecc (finite field FQ/FQP and elliptic curve ops).

These cover the pure-math primitives that SM2/SM9 build upon. They use
known algebraic identities and small scalar multiplications rather than
a full pairing, so they stay fast and dependency-free.
"""

import unittest

from pysmx.ecc import fq
from pysmx.ecc import ec


class TestFQ(unittest.TestCase):
    """Prime field element arithmetic (FQ over field_modulus)."""

    def test_mod_reduction(self):
        self.assertEqual(fq.FQ(fq.field_modulus).n, 0)
        self.assertEqual(fq.FQ(fq.field_modulus + 5).n, 5)
        self.assertEqual(fq.FQ(-1).n, fq.field_modulus - 1)

    def test_add_sub(self):
        a = fq.FQ(7)
        b = fq.FQ(3)
        self.assertEqual((a + b).n, 10 % fq.field_modulus)
        self.assertEqual((a - b).n, 4)
        self.assertEqual((b - a).n, fq.field_modulus - 4)
        # reflection methods
        self.assertEqual((3 + a).n, (a + 3).n)
        self.assertEqual((3 - a).n, (a.__rsub__(3)).n)

    def test_mul(self):
        a = fq.FQ(123456789)
        b = fq.FQ(987654321)
        self.assertEqual((a * b).n, (123456789 * 987654321) % fq.field_modulus)
        self.assertEqual((5 * a).n, (a * 5).n)

    def test_mul_negative(self):
        a = fq.FQ(10)
        self.assertEqual((a * -1).n, fq.field_modulus - 10)

    def test_pow(self):
        a = fq.FQ(2)
        self.assertEqual(a ** 0, fq.FQ(1))
        self.assertEqual(a ** 1, fq.FQ(2))
        self.assertEqual(a ** 3, fq.FQ(8))
        # Fermat's little theorem: a**(p-1) == 1
        self.assertEqual(a ** (fq.field_modulus - 1), fq.FQ(1))

    def test_inv(self):
        a = fq.FQ(12345)
        inv = fq.prime_field_inv(12345, fq.field_modulus)
        self.assertEqual((a * inv), fq.FQ(1))
        # 0 inverse is defined as 0 in this implementation
        self.assertEqual(fq.prime_field_inv(0, fq.field_modulus), 0)

    def test_div(self):
        a = fq.FQ(100)
        b = fq.FQ(4)
        self.assertEqual((a / 4).n, 25)
        self.assertEqual((a / b) * b, a)

    def test_eq_neq_neg(self):
        a = fq.FQ(5)
        self.assertEqual(a, 5)
        self.assertEqual(a, fq.FQ(5))
        self.assertNotEqual(a, 6)
        self.assertEqual(-a, fq.FQ(fq.field_modulus - 5))

    def test_one_zero(self):
        self.assertEqual(fq.FQ.one(), fq.FQ(1))
        self.assertEqual(fq.FQ.zero(), fq.FQ(0))


class TestFQP(unittest.TestCase):
    """Extension field FQP / FQ2 / FQ12 arithmetic."""

    def test_fq2_add_sub_mul(self):
        a = fq.FQ2([1, 2])
        b = fq.FQ2([3, 4])
        self.assertEqual((a + b).coeffs, [4, 6])
        self.assertEqual((a - b).coeffs, [fq.field_modulus - 2, fq.field_modulus - 2])
        # (1 + 2i) * (3 + 4i) = 3 + 4i + 6i + 8i^2, i^2 = -1 -> -5 + 10i
        prod = (a * b).coeffs
        self.assertEqual(prod[0], fq.field_modulus - 5)
        self.assertEqual(prod[1], 10)

    def test_fq2_inv(self):
        a = fq.FQ2([2, 3])
        inv = a.inv()
        one = (a * inv)
        self.assertEqual(one.coeffs[0], 1)
        self.assertEqual(one.coeffs[1], 0)

    def test_fq2_scalar_mul(self):
        a = fq.FQ2([2, 3])
        self.assertEqual((a * 2).coeffs, [4, 6])

    def test_fq2_pow(self):
        a = fq.FQ2([2, 0])
        self.assertEqual((a ** 0).coeffs, [1, 0])
        self.assertEqual((a ** 3).coeffs, [8, 0])

    def test_fq2_eq_neg(self):
        a = fq.FQ2([1, 2])
        # __neg__ returns the raw negated form [-1, -2]; it is equal to the
        # modulo-reduced representation because FQ2.__eq__ works element-wise.
        self.assertEqual(-a, fq.FQ2([-1, -2]))
        self.assertEqual(a, fq.FQ2([1, 2]))
        self.assertNotEqual(a, fq.FQ2([1, 3]))

    def test_fq12_identity(self):
        one = fq.FQ12.one()
        self.assertEqual(one.coeffs, [1] + [0] * 11)
        zero = fq.FQ12.zero()
        self.assertEqual(zero.coeffs, [0] * 12)

    def test_fq12_mul_identity(self):
        a = fq.FQ12([2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37])
        one = fq.FQ12.one()
        self.assertEqual((a * one).coeffs, a.coeffs)

    def test_fq12_pow(self):
        a = fq.FQ12([2] + [0] * 11)
        self.assertEqual((a ** 5).coeffs[0], 32 % fq.field_modulus)


class TestEC(unittest.TestCase):
    """Elliptic curve point operations on the SM9 pairing-friendly curve."""

    def test_generators_on_curve(self):
        self.assertTrue(ec.is_on_curve(ec.G1, ec.b))
        self.assertTrue(ec.is_on_curve(ec.G2, ec.b2))

    def test_double(self):
        d = ec.double(ec.G1)
        self.assertTrue(ec.is_on_curve(d, ec.b))
        # 2G == multiply(G, 2)
        self.assertTrue(ec.eq(d, ec.multiply(ec.G1, 2)))

    def test_add(self):
        # G1 + G1 == double(G1)
        self.assertTrue(ec.eq(ec.add(ec.G1, ec.G1), ec.double(ec.G1)))
        # add with point at infinity is identity
        inf = (ec.G1[0].__class__.one(), ec.G1[0].__class__.one(), ec.G1[0].__class__.zero())
        self.assertTrue(ec.eq(ec.add(ec.G1, inf), ec.G1))

    def test_multiply_basic(self):
        for n in (0, 1, 2, 3, 5, 16, 123):
            p = ec.multiply(ec.G1, n)
            self.assertTrue(ec.is_on_curve(p, ec.b))

    def test_multiply_zero_is_infinity(self):
        inf = ec.multiply(ec.G1, 0)
        self.assertTrue(ec.is_inf(inf))

    def test_multiply_identity(self):
        self.assertTrue(ec.eq(ec.multiply(ec.G1, 1), ec.G1))

    def test_neg(self):
        neg_g = ec.neg(ec.G1)
        self.assertTrue(ec.eq(ec.add(ec.G1, neg_g), ec.multiply(ec.G1, 0)))

    def test_normalize(self):
        # normalize(double(G)) stays on the affine curve
        p = ec.normalize(ec.double(ec.G1))
        x, y = p
        self.assertEqual(y ** 2, x ** 3 + ec.b)

    def test_twist_on_curve(self):
        self.assertTrue(ec.is_on_curve(ec.G12, ec.b12))

    def test_multiply_consistency(self):
        # scalar multiplication is deterministic
        a = ec.multiply(ec.G1, 777)
        b = ec.multiply(ec.G1, 777)
        self.assertTrue(ec.eq(a, b))

    def test_g2_multiply_on_curve(self):
        self.assertTrue(ec.is_on_curve(ec.multiply(ec.G2, 42), ec.b2))


if __name__ == '__main__':
    unittest.main()
