#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @contact: astar@snowland.ltd
# @file: _SM9.py
# @time: 2018/10/20 17:23
# @Software: PyCharm
#
# SM9 Identity-Based Cryptographic Algorithm (GM/T 0044-2016)
# Based on BN (Barreto-Naehrig) curve with 256-bit security.
#

import os

from pysmx.SM3 import KDF as _sm3_KDF
from pysmx.crypto.hashlib import new as _hash_new

# ============================================================
# SM9 BN Curve Parameters (GM/T 0044.5-2016)
# ============================================================

_sm9_q = int(
    'B640000002A3A6F1D603AB4FF58EC745'
    '21F2934B1A7AEEDBE56F9B27E351457D', 16
)  # field characteristic

_sm9_N = int(
    'B640000002A3A6F1D603AB4FF58EC744'
    '49F2934B18EA8BEEE56EE19CD69ECF25', 16
)  # group order

_sm9_t = 0x600000000058F98A  # trace of Frobenius

_sm9_b = 5  # curve parameter b (a=0)

# G1 generator (affine, hex)
_sm9_P1x = int(
    '93DE051D62BF718FF5ED0704487D01D6'
    'E1E4086909DC3280E8C4E4817C66DDDD', 16
)
_sm9_P1y = int(
    '21FE8DDA4F21E607631065125C395BBC'
    '1C1C00CBFA6024350C464CD70A3EA616', 16
)

# G2 generator (affine on twisted curve, Fp2 elements as hex)
# P2x = (x_a, x_b) in Fp2, P2y = (y_a, y_b)
_sm9_P2 = (
    int(
        '85AEF3D078640C98597B60277B41A01F'
        'F1DD2C190F5E93C454806C11D8806141', 16
    ),
    int(
        '3722755292130B08D2AAB97FD34EC120'
        'EE265948D19C17ABF9B7213BAF82D65B', 16
    ),
    int(
        '17509B092E845C1266BA0D262CBEE6ED'
        '0736A96FA347C8BD856DC76B84EBEB96', 16
    ),
    int(
        'A7CF28D519BE3DA65F3170153D278FF2'
        '47EFBA98A71A08116215BBA5C999A7C7', 16
    ),
)

# a = 0 for SM9 curve
_sm9_a = 0

# ============================================================
# Precomputed values
# ============================================================

# Quadratic non-residue for Fp2: alpha = 2
# (for p ≡ 5 mod 8, 2 is a QNR)
_ALPHA = 2

# Fp2 representation: (a0, a1) for a0 + a1*u where u^2 = alpha = 2
# Fp6 = Fp2[v]/(v^3 - u)  → element = (a0, a1, a2) where each is Fp2
# Fp12 = Fp6[w]/(w^2 - v) → element = (a0, a1) where each is Fp6

# Twist curve parameter: b_twist = 5 / u = 5 * u^(-1) in Fp2
# u^(-1) = (0, inv(2)) because u = (0,1), u*(0,inv(2)) = (2*inv(2), 0) = (1,0)
_INV2 = pow(2, _sm9_q - 2, _sm9_q)
_B_TWIST_A0 = 0
_B_TWIST_A1 = (5 * _INV2) % _sm9_q  # b' = (0, 5/2)
_B_TWIST = (_B_TWIST_A0, _B_TWIST_A1)

# Final exponentiation exponents
_Q6_MINUS_1 = pow(_sm9_q, 6) - 1
_Q2_PLUS_1 = pow(_sm9_q, 2) + 1
_Q4_MINUS_Q2_PLUS_1_DIV_N = (pow(_sm9_q, 4) - pow(_sm9_q, 2) + 1) // _sm9_N

# Zero / One in various fields
_FP2_ZERO = (0, 0)
_FP2_ONE = (1, 0)
_FP6_ZERO = (_FP2_ZERO, _FP2_ZERO, _FP2_ZERO)
_FP6_ONE = (_FP2_ONE, _FP2_ZERO, _FP2_ZERO)
_FP12_ZERO = (_FP6_ZERO, _FP6_ZERO)
_FP12_ONE = (_FP6_ONE, _FP6_ZERO)

# Precomputed Frobenius constants
# beta = alpha^((q-1)/6) → v^q = v * beta
_BETA = pow(_ALPHA, (_sm9_q - 1) // 6, _sm9_q)
_BETA_SQ = (_BETA * _BETA) % _sm9_q
_BETA_QU = (_BETA_SQ * _BETA_SQ) % _sm9_q
# gamma = alpha^((q-1)/12) → w^q = w * gamma
_GAMMA = pow(_ALPHA, (_sm9_q - 1) // 12, _sm9_q)
_GAMMA_SQ = (_GAMMA * _GAMMA) % _sm9_q
_GAMMA_3 = (_GAMMA_SQ * _GAMMA) % _sm9_q

# Lazy init flag
_SM9_READY = True


# ============================================================
# Fp2 Arithmetic  (a0 + a1*u,  u^2 = ALPHA = 2)
# ============================================================

def _fp2_add(a, b):
    return ((a[0] + b[0]) % _sm9_q, (a[1] + b[1]) % _sm9_q)


def _fp2_sub(a, b):
    return ((a[0] - b[0]) % _sm9_q, (a[1] - b[1]) % _sm9_q)


def _fp2_neg(a):
    return ((-a[0]) % _sm9_q, (-a[1]) % _sm9_q)


def _fp2_mul(a, b):
    # (a0+a1*u)(b0+b1*u) = a0*b0 + alpha*a1*b1 + (a0*b1 + a1*b0)*u
    a0b0 = (a[0] * b[0]) % _sm9_q
    a1b1 = (a[1] * b[1]) % _sm9_q
    return (
        (a0b0 + _ALPHA * a1b1) % _sm9_q,
        ((a[0] + a[1]) * (b[0] + b[1]) - a0b0 - a1b1) % _sm9_q
    )


def _fp2_mul_fp(a, k):
    # (a0 + a1*u) * k
    return ((a[0] * k) % _sm9_q, (a[1] * k) % _sm9_q)


def _fp2_sqr(a):
    # (a0+a1*u)^2 = a0^2 + alpha*a1^2 + 2*a0*a1*u
    a0 = a[0]
    a1 = a[1]
    return (
        (a0 * a0 + _ALPHA * a1 * a1) % _sm9_q,
        (2 * a0 * a1) % _sm9_q
    )


def _fp2_inv(a):
    # (a0+a1*u)^(-1) = (a0 - a1*u) / (a0^2 - alpha*a1^2)
    t0 = (a[0] * a[0]) % _sm9_q
    t1 = (a[1] * a[1]) % _sm9_q
    denom_inv = pow((t0 - _ALPHA * t1) % _sm9_q, _sm9_q - 2, _sm9_q)
    return ((a[0] * denom_inv) % _sm9_q, ((-a[1]) * denom_inv) % _sm9_q)


def _fp2_conjugate(a):
    return (a[0], (-a[1]) % _sm9_q)


def _fp2_frobenius(a):
    # Frobenius map: (a0 + a1*u)^q = a0^q + a1^q * u^q
    # u^q = u * u^(q-1) = u * (u^2)^((q-1)/2) = u * alpha^((q-1)/2)
    # For alpha=2 and q ≡ 5 mod 8: 2^((q-1)/2) ≡ -1 mod q
    # So u^q = -u → Frobenius(a) = a0 - a1*u = conjugate
    return _fp2_conjugate(a)


def _fp2_frobenius2(a):
    return a  # u^(q^2) = u


def _fp2_frobenius3(a):
    return _fp2_conjugate(a)  # same as q


def _fp2_is_zero(a):
    return a[0] == 0 and a[1] == 0


def _fp2_eq(a, b):
    return a[0] == b[0] and a[1] == b[1]


# ============================================================
# Fp6 Arithmetic  (a0 + a1*v + a2*v^2,  v^3 = u = (0,1))
# ============================================================

def _fp6_add(a, b):
    return (
        _fp2_add(a[0], b[0]),
        _fp2_add(a[1], b[1]),
        _fp2_add(a[2], b[2]),
    )


def _fp6_sub(a, b):
    return (
        _fp2_sub(a[0], b[0]),
        _fp2_sub(a[1], b[1]),
        _fp2_sub(a[2], b[2]),
    )


def _fp6_neg(a):
    return (
        _fp2_neg(a[0]),
        _fp2_neg(a[1]),
        _fp2_neg(a[2]),
    )


def _fp6_mul(a, b):
    # (a0+a1v+a2v^2)(b0+b1v+b2v^2)
    # = a0*b0 + a0*b1*v + a0*b2*v^2
    # + a1*b0*v + a1*b1*v^2 + a1*b2*v^3
    # + a2*b0*v^2 + a2*b1*v^3 + a2*b2*v^4
    # v^3 = u = (0,1), v^4 = v*u
    a0, a1, a2 = a
    b0, b1, b2 = b

    a0b0 = _fp2_mul(a0, b0)
    a0b1 = _fp2_mul(a0, b1)
    a0b2 = _fp2_mul(a0, b2)
    a1b0 = _fp2_mul(a1, b0)
    a1b1 = _fp2_mul(a1, b1)
    a1b2 = _fp2_mul(a1, b2)
    a2b0 = _fp2_mul(a2, b0)
    a2b1 = _fp2_mul(a2, b1)
    a2b2 = _fp2_mul(a2, b2)

    # v^3 = u = (0, 1)
    # Contribution from a1*b2 and a2*b1 (v^3 terms): (a1*b2 + a2*b1)*u
    c0 = _fp2_add(a0b0, _fp2_mul(_fp2_add(a1b2, a2b1), (0, 1)))

    # v^4 = v*u → a2*b2 * v*u
    c1 = _fp2_add(_fp2_add(a0b1, a1b0), _fp2_mul(a2b2, (0, 1)))

    c2 = _fp2_add(_fp2_add(a0b2, a1b1), a2b0)

    return (c0, c1, c2)


def _fp6_mul_fp2(a, b):
    # Multiply Fp6 element by Fp2 scalar
    return (
        _fp2_mul(a[0], b),
        _fp2_mul(a[1], b),
        _fp2_mul(a[2], b),
    )


def _fp6_sqr(a):
    a0, a1, a2 = a
    # (a0 + a1*v + a2*v^2)^2
    # = a0^2 + 2*a0*a1*v + 2*a0*a2*v^2 + a1^2*v^2 + 2*a1*a2*v^3 + a2^2*v^4
    # = (a0^2 + 2*a1*a2*u) + (2*a0*a1 + a2^2*u)*v + (2*a0*a2 + a1^2)*v^2
    a0_sq = _fp2_sqr(a0)
    a1_sq = _fp2_sqr(a1)
    a2_sq = _fp2_sqr(a2)

    two_a0_a1 = _fp2_mul_fp(_fp2_mul(a0, a1), 2)
    two_a0_a2 = _fp2_mul_fp(_fp2_mul(a0, a2), 2)
    two_a1_a2 = _fp2_mul_fp(_fp2_mul(a1, a2), 2)

    u = (0, 1)
    c0 = _fp2_add(a0_sq, _fp2_mul(two_a1_a2, u))
    c1 = _fp2_add(two_a0_a1, _fp2_mul(a2_sq, u))
    c2 = _fp2_add(two_a0_a2, a1_sq)

    return (c0, c1, c2)


_Q6_MINUS_2 = pow(_sm9_q, 6) - 2  # for Fp6 inversion via exponentiation


def _fp6_inv(a):
    """Fp6 inverse: a^(-1) = a^(q^6 - 2) by binary exponentiation."""
    if _fp6_is_zero(a):
        raise ZeroDivisionError("Cannot invert zero Fp6 element")
    result = _FP6_ONE
    base = a
    e = _Q6_MINUS_2
    while e > 0:
        if e & 1:
            result = _fp6_mul(result, base)
        base = _fp6_sqr(base)
        e >>= 1
    return result


def _fp6_is_zero(a):
    return _fp2_is_zero(a[0]) and _fp2_is_zero(a[1]) and _fp2_is_zero(a[2])


def _fp6_frobenius(a):
    """Frobenius map on Fp6: (a0+a1*v+a2*v^2)^q.
    v^q = v * beta where beta = alpha^((q-1)/6) = primitive 6th root of unity.
    """
    a0 = _fp2_frobenius(a[0])
    a1 = _fp2_frobenius(a[1])
    a2 = _fp2_frobenius(a[2])
    return (
        a0,
        _fp2_mul_fp(a1, _BETA),
        _fp2_mul_fp(a2, _BETA_SQ),
    )


def _fp6_frobenius2(a):
    """Frobenius^2: raise to q^2. v^(q^2) = v * beta^2"""
    a0 = _fp2_frobenius2(a[0])
    a1 = _fp2_frobenius2(a[1])
    a2 = _fp2_frobenius2(a[2])
    return (
        a0,
        _fp2_mul_fp(a1, _BETA_SQ),
        _fp2_mul_fp(a2, _BETA_QU),
    )


def _fp6_frobenius3(a):
    """Frobenius^3: raise to q^3. v^(q^3) = v * beta^3 = v * (-1)"""
    a0 = _fp2_frobenius3(a[0])
    a1 = _fp2_frobenius3(a[1])
    a2 = _fp2_frobenius3(a[2])
    beta_3 = (_BETA * _BETA_SQ) % _sm9_q  # beta^3 = -1
    beta_6 = (_BETA_SQ * _BETA_QU) % _sm9_q  # beta^6 = 1
    return (
        a0,
        _fp2_mul_fp(a1, beta_3),
        _fp2_mul_fp(a2, beta_6),
    )


# ============================================================
# Fp12 Arithmetic  (a0 + a1*w,  w^2 = v)
# ============================================================

def _fp12_add(a, b):
    return (_fp6_add(a[0], b[0]), _fp6_add(a[1], b[1]))


def _fp12_sub(a, b):
    return (_fp6_sub(a[0], b[0]), _fp6_sub(a[1], b[1]))


def _fp12_neg(a):
    return (_fp6_neg(a[0]), _fp6_neg(a[1]))


def _fp12_mul(a, b):
    # (a0 + a1*w)(b0 + b1*w) = a0*b0 + a1*b1*v + (a0*b1 + a1*b0)*w
    a0b0 = _fp6_mul(a[0], b[0])
    a1b1 = _fp6_mul(a[1], b[1])
    v = (_FP2_ZERO, _FP2_ONE, _FP2_ZERO)  # v = (0, 1, 0) in Fp6

    real = _fp6_add(a0b0, _fp6_mul(a1b1, v))
    imag = _fp6_add(_fp6_mul(a[0], b[1]), _fp6_mul(a[1], b[0]))

    return (real, imag)


def _fp12_sqr(a):
    # (a0 + a1*w)^2 = a0^2 + a1^2*v + 2*a0*a1*w
    a0_sq = _fp6_sqr(a[0])
    a1_sq = _fp6_sqr(a[1])
    v = (_FP2_ZERO, _FP2_ONE, _FP2_ZERO)
    two_a0_a1 = _fp6_add(_fp6_mul(a[0], a[1]), _fp6_mul(a[0], a[1]))

    real = _fp6_add(a0_sq, _fp6_mul(a1_sq, v))
    imag = two_a0_a1

    return (real, imag)


def _fp12_inv(a):
    # (a0 + a1*w)^(-1) = (a0 - a1*w) / (a0^2 - a1^2*v)
    v = (_FP2_ZERO, _FP2_ONE, _FP2_ZERO)
    a0_sq = _fp6_sqr(a[0])
    a1_sq_v = _fp6_mul(_fp6_sqr(a[1]), v)
    denom = _fp6_sub(a0_sq, a1_sq_v)
    denom_inv = _fp6_inv(denom)

    return (
        _fp6_mul(a[0], denom_inv),
        _fp6_mul(_fp6_neg(a[1]), denom_inv),
    )


def _fp12_conjugate(a):
    return (a[0], _fp6_neg(a[1]))


def _fp12_frobenius(a):
    """Frobenius: raise to q. w^q = w * gamma where gamma = alpha^((q-1)/12)"""
    real = _fp6_frobenius(a[0])
    imag = _fp6_frobenius(a[1])
    return (real, _fp6_mul_fp2(imag, (_GAMMA, 0)))


def _fp12_frobenius2(a):
    """Frobenius^2: raise to q^2. w^(q^2) = w * gamma^2"""
    real = _fp6_frobenius2(a[0])
    imag = _fp6_frobenius2(a[1])
    return (real, _fp6_mul_fp2(imag, (_GAMMA_SQ, 0)))


def _fp12_frobenius3(a):
    """Frobenius^3: raise to q^3. w^(q^3) = w * gamma^3"""
    real = _fp6_frobenius3(a[0])
    imag = _fp6_frobenius3(a[1])
    return (real, _fp6_mul_fp2(imag, (_GAMMA_3, 0)))


def _fp12_frobenius6(a):
    # w^(q^6) = -w (for BN curves) → conjugate
    return _fp12_conjugate(a)


def _fp12_pow(a, exp):
    """Binary exponentiation in Fp12."""
    if exp == 0:
        return _FP12_ONE
    if exp == 1:
        return a

    result = _FP12_ONE
    base = a
    e = exp
    while e > 0:
        if e & 1:
            result = _fp12_mul(result, base)
        base = _fp12_sqr(base)
        e >>= 1
    return result


def _fp12_is_one(a):
    return _fp6_eq(a[0], _FP6_ONE) and _fp6_eq(a[1], _FP6_ZERO)


def _fp6_eq(a, b):
    return _fp2_eq(a[0], b[0]) and _fp2_eq(a[1], b[1]) and _fp2_eq(a[2], b[2])


# ============================================================
# G1 Point Arithmetic (over Fp, Jacobian coordinates)
# y^2 = x^3 + b
# ============================================================

def _g1_double(T):
    """Double G1 point in Jacobian: T = (X,Y,Z)"""
    X, Y, Z = T
    if Z == 0:
        return T  # point at infinity

    # T1 = Y^2
    T1 = (Y * Y) % _sm9_q
    # T2 = 4*X*T1
    T2 = (4 * X * T1) % _sm9_q
    # T3 = 8*T1^2
    T3 = (8 * T1 * T1) % _sm9_q
    # T4 = 3*X^2 + a*Z^4  (a=0 for SM9)
    T4 = (3 * X * X) % _sm9_q
    # X3 = T4^2 - 2*T2
    X3 = (T4 * T4 - 2 * T2) % _sm9_q
    # Y3 = T4*(T2 - X3) - T3
    Y3 = (T4 * (T2 - X3) - T3) % _sm9_q
    # Z3 = 2*Y*Z
    Z3 = (2 * Y * Z) % _sm9_q

    return (X3, Y3, Z3)


def _g1_add(T, P_aff):
    """Add G1 point T(Jacobian) + P(affine)"""
    X1, Y1, Z1 = T
    x2, y2 = P_aff
    if Z1 == 0:
        return (x2, y2, 1)

    # Z1^2
    Z1Z1 = (Z1 * Z1) % _sm9_q
    # U2 = x2 * Z1Z1
    U2 = (x2 * Z1Z1) % _sm9_q
    # S2 = y2 * Z1 * Z1Z1
    S2 = (y2 * Z1 % _sm9_q * Z1Z1) % _sm9_q
    # H = U2 - X1
    H = (U2 - X1) % _sm9_q
    if H == 0:
        if (S2 - Y1) % _sm9_q == 0:
            return _g1_double((x2, y2, 1))
        else:
            return (0, 0, 0)  # point at infinity
    # HH = H^2
    HH = (H * H) % _sm9_q
    # HHH = H * HH
    HHH = (H * HH) % _sm9_q
    # r = 2*(S2 - Y1)
    r = (2 * (S2 - Y1)) % _sm9_q
    # V = X1 * HH
    V = (X1 * HH) % _sm9_q
    # X3 = r^2 - HHH - 2*V
    X3 = (r * r - HHH - 2 * V) % _sm9_q
    # Y3 = r*(V - X3) - Y1*HHH
    Y3 = (r * (V - X3) - Y1 * HHH) % _sm9_q
    # Z3 = (Z1 + H)^2 - Z1Z1 - HH
    Z3 = ((Z1 + H) ** 2 - Z1Z1 - HH) % _sm9_q

    return (X3, Y3, Z3)


def _g1_scalar_mult(k, P_aff):
    """Scalar multiplication k*P for G1, k>0, P in affine."""
    if k == 0:
        return (0, 0, 0)

    bits = []
    e = k
    while e > 0:
        bits.append(e & 1)
        e >>= 1
    bits.reverse()

    X, Y, Z = 0, 0, 0
    x_p, y_p = P_aff

    for bit in bits:
        if Z != 0:
            X, Y, Z = _g1_double((X, Y, Z))

        if bit:
            if Z == 0:
                X, Y, Z = x_p, y_p, 1
            else:
                X, Y, Z = _g1_add((X, Y, Z), P_aff)

    return (X, Y, Z)


def _g1_to_affine(T):
    """Convert Jacobian to affine."""
    X, Y, Z = T
    if Z == 0:
        return (0, 0)
    Z_inv = pow(Z, _sm9_q - 2, _sm9_q)
    Z_inv2 = (Z_inv * Z_inv) % _sm9_q
    Z_inv3 = (Z_inv2 * Z_inv) % _sm9_q
    return ((X * Z_inv2) % _sm9_q, (Y * Z_inv3) % _sm9_q)


def _g1_is_on_curve(P_aff):
    """Check if affine point is on E: y^2 = x^3 + b"""
    x, y = P_aff
    if x == 0 and y == 0:
        return True  # point at infinity (by convention in this code)
    lhs = (y * y) % _sm9_q
    rhs = (x * x * x + _sm9_b) % _sm9_q
    return lhs == rhs


# ============================================================
# G2 Point Arithmetic (over Fp^2, twisted curve, Jacobian)
# y^2 = x^3 + b_twist
# ============================================================

def _g2_double(T):
    """Double G2 point in Jacobian."""
    X, Y, Z = T
    if _fp2_is_zero(Z):
        return T

    # T1 = Y^2
    T1 = _fp2_sqr(Y)
    # T2 = 4*X*T1
    T2 = _fp2_mul_fp(_fp2_mul(X, T1), 4)
    # T3 = 8*T1^2
    T3 = _fp2_mul_fp(_fp2_sqr(T1), 8)
    # T4 = 3*X^2 + a*Z^4  (a=0 for BN curve)
    T4 = _fp2_mul_fp(_fp2_sqr(X), 3)
    # X3 = T4^2 - 2*T2
    X3 = _fp2_sub(_fp2_sqr(T4), _fp2_mul_fp(T2, 2))
    # Y3 = T4*(T2 - X3) - T3
    Y3 = _fp2_sub(_fp2_mul(T4, _fp2_sub(T2, X3)), T3)
    # Z3 = 2*Y*Z
    Z3 = _fp2_mul_fp(_fp2_mul(Y, Z), 2)

    return (X3, Y3, Z3)


def _g2_add(T, P_aff):
    """Add G2 Jacobian point T + affine point P_aff."""
    X1, Y1, Z1 = T
    x2, y2 = P_aff
    if _fp2_is_zero(Z1):
        return (x2, y2, _FP2_ONE)

    Z1Z1 = _fp2_sqr(Z1)
    U2 = _fp2_mul(x2, Z1Z1)
    S2 = _fp2_mul(_fp2_mul(y2, Z1), Z1Z1)
    H = _fp2_sub(U2, X1)
    if _fp2_is_zero(H):
        if _fp2_eq(S2, Y1):
            return _g2_double((x2, y2, _FP2_ONE))
        else:
            return (_FP2_ZERO, _FP2_ZERO, _FP2_ZERO)

    HH = _fp2_sqr(H)
    HHH = _fp2_mul(H, HH)

    r = _fp2_mul_fp(_fp2_sub(S2, Y1), 2)
    V = _fp2_mul(X1, HH)

    X3 = _fp2_sub(_fp2_sub(_fp2_sqr(r), HHH), _fp2_mul_fp(V, 2))
    Y3 = _fp2_sub(_fp2_mul(r, _fp2_sub(V, X3)), _fp2_mul(Y1, HHH))

    Z1_H = _fp2_add(Z1, H)
    Z3 = _fp2_sub(_fp2_sub(_fp2_sqr(Z1_H), Z1Z1), HH)

    return (X3, Y3, Z3)


def _g2_to_affine(T):
    """Convert G2 Jacobian to affine."""
    X, Y, Z = T
    if _fp2_is_zero(Z):
        return (_FP2_ZERO, _FP2_ZERO)
    Z_inv = _fp2_inv(Z)
    Z_inv2 = _fp2_sqr(Z_inv)
    Z_inv3 = _fp2_mul(Z_inv2, Z_inv)
    return (_fp2_mul(X, Z_inv2), _fp2_mul(Y, Z_inv3))


def _g2_scalar_mult(k, P_aff):
    """Scalar multiplication k*P for G2. k>=0, P in affine."""
    if k == 0:
        return (_FP2_ZERO, _FP2_ZERO, _FP2_ZERO)

    bits = []
    e = k
    while e > 0:
        bits.append(e & 1)
        e >>= 1
    bits.reverse()

    X, Y, Z = _FP2_ZERO, _FP2_ZERO, _FP2_ZERO
    x_p, y_p = P_aff

    for bit in bits:
        if not _fp2_is_zero(Z):
            X, Y, Z = _g2_double((X, Y, Z))

        if bit:
            if _fp2_is_zero(Z):
                X, Y, Z = x_p, y_p, _FP2_ONE
            else:
                X, Y, Z = _g2_add((X, Y, Z), P_aff)

    return (X, Y, Z)


def _g2_is_on_curve(P_aff):
    """Check if G2 affine point is on twisted curve."""
    x, y = P_aff
    if _fp2_is_zero(x) and _fp2_is_zero(y):
        return True
    lhs = _fp2_sqr(y)
    rhs = _fp2_add(_fp2_mul(_fp2_sqr(x), x), _B_TWIST)
    return _fp2_eq(lhs, rhs)


# ============================================================
# Miller Loop Line Functions (sparse optimization)
# ============================================================

def _line_double_eval(T, P):
    """Evaluate tangent line at T (G2 twisted) evaluated at P (G1 affine).
    Returns sparse Fp12 element.
    T: Jacobian (X,Y,Z), P: affine (x,y) on G1 (base field)
    """
    X, Y, Z = T
    if _fp2_is_zero(Z):
        return _FP12_ONE

    # Affine coordinates of T
    Z_inv = _fp2_inv(Z)
    Z_inv2 = _fp2_sqr(Z_inv)
    Z_inv3 = _fp2_mul(Z_inv2, Z_inv)
    x1 = _fp2_mul(X, Z_inv2)
    y1 = _fp2_mul(Y, Z_inv3)

    # lambda = 3*x1^2 / (2*y1)
    x1_sq = _fp2_sqr(x1)
    lam = _fp2_mul_fp(x1_sq, 3)
    two_y1 = _fp2_mul_fp(y1, 2)
    lam = _fp2_mul(lam, _fp2_inv(two_y1))

    # Line value in Fp12:
    # l = y_P * w^3*v + (-lam)*x_P + (lam*x1 - y1) - lam*x_P * v
    x_p, y_p = P

    # a = lam*x1 - y1  (Fp2, w^0 coefficient of real part)
    a = _fp2_sub(_fp2_mul(lam, x1), y1)

    # b = -lam * x_P  (Fp2, v coefficient of real part)
    neg_lam_xp = _fp2_mul_fp(lam, (-x_p) % _sm9_q)

    # c = y_P  (Fp2, v coefficient of imag part, multiplied by w)
    yp_fp2 = (y_p % _sm9_q, 0)

    # Fp6 real part: (a, b, FP2_ZERO)
    real_fp6 = (a, neg_lam_xp, _FP2_ZERO)
    # Fp6 imag part: (FP2_ZERO, yp_fp2, FP2_ZERO)
    imag_fp6 = (_FP2_ZERO, yp_fp2, _FP2_ZERO)

    return (real_fp6, imag_fp6)


def _line_add_eval(T, Q_aff, P):
    """Evaluate line through T and Q evaluated at P.
    T: Jacobian (X,Y,Z), Q_aff: affine on G2, P: affine on G1
    """
    X1, Y1, Z1 = T
    x2, y2 = Q_aff
    x_p, y_p = P

    if _fp2_is_zero(Z1):
        return _FP12_ONE

    # Affine coordinates of T
    Z_inv = _fp2_inv(Z1)
    Z_inv2 = _fp2_sqr(Z_inv)
    Z_inv3 = _fp2_mul(Z_inv2, Z_inv)
    x1 = _fp2_mul(X1, Z_inv2)
    y1 = _fp2_mul(Y1, Z_inv3)

    # lambda = (y2 - y1) / (x2 - x1)
    dx = _fp2_sub(x2, x1)
    dy = _fp2_sub(y2, y1)
    lam = _fp2_mul(dy, _fp2_inv(dx))

    # Line value: a + b*v + c*w*v in Fp12
    a = _fp2_sub(_fp2_mul(lam, x1), y1)
    b = _fp2_mul_fp(lam, (-x_p) % _sm9_q)
    c = (y_p % _sm9_q, 0)

    real_fp6 = (a, b, _FP2_ZERO)
    imag_fp6 = (_FP2_ZERO, c, _FP2_ZERO)

    return (real_fp6, imag_fp6)


def _sparse_fp12_mul(a, sparse):
    """Multiply Fp12 element 'a' by sparse Fp12 element (from line eval).
    sparse = (real_fp6, imag_fp6) where:
      real_fp6 = (r0, r1, 0)   - only first two Fp2 components non-zero
      imag_fp6 = (0, i1, 0)    - only second Fp2 component non-zero
    """
    a_real, a_imag = a
    s_real, s_imag = sparse

    # a * s = (a_real + a_imag*w) * (s_real + s_imag*w)
    # = a_real*s_real + a_imag*s_imag*v + (a_real*s_imag + a_imag*s_real)*w
    # s_real = (r0, r1, 0), s_imag = (0, i1, 0)
    # v = (0, 1, 0) in Fp6

    # Compute a_real * s_real
    # (a0 + a1*v + a2*v^2) * (r0 + r1*v + 0*v^2)
    # = a0*r0 + a0*r1*v + a1*r0*v + a1*r1*v^2 + a2*r0*v^2 + a2*r1*v^3
    # = (a0*r0 + a2*r1*u) + (a0*r1 + a1*r0)*v + (a1*r1 + a2*r0)*v^2
    a0, a1, a2 = a_real
    r0, r1, r0_rest = s_real  # r0_rest should be zero

    a0r0 = _fp2_mul(a0, r0)
    a2r1_u = _fp2_mul(_fp2_mul(a2, r1), (0, 1))  # multiply by u
    a0r1_a1r0 = _fp2_add(_fp2_mul(a0, r1), _fp2_mul(a1, r0))
    a1r1_a2r0 = _fp2_add(_fp2_mul(a1, r1), _fp2_mul(a2, r0))

    a_real_s_real = (
        _fp2_add(a0r0, a2r1_u),
        a0r1_a1r0,
        a1r1_a2r0,
    )

    # Compute a_imag * s_imag * v
    # a_imag = (b0, b1, b2), s_imag = (0, i1, 0)
    # a_imag * s_imag = (b0, b1, b2) * (0, i1, 0)
    # = b0*0 + b0*i1*v + b1*0*v + b1*i1*v^2 + b2*0*v^2 + b2*i1*v^3
    # = b2*i1*u + b0*i1*v + b1*i1*v^2
    # Then multiply by v:
    # (b2*i1*u + b0*i1*v + b1*i1*v^2) * v
    # = b2*i1*u*v + b0*i1*v^2 + b1*i1*v^3
    # = b1*i1*u + b2*i1*u*v + b0*i1*v^2
    b0, b1, b2 = a_imag
    i1 = s_imag[1]

    bi1 = (_fp2_mul(b0, i1), _fp2_mul(b1, i1), _fp2_mul(b2, i1))
    u = (0, 1)
    a_imag_s_imag_v = (
        _fp2_mul(bi1[1], u),  # b1*i1*u
        _fp2_mul(bi1[2], u),  # b2*i1*u → this is the v coefficient
        bi1[0],  # b0*i1 → v^2 coefficient
    )

    # Real part of result
    result_real = _fp6_add(a_real_s_real, a_imag_s_imag_v)

    # Compute a_real * s_imag + a_imag * s_real
    # a_real * s_imag = (a0,a1,a2) * (0,i1,0) = (a2*i1*u, a0*i1, a1*i1)
    a_real_s_imag = (
        _fp2_mul(_fp2_mul(a2, i1), u),
        _fp2_mul(a0, i1),
        _fp2_mul(a1, i1),
    )
    # a_imag * s_real = (b0,b1,b2) * (r0,r1,0)
    # = (b0*r0 + b2*r1*u, b0*r1 + b1*r0, b1*r1 + b2*r0)
    b0r0 = _fp2_mul(b0, r0)
    b2r1_u = _fp2_mul(_fp2_mul(b2, r1), u)
    a_imag_s_real = (
        _fp2_add(b0r0, b2r1_u),
        _fp2_add(_fp2_mul(b0, r1), _fp2_mul(b1, r0)),
        _fp2_add(_fp2_mul(b1, r1), _fp2_mul(b2, r0)),
    )

    result_imag = _fp6_add(a_real_s_imag, a_imag_s_real)

    return (result_real, result_imag)


# ============================================================
# Miller Loop and Ate Pairing
# ============================================================

# Miller loop parameter: s = t - 1
_MILLER_S = _sm9_t - 1


def _ate_pairing(P_aff, Q_aff):
    """Ate pairing e(P, Q).
    P: G1 point (affine, on base field E/Fp)
    Q: G2 point (affine, on twisted curve E'/Fp^2)
    Returns Fp12 element.
    """
    f = _FP12_ONE

    # If P is infinity (0,0)
    if P_aff[0] == 0 and P_aff[1] == 0:
        return _FP12_ONE

    # If Q is infinity
    xq, yq = Q_aff
    if _fp2_is_zero(xq) and _fp2_is_zero(yq):
        return _FP12_ONE

    T = (xq, yq, _FP2_ONE)  # Q in Jacobian

    s = _MILLER_S
    neg = False
    if s < 0:
        s = -s
        neg = True

    bits = []
    e = s
    while e > 0:
        bits.append(e & 1)
        e >>= 1
    bits.reverse()

    # Standard Miller loop: for i from len(bits)-2 down to 0
    # f = f^2 * l_{T,T}(P); T = 2T
    # if bit[i]: f = f * l_{T,Q}(P); T = T + Q
    for i in range(1, len(bits)):
        f = _fp12_sqr(f)
        line = _line_double_eval(T, P_aff)
        f = _sparse_fp12_mul(f, line)
        T = _g2_double(T)

        if bits[i]:
            line = _line_add_eval(T, Q_aff, P_aff)
            f = _sparse_fp12_mul(f, line)
            T = _g2_add(T, Q_aff)

    # Final exponentiation
    f = _fp12_final_exp(f)

    if neg:
        f = _fp12_inv(f)

    return f


def _fp12_final_exp(f):
    """Final exponentiation: f^((q^12 - 1)/N)"""
    # Step 1: f = f^(q^6 - 1)  [easy: conjugate * inverse]
    f = _fp12_mul(_fp12_frobenius6(f), _fp12_inv(f))

    # Step 2: f = f^(q^2 + 1)  [easy: frob2 * f]
    f = _fp12_mul(_fp12_frobenius2(f), f)

    # Step 3: f = f^( (q^4 - q^2 + 1) / N )  [hard part]
    f = _fp12_pow(f, _Q4_MINUS_Q2_PLUS_1_DIV_N)

    return f


# ============================================================
# GT Exponentiation (pairing-based exponentiation)
# ============================================================

def _gt_pow(g, exp):
    """g^exp in GT (Fp12 element to integer power)"""
    return _fp12_pow(g, exp)


# ============================================================
# Hash Functions H1, H2 (GM/T 0044.5-2016)
# ============================================================

def _hash_sm3(data):
    """SM3 hash, returns bytes."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    h = _hash_new('sm3')
    h.update(data)
    return h.digest()


def _int_to_bytes(x, length):
    """Convert integer to big-endian bytes of given length."""
    return x.to_bytes(length, 'big')


def _H1(Z, n, hid=0x03):
    """H1: hash to G1 point.
    Z: bytes, identity string
    n: int, order (N)
    hid: function identifier (1=sign, 2=key_exchange, 3=encrypt)
    Returns G1 point (x,y) in affine.
    """
    hlen = 32  # SM3 output length
    if hid == 0x01:
        prefix = b'\x01'
    elif hid == 0x02:
        prefix = b'\x02'
    elif hid == 0x03:
        prefix = b'\x03'
    else:
        prefix = bytes([hid])

    ct = 1
    while True:
        ha = _hash_sm3(prefix + Z + _int_to_bytes(ct, 4))
        # Convert to integer and reduce mod N
        h_int = int.from_bytes(ha, 'big') % _sm9_N
        if h_int == 0:
            ct += 1
            continue

        # Try to find y such that y^2 = h_int^3 + b (mod q)
        x = h_int
        rhs = (x * x * x + _sm9_b) % _sm9_q

        # q = 5 mod 8: if rhs is QR, y = rhs^((q+3)/8) and adjust
        y = pow(rhs, (_sm9_q + 3) // 8, _sm9_q)
        y2 = (y * y) % _sm9_q
        if y2 == rhs:
            return (x, y)
        elif y2 == (_sm9_q - rhs) % _sm9_q:
            # y^2 = -rhs, multiply by sqrt(-1) = 2^((q-1)/4)
            sqrt_m1 = pow(2, (_sm9_q - 1) // 4, _sm9_q)
            y = (y * sqrt_m1) % _sm9_q
            if (y * y) % _sm9_q == rhs:
                return (x, y)

        ct += 1


def _H2(Z, n=0):
    """H2: hash to integer mod N.
    Z: bytes or str
    Returns: int in [1, N-1]
    """
    if n == 0:
        n = _sm9_N
    hlen = 32
    if isinstance(Z, str):
        Z = Z.encode('utf-8')
    ct = 1
    while True:
        ha = _hash_sm3(b'\x02' + Z + _int_to_bytes(ct, 4))
        h_int = int.from_bytes(ha, 'big')
        h_mod = (h_int % (n - 1)) + 1
        if h_mod != 0:
            return h_mod
        ct += 1


def _H1_G2(Z, n=None, hid=0x03):
    """H1 for G2: hash identity to G2 point.
    Used for encryption (user decryption key extraction on G2).
    Returns G2 point (x, y) on twisted curve, in affine.
    """
    if n is None:
        n = _sm9_N
    if hid == 0x01:
        prefix = b'\x01'
    elif hid == 0x02:
        prefix = b'\x02'
    elif hid == 0x03:
        prefix = b'\x03'
    else:
        prefix = bytes([hid])

    ct = 1
    while True:
        ha = _hash_sm3(prefix + Z + _int_to_bytes(ct, 4))
        h_int = int.from_bytes(ha, 'big') % _sm9_N
        if h_int == 0:
            ct += 1
            continue

        # Construct x coordinate in Fp2
        # x = h_int + 0*u (Fp2 element with a1=0)
        x = (h_int, 0)

        # Compute y^2 = x^3 + b_twist
        x_sq = _fp2_sqr(x)
        x_cu = _fp2_mul(x_sq, x)
        rhs = _fp2_add(x_cu, _B_TWIST)

        # Fp2 sqrt for q^2 ≡ 1 mod 8: y = a^((q^2+3)/8), adjust if needed
        exp_sqrt = (pow(_sm9_q, 2) + 3) // 8
        y = _fp2_pow(rhs, exp_sqrt)
        y_sq = _fp2_sqr(y)
        if _fp2_eq(y_sq, rhs):
            return (x, y)
        elif _fp2_eq(y_sq, _fp2_neg(rhs)):
            # y^2 = -rhs, multiply by sqrt(-1) in Fp2 = (sqrt_m1, 0)
            sqrt_m1 = pow(2, (_sm9_q - 1) // 4, _sm9_q)
            y = _fp2_mul(y, (sqrt_m1, 0))
            if _fp2_eq(_fp2_sqr(y), rhs):
                return (x, y)

        ct += 1


def _fp2_pow(a, exp):
    """Exponentiation in Fp2."""
    if exp == 0:
        return _FP2_ONE
    if exp == 1:
        return a
    result = _FP2_ONE
    base = a
    e = exp
    while e > 0:
        if e & 1:
            result = _fp2_mul(result, base)
        base = _fp2_sqr(base)
        e >>= 1
    return result


# ============================================================
# SM9 KDF (Key Derivation Function)
# ============================================================

def _sm9_KDF(Z, klen):
    """SM9 KDF: Derive key material of klen bytes from Z.
    Z: bytes
    klen: int, key length in bytes
    Returns: bytes (length klen)
    """
    from pysmx.SM3._SM3 import _BKDF
    if isinstance(Z, bytes):
        Z = Z.hex()
    return _BKDF(Z, klen)


# ============================================================
# SM9 Key Generation
# ============================================================

def _rand_int_n():
    """Generate random integer in [1, N-1]."""
    byte_len = 32
    while True:
        r = int.from_bytes(os.urandom(byte_len), 'big')
        if 1 <= r < _sm9_N:
            return r


def _rand_bytes(n):
    """Generate n random bytes."""
    return os.urandom(n)


def generate_master_key():
    """Generate SM9 master key pair.
    Returns: (master_private_key, master_public_key_P1, master_public_key_P2)
    ke: master private key (int)
    P_pub_e: encryption master public key = [ke]P1 (G1 point, affine)
    P_pub_s: signature master public key = [ke]P2 (could be separate ks)
    """
    ke = _rand_int_n()
    P1 = (_sm9_P1x, _sm9_P1y)
    P_pub_e_jac = _g1_scalar_mult(ke, P1)
    P_pub_e = _g1_to_affine(P_pub_e_jac)
    return ke, P_pub_e


def generate_user_sign_key(ks, ID_A, hid=0x01):
    """Generate user signing private key.
    ks: master private key (int)
    ID_A: user identity (bytes)
    hid: 0x01 for signature
    Returns: G1 point (user signing key d_A, in affine)
    """
    if isinstance(ID_A, str):
        ID_A = ID_A.encode('utf-8')

    # t1 = H1(ID || hid, N) + ks mod N
    h1_x, h1_y = _H1(ID_A, _sm9_N, hid)
    h1_int = h1_x  # x-coordinate as integer

    t1 = (h1_int + ks) % _sm9_N
    if t1 == 0:
        raise ValueError("t1 == 0, regenerate master key")

    # t2 = ks * t1^(-1) mod N
    t2 = (ks * pow(t1, _sm9_N - 2, _sm9_N)) % _sm9_N

    # d_A = [t2] * P1
    P1 = (_sm9_P1x, _sm9_P1y)
    d_A_jac = _g1_scalar_mult(t2, P1)
    d_A = _g1_to_affine(d_A_jac)

    return d_A


def generate_user_enc_key(ke, ID_B, hid=0x03):
    """Generate user decryption private key.
    ke: encryption master private key (int)
    ID_B: user identity (bytes)
    hid: 0x03 for encryption
    Returns: G2 point (user decryption key d_B, in affine)
    """
    if isinstance(ID_B, str):
        ID_B = ID_B.encode('utf-8')

    # t1 = H1(ID || hid, N) + ke mod N
    h1_x, h1_y = _H1(ID_B, _sm9_N, hid)
    h1_int = h1_x

    t1 = (h1_int + ke) % _sm9_N
    if t1 == 0:
        raise ValueError("t1 == 0, regenerate master key")

    # t2 = ke * t1^(-1) mod N
    t2 = (ke * pow(t1, _sm9_N - 2, _sm9_N)) % _sm9_N

    # d_B = [t2] * P2
    P2 = ((_sm9_P2[0], _sm9_P2[1]), (_sm9_P2[2], _sm9_P2[3]))
    d_B_jac = _g2_scalar_mult(t2, P2)
    d_B = _g2_to_affine(d_B_jac)

    return d_B


# ============================================================
# SM9 Digital Signature (GM/T 0044.2-2016)
# ============================================================

def Sign(M, d_A, P_pub_s, hid=0x01):
    """SM9 signature.
    M: message (bytes)
    d_A: user signing private key (G1 point in affine: (x,y))
    P_pub_s: signature master public key (G2 point in affine: ((xa,xb),(ya,yb)))
    hid: 0x01 for signature
    Returns: signature as bytes (h || S_x || S_y)
    """
    if isinstance(M, str):
        M = M.encode('utf-8')

    P1 = (_sm9_P1x, _sm9_P1y)

    # Precompute g = e(P1, P_pub_s)
    g = _ate_pairing(P1, P_pub_s)

    while True:
        # r in [1, N-1]
        r = _rand_int_n()

        # w = g^r
        w = _fp12_pow(g, r)

        # Convert w to bytes for hashing
        w_bytes = _fp12_to_bytes(w)

        # h = H2(M || w, N)
        h = _H2(M + w_bytes, _sm9_N)

        # l = (r - h) mod N
        ll = (r - h) % _sm9_N
        if ll == 0:
            continue

        # S = [l] * d_A
        S_jac = _g1_scalar_mult(ll, d_A)
        S = _g1_to_affine(S_jac)

        # Signature = (h, S)
        h_bytes = _int_to_bytes(h, 32)
        S_x_bytes = _int_to_bytes(S[0], 32)
        S_y_bytes = _int_to_bytes(S[1], 32)

        return h_bytes + S_x_bytes + S_y_bytes


def Verify(M, signature, ID_A, P_pub_s, hid=0x01):
    """SM9 signature verification.
    M: message (bytes)
    signature: bytes (h || S_x || S_y), 96 bytes
    ID_A: signer identity (bytes)
    P_pub_s: signature master public key (G2 point in affine)
    hid: 0x01 for signature
    Returns: True if valid, False otherwise
    """
    if isinstance(M, str):
        M = M.encode('utf-8')
    if isinstance(ID_A, str):
        ID_A = ID_A.encode('utf-8')

    if len(signature) != 96:
        return False

    # Parse h and S
    h = int.from_bytes(signature[:32], 'big')
    S_x = int.from_bytes(signature[32:64], 'big')
    S_y = int.from_bytes(signature[64:96], 'big')
    S = (S_x, S_y)

    # Check h in [1, N-1]
    if h < 1 or h >= _sm9_N:
        return False

    # Check S on curve
    if not _g1_is_on_curve(S):
        return False

    P1 = (_sm9_P1x, _sm9_P1y)

    # g = e(P1, P_pub_s)
    g = _ate_pairing(P1, P_pub_s)

    # t = g^h
    t = _fp12_pow(g, h)

    # h1 = H1(ID_A || hid, N)
    h1_pt = _H1(ID_A, _sm9_N, hid)
    h1_int = h1_pt[0]

    # P = [h1] * P2 + P_pub_s
    P2 = ((_sm9_P2[0], _sm9_P2[1]), (_sm9_P2[2], _sm9_P2[3]))
    h1P2_jac = _g2_scalar_mult(h1_int, P2)
    h1P2 = _g2_to_affine(h1P2_jac)

    # P = h1P2 + P_pub_s
    P_jac = _g2_add((h1P2[0], h1P2[1], _FP2_ONE), P_pub_s)
    P = _g2_to_affine(P_jac)

    # u = e(S, P)
    u = _ate_pairing(S, P)

    # w' = u * t
    w_prime = _fp12_mul(u, t)

    # h2 = H2(M || w', N)
    w_prime_bytes = _fp12_to_bytes(w_prime)
    h2 = _H2(M + w_prime_bytes, _sm9_N)

    return h2 == h


def _fp12_to_bytes(f):
    """Convert Fp12 element to bytes."""
    result = b''
    real, imag = f
    for fp2 in real:
        result += _int_to_bytes(fp2[0], 32)
        result += _int_to_bytes(fp2[1], 32)
    for fp2 in imag:
        result += _int_to_bytes(fp2[0], 32)
        result += _int_to_bytes(fp2[1], 32)
    return result


# ============================================================
# SM9 Encryption / Decryption (GM/T 0044.4-2016)
# ============================================================

def Encrypt(M, ID_B, P_pub_e, hid=0x03):
    """SM9 encryption.
    M: plaintext (bytes)
    ID_B: recipient identity (bytes)
    P_pub_e: encryption master public key (G1 point in affine)
    hid: 0x03 for encryption
    Returns: ciphertext (bytes) = C1 || C3 || C2
    """
    if isinstance(M, str):
        M = M.encode('utf-8')
    if isinstance(ID_B, str):
        ID_B = ID_B.encode('utf-8')

    mlen = len(M)
    # SM3 MAC output
    mac_len = 32

    P2 = ((_sm9_P2[0], _sm9_P2[1]), (_sm9_P2[2], _sm9_P2[3]))

    while True:
        # r in [1, N-1]
        r = _rand_int_n()

        # Q_B = H1(ID_B || hid, N)
        Q_B = _H1(ID_B, _sm9_N, hid)

        # C1 = [r] * Q_B
        C1_jac = _g1_scalar_mult(r, Q_B)
        C1 = _g1_to_affine(C1_jac)

        # g = e(P_pub_e, P2)
        g = _ate_pairing(P_pub_e, P2)

        # w = g^r
        w = _fp12_pow(g, r)

        # Convert to bytes
        C1_bytes = b'\x04' + _int_to_bytes(C1[0], 32) + _int_to_bytes(C1[1], 32)
        w_bytes = _fp12_to_bytes(w)

        # K = KDF(C1 || w || ID_B, mlen + mac_len)
        kdf_input = C1_bytes + w_bytes + ID_B
        K = _sm9_KDF(kdf_input, mlen + mac_len)

        # K1 = K[:mlen], K2 = K[mlen:]
        K1 = K[:mlen]
        K2 = K[mlen:mlen + mac_len]

        # Check K1 is not all-zero
        if K1 == b'\x00' * mlen:
            continue

        # C2 = M XOR K1
        C2 = bytes(a ^ b for a, b in zip(M, K1))

        # C3 = MAC(K2, C2) using SM3-based HMAC
        import hmac as _hmac_module
        C3 = _hmac_module.new(K2, C2, 'sm3').digest()

        ciphertext = C1_bytes + C3 + C2
        return ciphertext


def Decrypt(C, d_B, ID_B, hid=0x03):
    """SM9 decryption.
    C: ciphertext (bytes)
    d_B: user decryption private key (G2 point in affine)
    ID_B: recipient identity (bytes)
    hid: 0x03 for encryption
    Returns: plaintext (bytes) or None on failure
    """
    import hmac as _hmac_module

    if isinstance(ID_B, str):
        ID_B = ID_B.encode('utf-8')

    mac_len = 32

    # Parse ciphertext
    if len(C) < 65 + mac_len:
        return None

    # C1: 65 bytes (04 || x || y)
    C1_bytes = C[:65]
    C3 = C[65:65 + mac_len]
    C2 = C[65 + mac_len:]

    C1_x = int.from_bytes(C1_bytes[1:33], 'big')
    C1_y = int.from_bytes(C1_bytes[33:65], 'big')
    C1 = (C1_x, C1_y)

    # w = e(C1, d_B)
    w = _ate_pairing(C1, d_B)

    w_bytes = _fp12_to_bytes(w)

    mlen = len(C2)
    kdf_input = C1_bytes + w_bytes + ID_B
    K = _sm9_KDF(kdf_input, mlen + mac_len)

    K1 = K[:mlen]
    K2 = K[mlen:mlen + mac_len]

    # Check K1
    if K1 == b'\x00' * mlen and mlen > 0:
        return None

    # M' = C2 XOR K1
    M_prime = bytes(a ^ b for a, b in zip(C2, K1))

    # u = MAC(K2, M')
    u = _hmac_module.new(K2, M_prime, 'sm3').digest()

    if u != C3:
        return None

    return M_prime


# ============================================================
# SM9 Key Encapsulation (KEM)
# ============================================================

def KEM_Encapsulate(ID_B, P_pub_e, klen, hid=0x02):
    """SM9 KEM encapsulation.
    ID_B: recipient identity (bytes)
    P_pub_e: encryption master public key
    klen: desired key length (bytes)
    hid: 0x02 for key exchange
    Returns: (K, C) where K is the shared key (bytes) and C is the ciphertext (bytes)
    """
    if isinstance(ID_B, str):
        ID_B = ID_B.encode('utf-8')

    P2 = ((_sm9_P2[0], _sm9_P2[1]), (_sm9_P2[2], _sm9_P2[3]))

    while True:
        r = _rand_int_n()
        Q_B = _H1(ID_B, _sm9_N, hid)
        C1_jac = _g1_scalar_mult(r, Q_B)
        C1 = _g1_to_affine(C1_jac)

        g = _ate_pairing(P_pub_e, P2)
        w = _fp12_pow(g, r)

        C1_bytes = b'\x04' + _int_to_bytes(C1[0], 32) + _int_to_bytes(C1[1], 32)
        w_bytes = _fp12_to_bytes(w)

        K = _sm9_KDF(C1_bytes + w_bytes + ID_B, klen)

        if K != b'\x00' * klen:
            return K, C1_bytes


def KEM_Decapsulate(C1_bytes, d_B, ID_B, klen, hid=0x02):
    """SM9 KEM decapsulation.
    C1_bytes: ciphertext from encapsulation
    d_B: user decryption private key (G2 point)
    ID_B: identity (bytes)
    klen: key length (bytes)
    hid: 0x02
    Returns: shared key K (bytes) or None
    """
    if isinstance(ID_B, str):
        ID_B = ID_B.encode('utf-8')

    C1_x = int.from_bytes(C1_bytes[1:33], 'big')
    C1_y = int.from_bytes(C1_bytes[33:65], 'big')
    C1 = (C1_x, C1_y)

    w = _ate_pairing(C1, d_B)
    w_bytes = _fp12_to_bytes(w)

    K = _sm9_KDF(C1_bytes + w_bytes + ID_B, klen)

    return K


# ============================================================
# Convenience functions
# ============================================================

def sm9_hex(s):
    """Convert bytes to hex string."""
    if isinstance(s, str):
        return s
    return s.hex()


def sm9_unhex(s):
    """Convert hex string to bytes."""
    if isinstance(s, bytes):
        return s
    return bytes.fromhex(s)


# ============================================================
# Test
# ============================================================
if __name__ == '__main__':
    print("SM9 BN Curve Parameters:")
    print(f"  q (field): {hex(_sm9_q)}")
    print(f"  N (order): {hex(_sm9_N)}")
    print(f"  t (trace): {hex(_sm9_t)}")
    print("")

    # Test key generation
    print("Generating master key...")
    ke, P_pub_e = generate_master_key()
    print(f"  master private key (ke): {hex(ke)}")
    print(f"  master public key (P_pub_e): ({hex(P_pub_e[0])}, {hex(P_pub_e[1])})")
    print("")

    # Test user key generation
    ID_A = b'alice@sm9.test'
    d_A = generate_user_sign_key(ke, ID_A, hid=0x01)
    print(f"  user signing key (d_A): ({hex(d_A[0])}, {hex(d_A[1])})")
    print("")

    # Test sign/verify
    P2 = ((_sm9_P2[0], _sm9_P2[1]), (_sm9_P2[2], _sm9_P2[3]))
    P_pub_s = _g2_to_affine(_g2_scalar_mult(ke, P2))

    M = b'Hello SM9!'
    sig = Sign(M, d_A, P_pub_s, hid=0x01)
    print(f"  Signature: {sig.hex()[:64]}... ({len(sig)} bytes)")

    ok = Verify(M, sig, ID_A, P_pub_s, hid=0x01)
    print(f"  Verify: {'OK' if ok else 'FAIL'}")
    print("")

    # Test encrypt/decrypt
    P1 = (_sm9_P1x, _sm9_P1y)
    P_pub_e = _g1_to_affine(_g1_scalar_mult(ke, P1))

    ID_B = b'bob@sm9.test'
    d_B = generate_user_enc_key(ke, ID_B, hid=0x03)

    plaintext = b'Secret message for SM9 encryption'
    ciphertext = Encrypt(plaintext, ID_B, P_pub_e, hid=0x03)
    print(f"  Ciphertext: {len(ciphertext)} bytes")

    decrypted = Decrypt(ciphertext, d_B, ID_B, hid=0x03)
    print(f"  Decrypted: {decrypted}")
    print(f"  Match: {decrypted == plaintext}")
