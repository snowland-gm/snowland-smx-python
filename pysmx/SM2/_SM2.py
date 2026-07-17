#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @contact: astar@snowland.ltd
# @file: _SM2.py
# @time: 2018/12/03 15:11
# @Software: PyCharm


from functools import reduce
import secrets
from pysmx.SM3 import KDF
from pysmx.crypto import hashlib
from collections import namedtuple

# select prime field, set elliptic curve parameters
sm2_N = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16)
sm2_P = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16)
sm2_G = '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0'  # G point
sm2_G_number = int(sm2_G, 16)
sm2_a = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', 16)
sm2_b = int('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', 16)
sm2_a_3 = (sm2_a + 3) % sm2_P  # intermediate value for double point
Fp = 256


# sm2_N = int('BDB6F4FE3E8B1D9E0DA8C0D40FC962195DFAE76F56564677', 16)
# sm2_P = int('BDB6F4FE3E8B1D9E0DA8C0D46F4C318CEFE4AFE3B6B8551F', 16)
# sm2_G = '4AD5F7048DE709AD51236DE65E4D4B482C836DC6E410664002BB3A02D4AAADACAE24817A4CA3A1B014B5270432DB27D2'# G point
# sm2_a = int('BB8E5E8FBC115E139FE6A814FE48AAA6F0ADA1AA5DF91985',16)
# sm2_b = int('1854BEBDC31B21B7AEFC80AB0ECD10D5B1B3308E6DBF11C1',16)
# sm2_a_3 = (sm2_a + 3) % sm2_P # intermediate value for double point
# Fp = 192


def modular_power(a, n, p):
    """
    compute a^ n % p
    if n == 0:
        return 1
    elif n == 1:
        return a % p
    temp = a * a % p
    if n & 1:
        return a % p * modular_power(temp, n // 2, p) % p
    else:
        return (modular_power(temp, n // 2, p)) % p
    original: https://blog.csdn.net/qq_36921652/article/details/79368299
    """
    return pow(a, n, p)


def is_prime(number: (str, int), itor=10):
    if not isinstance(number, int):
        number = int(number)
    for i in range(itor):
        a = secrets.randbelow(number - 1) + 1
        if modular_power(a, number - 1, number) != 1:
            return False
    return True


def get_hash(algorithm_name, message, Hexstr=0, encoding='utf-8'):
    if hasattr(hashlib, algorithm_name):
        f = getattr(hashlib, algorithm_name)()
    else:
        raise ValueError('method does not exists')
    if Hexstr:
        message = bytes.fromhex(message)
    if isinstance(message, (bytes, bytearray)):
        f.update(message)
    else:
        f.update(bytes(message, encoding=encoding))
    return f.hexdigest()


def get_random_int(upper):
    """Return a cryptographically secure random integer in [1, upper - 1]."""
    if upper <= 2:
        raise ValueError('upper must be greater than 2')
    return secrets.randbelow(upper - 1) + 1


def get_random_str(n: int = 64):
    """Return a cryptographically secure random hex string of n digits.

    The underlying integer is drawn from [1, sm2_N - 1] so the result is
    directly usable as an SM2 private key or ephemeral value, complying with
    GM/T 0003 (random values must lie in [1, n-1]).
    """
    return '%0{}x'.format(n) % get_random_int(sm2_N)


def _jac_double(X, Y, Z, P=sm2_P, a_3=sm2_a_3):
    """Double a Jacobian point (X,Y,Z) using integer arithmetic."""
    if Z == 0:
        return (X, Y, Z)
    T6 = (Z * Z) % P
    T2 = (Y * Y) % P
    T3 = (X + T6) % P
    T4 = (X - T6) % P
    T1 = (T3 * T4) % P
    T3 = (Y * Z) % P
    T4 = (T2 * 8) % P
    T5 = (X * T4) % P
    T1 = (T1 * 3) % P
    T6 = (T6 * T6) % P
    T6 = (a_3 * T6) % P
    T1 = (T1 + T6) % P
    z3 = (T3 + T3) % P
    T3 = (T1 * T1) % P
    T2 = (T2 * T4) % P
    x3 = (T3 - T5) % P
    if T5 % 2:
        T4 = (T5 + ((T5 + P) >> 1) - T3) % P
    else:
        T4 = (T5 + (T5 >> 1) - T3) % P
    T1 = (T1 * T4) % P
    y3 = (T1 - T2) % P
    return (x3, y3, z3)


def _jac_add_affine(X1, Y1, Z1, x2, y2, P=sm2_P):
    """Add Jacobian point (X1,Y1,Z1) with affine point (x2,y2) using integer arithmetic."""
    if Z1 == 0:
        return (x2, y2, 1)
    T1 = (Z1 * Z1) % P
    T2 = (y2 * Z1) % P
    T3 = (x2 * T1) % P
    T1 = (T1 * T2) % P
    T2 = (T3 - X1) % P
    T3 = (T3 + X1) % P
    T4 = (T2 * T2) % P
    T1 = (T1 - Y1) % P
    Z3 = (Z1 * T2) % P
    T2 = (T2 * T4) % P
    T3 = (T3 * T4) % P
    T5 = (T1 * T1) % P
    T4 = (X1 * T4) % P
    X3 = (T5 - T3) % P
    T2 = (Y1 * T2) % P
    T3 = (T4 - X3) % P
    T1 = (T1 * T3) % P
    Y3 = (T1 - T2) % P
    return (X3, Y3, Z3)


def _jac_to_affine(X, Y, Z, P=sm2_P):
    """Convert Jacobian (X,Y,Z) to affine (x,y); None at point at infinity."""
    if Z == 0:
        return None
    z_inv = pow(Z, P - 2, P)
    z_inv_sq = (z_inv * z_inv) % P
    z_inv_cu = (z_inv_sq * z_inv) % P
    x_new = (X * z_inv_sq) % P
    y_new = (Y * z_inv_cu) % P
    return (x_new, y_new)


def _jac_scalar_mult(k, x, y, z, P=sm2_P):
    """k * (x,y,z) via double-and-add (MSB-first, no list allocation)."""
    if k == 0:
        return (0, 0, 0)
    X, Y, Z = 0, 0, 0
    got = False
    for i in range(k.bit_length() - 1, -1, -1):
        if got:
            X, Y, Z = _jac_double(X, Y, Z, P)
        if (k >> i) & 1:
            if not got:
                X, Y, Z = x, y, z
                got = True
            else:
                X, Y, Z = _jac_add_affine(X, Y, Z, x, y, P)
    return (X, Y, Z)


def kG(k, Point, len_para):
    """
    kP operation (integer arithmetic internally, hex-string in / out)
    :param k: scalar (int)
    :param Point: point as hex string (affine x||y, or jacobian x||y||z)
    :param len_para: hex length of a field element
    :return: affine point as hex string
    """
    length = len(Point)
    len_2 = 2 * len_para
    if length < len_2:
        return None
    x = int(Point[0:len_para], 16)
    y = int(Point[len_para:len_2], 16)
    z = 1 if length == len_2 else int(Point[len_2:], 16)
    X, Y, Z = _jac_scalar_mult(k, x, y, z)
    res = _jac_to_affine(X, Y, Z)
    if res is None:
        return None
    x_new, y_new = res
    form = '%%0%dx' % len_para
    form = form * 2
    return form % (x_new, y_new)


def DoublePoint(Point, len_para, P=sm2_P):
    """
    double point
    :param Point:
    :param len_para:
    :param P:
    :return:
    """
    length = len(Point)
    len_2 = 2 * len_para
    if length < len_2:
        return None
    else:
        x1 = int(Point[0:len_para], 16)
        y1 = int(Point[len_para:len_2], 16)
        z1 = 1 if length == len_2 else int(Point[len_2:], 16)
        T6 = (z1 * z1) % P
        T2 = (y1 * y1) % P
        T3 = (x1 + T6) % P
        T4 = (x1 - T6) % P
        T1 = (T3 * T4) % P
        T3 = (y1 * z1) % P
        T4 = (T2 * 8) % P
        T5 = (x1 * T4) % P
        T1 = (T1 * 3) % P
        T6 = (T6 * T6) % P
        T6 = (sm2_a_3 * T6) % P
        T1 = (T1 + T6) % P
        z3 = (T3 + T3) % P
        T3 = (T1 * T1) % P
        T2 = (T2 * T4) % P
        x3 = (T3 - T5) % P
        T4 = (T5 + ((T5 + P) >> 1) - T3) % P if T5 % 2 else (T5 + (T5 >> 1) - T3) % P
        T1 = (T1 * T4) % P
        y3 = (T1 - T2) % P

        form = '%%0%dx' % len_para
        form = form * 3
        return form % (x3, y3, z3)


def AddPoint(P1, P2, len_para, P=sm2_P):
    """point add function
    :param P1 is Jacobian projective coordinates
    :param P2 is affine coordinates i.e. z=1
    """
    len_2 = 2 * len_para
    l1 = len(P1)
    l2 = len(P2)
    if (l1 < len_2) or (l2 < len_2):
        return None
    else:
        X1 = int(P1[0:len_para], 16)
        Y1 = int(P1[len_para:len_2], 16)
        Z1 = 1 if l1 == len_2 else int(P1[len_2:], 16)
        x2 = int(P2[0:len_para], 16)
        y2 = int(P2[len_para:len_2], 16)

        T1 = (Z1 * Z1) % P
        T2 = (y2 * Z1) % P
        T3 = (x2 * T1) % P
        T1 = (T1 * T2) % P
        T2 = (T3 - X1) % P
        T3 = (T3 + X1) % P
        T4 = (T2 * T2) % P
        T1 = (T1 - Y1) % P
        Z3 = (Z1 * T2) % P
        T2 = (T2 * T4) % P
        T3 = (T3 * T4) % P
        T5 = (T1 * T1) % P
        T4 = (X1 * T4) % P
        X3 = (T5 - T3) % P
        T2 = (Y1 * T2) % P
        T3 = (T4 - X3) % P
        T1 = (T1 * T3) % P
        Y3 = (T1 - T2) % P

        form = '%%0%dx' % len_para
        form = form * 3
        return form % (X3, Y3, Z3)


def ConvertJacb2Nor(Point, len_para, P=sm2_P):
    """Jacobian projective coordinates to affine coordinates"""
    len_2 = 2 * len_para
    x = int(Point[0:len_para], 16)
    y = int(Point[len_para:len_2], 16)
    z = int(Point[len_2:], 16)
    # z_inv = Inverse(z, P)
    z_inv = pow(z, P - 2, P)
    z_invSquar = (z_inv * z_inv) % P
    z_invQube = (z_invSquar * z_inv) % P
    x_new = (x * z_invSquar) % P
    y_new = (y * z_invQube) % P
    z_new = (z * z_inv) % P
    if z_new == 1:
        form = '%%0%dx' % len_para
        form = form * 2
        return form % (x_new, y_new)
    else:
        return None


def Inverse(data, M, len_para=64):
    """ find inverse, can use pow() instead"""
    tempM = M - 2
    mask_str = '8' + '0' * (len_para - 1)
    mask = int(mask_str, 16)
    tempA = 1
    tempB = data

    for i in range(len_para * 4):
        tempA = (tempA * tempA) % M
        if (tempM & mask) != 0:
            tempA = (tempA * tempB) % M
        mask = mask >> 1

    return tempA


def Verify(Sign, E, PA, len_para=64, Hexstr=0, encoding='utf-8'):
    """
    verify function
    :param Sign: signature r||s
    :param E: E message hash
    :param PA: PA public key
    :param len_para:
    :return:
    """
    if isinstance(Sign, str):
        r = int(Sign[0:len_para], 16)
        s = int(Sign[len_para:2 * len_para], 16)
    elif isinstance(Sign, bytes):
        r = int(Sign.hex()[:len_para], 16)
        s = int(Sign.hex()[len_para:2 * len_para], 16)

    if Hexstr:
        e = int(E, 16)  # input message itself is hex string
    else:
        if isinstance(E, str):
            E = E.encode(encoding)
        E = E.hex()  # convert message to hex string
        e = int(E, 16)

    if isinstance(PA, str):
        pass
    elif isinstance(PA, (bytes, bytearray)):
        PA = PA.hex()
    else:
        raise ValueError('Typeof PA must be string or bytes')
    t = (r + s) % sm2_N
    if t == 0:
        return 0

    P1 = kG(s, sm2_G, len_para)
    P2 = kG(t, PA, len_para)
    # print(P1)
    # print(P2)
    if P1 == P2:
        P1 += '1'
        P1 = DoublePoint(P1, len_para)
    else:
        P1 += '1'
        P1 = AddPoint(P1, P2, len_para)
        P1 = ConvertJacb2Nor(P1, len_para)

    x = int(P1[0:len_para], 16)
    return r == ((e + x) % sm2_N)


def Sign(E, DA, K, len_para, Hexstr=0, encoding='utf-8'):
    """sign function
     :param E message hash, hex string
     :param DA private key, hex string
     :param K random number, hex string
     """
    if Hexstr:
        e = int(E, 16)  # input message itself is hex string
    else:
        if isinstance(E, str):
            E = E.encode(encoding)
        E = E.hex()  # convert message to hex string
        e = int(E, 16)
    if isinstance(DA, str):
        d = int(DA, 16)
    elif isinstance(DA, (bytes, bytearray)):
        d = int(DA.hex(), 16)
    else:
        raise ValueError('DA must be str or bytes')
    k = int(K, 16)

    P1 = kG(k, sm2_G, len_para)

    x = int(P1[:len_para], 16)
    R = (e + x) % sm2_N
    if R == 0 or R + k == sm2_N:
        return None
    d_1 = pow(d + 1, sm2_N - 2, sm2_N)
    S = (d_1 * (k + R) - R) % sm2_N
    s = '%0{}x%0{}x'.format(len_para, len_para) % (R, S) if S else None
    return bytes.fromhex(s)


def Encrypt(M, PA, len_para, Hexstr=0, encoding='utf-8', hash_algorithm='sm3',
            mode='C1C3C2'):
    """
    encrypt function
    :param M: message
    :param PA: PA public key
    :param len_para: currently fixed to 64
    :param Hexstr: whether M is hex string
    :param encoding: if M is not hex string
    :param hash_algorithm:
    :param mode: ciphertext mode, 'C1C3C2' (default, same as gmssl)
                 or 'C1C2C3'
    :return:
    """
    if Hexstr:
        msg = M  # input message itself is hex string
    else:
        if isinstance(M, str):
            msg = M.encode(encoding)
        else:
            msg = M
        msg = msg.hex()  # convert message to hex string
    if isinstance(PA, str):
        pass
    elif isinstance(PA, (bytes, bytearray)):
        PA = PA.hex()
    else:
        raise ValueError('Typeof PA must be string or bytes')
    k = get_random_str(len_para)
    # k = '59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21'
    # k = '384F30353073AEECE7A1654330A96204D37982A3E15B2CB5'
    C1 = kG(int(k, 16), sm2_G, len_para)
    # print('C1 = %s'%C1)
    xy = kG(int(k, 16), PA, len_para)
    # print('xy = %s' % xy)
    x2 = xy[0:len_para]
    y2 = xy[len_para:2 * len_para]
    ml = len(msg)
    t = KDF(xy, ml // 2)
    if int(t, 16) == 0:
        return None
    else:
        form = '%%0%dx' % ml
        C2 = form % (int(msg, 16) ^ int(t, 16))
        # print('C2 = %s'% C2)
        # print('%s%s%s'% (x2,msg,y2))
        C3 = get_hash(hash_algorithm, '%s%s%s' % (x2, msg, y2), Hexstr=1)
        # print('C3 = %s' % C3)
        if mode == 'C1C2C3':
            return bytes.fromhex('%s%s%s' % (C1, C2, C3))
        else:
            return bytes.fromhex('%s%s%s' % (C1, C3, C2))


def Decrypt(C, DA, len_para, Hexstr=0, encoding='utf-8', hash_algorithm='sm3',
            mode='C1C3C2'):
    """
    decrypt function,
    :param C ciphertext (hex string)
    :param DA private key
    :param len_para length, currently only supports 64
    :param mode: ciphertext mode, 'C1C3C2' (default, same as gmssl)
                 or 'C1C2C3'
    """
    f = getattr(hashlib, hash_algorithm)()
    if isinstance(DA, str):
        pass
    elif isinstance(DA, (bytes, bytearray)):
        DA = DA.hex()
    else:
        raise ValueError('DA must be str or bytes')
    len_2 = 2 * len_para
    len_3 = len_2 + f.digest_size * 2
    if not Hexstr:
        if isinstance(C, bytes):
            C = C.hex()

    if mode == 'C1C2C3':
        C1 = C[0:len_2]
        hash_len = f.digest_size * 2
        C3 = C[-hash_len:]
        C2 = C[len_2:-hash_len]
    else:
        C1 = C[0:len_2]
        C3 = C[len_2:len_3]
        C2 = C[len_3:]
    xy = kG(int(DA, 16), C1, len_para)
    # print('xy = %s' % xy)
    x2 = xy[0:len_para]
    y2 = xy[len_para:len_2]
    cl = len(C2)
    # print(cl)
    t = KDF(xy, cl // 2)
    if int(t, 16) == 0:
        return None
    else:
        form = '%%0%dx' % cl
        M = form % (int(C2, 16) ^ int(t, 16))
        # print('M = %s' % M)

        u = get_hash(hash_algorithm, '%s%s%s' % (x2, M, y2), 1)
        return bytes.fromhex(M) if u == C3 else None


KeyPair = namedtuple('KeyPair', ['publicKey', 'privateKey'])


def generate_keypair(len_param=64):
    d = get_random_str(len_param)
    PA = kG(int(d, 16), sm2_G, len_param)
    return KeyPair(bytes.fromhex(PA), bytes.fromhex(d))

if __name__ == '__main__':
    print(generate_keypair(64))
