#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @contact: astar@snowland.ltd
# @file: _SM3.py
# @time: 2018/12/03 15:26
# @Software: PyCharm

from pysmx.common import (
    BIT_EACH_32, IV
)
from math import ceil
from functools import reduce
from copy import copy
import struct
import hashlib

def _rotl(x, k):
    return ((x << k) | (x >> (32 - k))) & 0xFFFFFFFF


def rotate_left(a, k):
    return _rotl(a, k % 32)


T_j = [0x79cc4519] * 16 + [0x7a879d8a] * 48
T_j_rotate_left = [rotate_left(Tj, j) for j, Tj in enumerate(T_j)]


def FF_j(X, Y, Z, j):
    # 已经融合到内部了
    return X ^ Y ^ Z if 0 <= j < 16 else (X & Y) | (X & Z) | (Y & Z)


def GG_j(X, Y, Z, j):
    # 已经融合在内部了
    return X ^ Y ^ Z if 0 <= j < 16 else (X & Y) | ((~ X) & Z)


def P_0(X):
    return X ^ _rotl(X, 9) ^ _rotl(X, 17)


def P_1(X):
    return X ^ _rotl(X, 15) ^ _rotl(X, 23)


def PUT_UINT32_BE(n):
    return [int((n >> 24) & 0xff), int((n >> 16) & 0xff), int((n >> 8) & 0xff), int(n & 0xff)]


def CF(V_i, B_i):
    W = [(B_i[ind] << 24) | (B_i[ind + 1] << 16) | (B_i[ind + 2] << 8) | B_i[ind + 3]
         for ind in range(0, 64, 4)]
    for j in range(16, 68):
        X = W[-16] ^ W[-9] ^ _rotl(W[-3], 15)
        W.append(P_1(X) ^ _rotl(W[-13], 7) ^ W[-6])
    W_1 = [W[j] ^ W[j + 4] for j in range(64)]
    A, B, C, D, E, F, G, H = V_i
    for j in range(0, 16):
        SS1 = _rotl((_rotl(A, 12) + E + T_j_rotate_left[j]) & 0xFFFFFFFF, 7)
        SS2 = SS1 ^ _rotl(A, 12)
        TT1 = ((A ^ B ^ C) + D + SS2 + W_1[j]) & 0xFFFFFFFF
        TT2 = ((E ^ F ^ G) + H + SS1 + W[j]) & 0xFFFFFFFF
        A, B, C, D, E, F, G, H = TT1, A, _rotl(B, 9), C, P_0(TT2), E, _rotl(F, 19), G
    for j in range(16, 64):
        SS1 = _rotl((_rotl(A, 12) + E + T_j_rotate_left[j]) & 0xFFFFFFFF, 7)
        SS2 = SS1 ^ _rotl(A, 12)
        TT1 = (((A & B) | (A & C) | (B & C)) + D + SS2 + W_1[j]) & 0xFFFFFFFF
        TT2 = (((E & F) | ((~E) & G)) + H + SS1 + W[j]) & 0xFFFFFFFF
        A, B, C, D, E, F, G, H = TT1, A, _rotl(B, 9), C, P_0(TT2), E, _rotl(F, 19), G
    return [A ^ V_i[0], B ^ V_i[1], C ^ V_i[2],
            D ^ V_i[3], E ^ V_i[4], F ^ V_i[5], G ^ V_i[6], H ^ V_i[7]]


def digest(msg, Hexstr=0):
    if isinstance(msg, list):
        pass
    else:
        msg = hex2byte(msg) if Hexstr else str2bytes(msg)
    len1 = len(msg)
    msg.append(0x80)
    reserve1 = len1 % 64 + 1
    range_end = 56 if reserve1 <= 56 else 120
    msg.extend([0] * (range_end - reserve1))
    bit_length = len1 * 8
    msg.extend(struct.pack(">Q", bit_length))
    B = (msg[i:i + 64] for i in range(0, len(msg), 64))
    y = reduce(CF, B, IV)
    b = bytearray()
    [b.extend(PUT_UINT32_BE(each)) for each in y]
    return bytes(b)


def hash_msg(msg):
    return digest(msg, 0).hex()


def str2bytes(msg: str, encoding='utf-8'):
    """
    字符串转换成byte数组
    :param msg: 信息串
    :param encoding: 编码
    :return:
    """
    msg_bytearray = msg.encode(encoding) if isinstance(msg, str) else msg
    return list(msg_bytearray)


def byte2str(msg, decode='utf-8'):
    """
    byte数组转字符串
    :param msg:
    :param decode:
    :return:
    """
    return msg.decode(decode) if isinstance(msg, (bytes, bytearray)) else msg


def hex2byte(msg):
    """
    16进制字符串转换成byte列表
    :param msg:
    :return:
    """
    if isinstance(msg, bytes):
        msg = msg.decode(encoding='utf8')
    if not isinstance(msg, str):
        raise ValueError('message must be string')
    ml = len(msg)
    if (ml & 1) != 0:
        msg = '0' + msg
    return list(bytes.fromhex(msg))


def Hash_sm3(msg, Hexstr=0):
    msg_byte = hex2byte(msg) if Hexstr else str2bytes(msg)
    return hash_msg(msg_byte)


hexdigest = Hash_sm3


def _BKDF(Z, klen: int):
    """
    :param Z: 16进制表示的比特串（str）或原始字节（bytes）
    :param klen: klen为密钥长度（单位byte）
    :return:
    """
    klen = int(klen)
    rcnt = int(ceil(klen / 32))
    Zin = hex2byte(Z) if isinstance(Z, str) else list(Z)
    b = bytearray()
    [b.extend(digest(Zin + PUT_UINT32_BE(ct), 0)) for ct in range(1, rcnt + 1)]
    return b[:klen]


def KDF(Z, klen: int):
    """
    :param Z: Z为16进制表示的比特串（str），
    :param klen: klen为密钥长度（单位byte）
    :return:
    """
    return _BKDF(Z, klen).hex()


class SM3Type(object):
    name = 'SM3'
    digest_size = 32
    block_size = 64

    def __init__(self, msg=b'', encoding='utf-8'):
        self.encoding = encoding
        # self.msg = bytearray(str2bytes(msg, self.encoding))

        self.__length = 0
        self.__block = []
        self.B = []
        self.iv = IV.copy()
        if len(msg) != 0:
            self.update(msg)

    def update(self, msg):
        """
        适用于大文件
        :param msg:
        :return:
        """
        b = str2bytes(msg, self.encoding)
        self.__length += len(b)
        self.__block += b
        len_block = len(self.__block)

        n_block, left = divmod(len_block, self.block_size)
        ind = n_block * self.block_size
        self.__digest_step(self.__block[:ind])
        self.__block = self.__block[ind:]

    def __digest_step(self, msg):
        """
        update的一步
        :param msg:
        :return:
        """
        len_msg = len(msg)
        if len_msg:
            B = (msg[i:i + 64] for i in range(0, len_msg, 64))
            self.iv = reduce(CF, B, self.iv)

    def digest(self):
        self.__block.append(0x80)
        reserve1 = self.__length % 64 + 1
        range_end = 56 if reserve1 <= 56 else 120
        self.__block.extend([0] * (range_end - reserve1))
        bit_length = self.__length * 8
        self.__block.extend(struct.pack(">Q", bit_length))
        len_block = len(self.__block)
        B = (self.__block[i:i + 64] for i in range(0, len_block, 64))
        y = reduce(CF, B, self.iv)
        b = bytearray()
        [b.extend(PUT_UINT32_BE(each)) for each in y]
        self.__clear()
        return bytes(b)

    def hexdigest(self):
        x = self.digest()
        return x.hex()

    def copy(self):
        return copy(self)

    def __clear(self):
        self.__length = 0
        self.__block = []
        self.B = []
        self.iv = IV.copy()


SM3 = SM3Type
