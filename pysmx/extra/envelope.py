#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: 深圳星河软通科技有限公司 A.Star
# @contact: astar@snowland.ltd
# @site: www.astar.ltd
# @file: envelope .py
# @time: 2020/7/18 19:54
# @Software: PyCharm

from pysmx.SM2 import generate_keypair, Encrypt,Decrypt, KeyPair
from pysmx.SM4 import sm4_crypt_cbc, ENCRYPT, DECRYPT
from collections import namedtuple
from astartool.random._random import security_random_hex


def envelope_encrypt(
        message,
        key1=None,
        key2=None,
        algorithm1='SM2',
        algorithm2='SM4',
):
    """

    :param message:
    :param key1:
    :param key2:
    :param algorithm1:
    :param algorithm2:
    :return:
    """
    if not isinstance(message, (bytes, bytearray, memoryview)):
        raise ValueError('error type in message')

    if not key2:
        key2 = security_random_hex()
    if not key1:
        key1 = generate_keypair()
    if algorithm1 == 'SM2':
        e1 = Encrypt(message, key1.publicKey, len_para=64)
    else:
        raise ValueError('algorithm1 NOT FOUND')
    if algorithm2 == 'SM4':
        e2 = sm4_crypt_cbc(key=key2, data=key2)
    else:
        raise ValueError('algorithm2 NOT FOUND')
    return key1, key2, e1, e2


def envelope_decrypt(
        message_key: (bytes, bytearray, memoryview),
        message_data: (bytes, bytearray, memoryview),
        key1=None,
        algorithm1='SM2',
        algorithm2='SM4',
):
    """

    :param message:
    :param key1:
    :param key2:
    :return:
    """
    if not isinstance(message_key, (bytes, bytearray, memoryview)):
        raise ValueError('error type in message')
    if not isinstance(message_data, (bytes, bytearray, memoryview)):
        raise ValueError('error type in message')

    if isinstance(key1, KeyPair):
        key1 = key1.privatekey
    if algorithm1 == 'SM2':
        key2 = Decrypt(message_key, key1, len_para=64)
    else:
        raise ValueError('algorithm1 NOT FOUND')
    if algorithm2 == 'SM4':
        message = sm4_crypt_cbc(DECRYPT, key=key2, data=message_data)
    else:
        raise ValueError('algorithm2 NOT FOUND')
    return key2, message
