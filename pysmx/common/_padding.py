#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: 深圳星河软通科技有限公司 A.Star
# @contact: astar@snowland.ltd
# @site: www.astar.ltd
# @file: _padding .py
# @time: 2021/1/26 18:11
# @Software: PyCharm

from cryptography.hazmat.backends.openssl.ciphers import *


def PKCS7Padding(text, block_size=16):
    """
    PKCS7/PKCS5填充方法
    :param text:
    :param block_size:
    :return:
    """

    if len(text) % block_size:
        add = block_size - (len(text) % block_size)
    else:
        add = block_size
    if isinstance(text, list):
        text = text + [add] * add
    elif isinstance(text, bytes):
        text = text + chr(add).encode() * add
    elif isinstance(text, str):
        text = text + chr(add) * add
    else:
        raise ValueError("type(text) error !")
    return text


def PKCS7UnPadding(text, block_size=16):
    """
    PKCS7/PKCS5填充方法
    :param output:
    :return:
    """

    if isinstance(text, list):
        pad = text[-1]
    elif isinstance(text, bytes):
        pad = int(text[-1])
    elif isinstance(text, str):
        pad = ord(text[-1])
    else:
        raise ValueError("type(text) error !")
    return text[:-pad]


def ZeroPadding(text, block_size=16):
    if len(text) % block_size:
        add = block_size - (len(text) % block_size)
    else:
        add = 0
    if isinstance(text, list):
        text = text + [0] * add
    elif isinstance(text, bytes):
        text = text + b'\0' * add
    elif isinstance(text, str):
        text = text + '\0' * add
    else:
        raise ValueError("type(text) error !")
    return text


def ZeroUnPadding(text, block_size=16):
    if isinstance(text, list):
        while text:
            if '\0' == text[-1]:
                text.pop()
            else:
                break
    elif isinstance(text, bytes):
        text = text.rstrip(b'\0')
    elif isinstance(text, str):
        text = text.rstrip('\0')
    else:
        raise ValueError("type(text) error !")
    return text


def ISO10126Padding(text, block_size=16):
    if len(text) % block_size:
        add = block_size - (len(text) % block_size)
    else:
        add = block_size
    if isinstance(text, list):
        text = text + [0] * (add - 1) + [add]
    elif isinstance(text, bytes):
        text = text + b'\0' * (add - 1) + chr(add).encode()
    elif isinstance(text, str):
        text = text + '\0' * (add - 1) + chr(add)
    else:
        raise ValueError("type(text) error !")
    return text


def ISO10126UnPadding(text, block_size=16):
    if isinstance(text, list):
        pad = text[-1]
    elif isinstance(text, bytes):
        pad = int(text[-1])
    elif isinstance(text, str):
        pad = ord(text[-1])
    else:
        raise ValueError("type(text) error !")
    return text[:-pad]


def NoPadding(text, block_size=16):
    return text


def NoUnPadding(text, block_size=16):
    return text


PKCS5Padding = lambda x, b: PKCS7Padding(x, 8)
PKCS5UnPadding = lambda x, b: PKCS7UnPadding(x, 8)


padding_map = {
    'no': NoPadding,
    'pkcs5': PKCS5Padding,
    'pkcs7': PKCS7Padding,
    'zero': ZeroPadding,
    'iso10126': ISO10126Padding
}

unpadding_map = {
    'pkcs5': PKCS5UnPadding,
    'pcks7': PKCS7UnPadding,
    'zero': ZeroUnPadding,
    'iso10126': ISO10126UnPadding
}
