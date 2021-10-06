#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: 深圳星河软通科技有限公司 A.Star
# @contact: astar@snowland.ltd
# @site: www.astar.ltd
# @file: _padding .py
# @time: 2021/1/26 18:11
# @Software: PyCharm


def PKCS5Padding(text, block_size=16):
    """
    PKCS7填充方法
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


def PKCS5UnPadding(text, block_size=16):
    """
    PKCS7填充方法
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


PKCS7Padding = PKCS5Padding
PKCS7UnPadding = PKCS5UnPadding

padding_map = {
    'pkcs5': PKCS5Padding,
    'pkcs7': PKCS7Padding
}

unpadding_map = {
    'pkcs5': PKCS5UnPadding,
    'PKCS7': PKCS7UnPadding
}
