#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: 深圳星河软通科技有限公司 A.Star
# @contact: astar@snowland.ltd
# @site: www.astar.ltd
# @file: _primitives .py
# @time: 2021/2/8 19:45
# @Software: PyCharm

from cryptography.hazmat.primitives.ciphers import BlockCipherAlgorithm, algorithms, modes, CipherAlgorithm


class SM4BlockCipherAlgorithm(BlockCipherAlgorithm):
    name = "sm4"
    key_size = 16
    block_size = 16
