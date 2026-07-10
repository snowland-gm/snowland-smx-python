#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @contact: astar@snowland.ltd
# @file: _algorithm.py .py
# @time: 2021/2/8 21:49
# @Software: PyCharm

from cryptography import utils

from cryptography.hazmat.primitives.hashes import HashAlgorithm


class SM3HashAlgorithm(object):
    name = "sm3"
    digest_size = 64
    block_size = 64

    def update(self):
        pass


HashAlgorithm.register(SM3HashAlgorithm)


