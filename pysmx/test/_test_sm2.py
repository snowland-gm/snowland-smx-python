#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: 深圳星河软通科技有限公司 A.Star
# @contact: astar@snowland.ltd
# @site: www.astar.ltd
# @file: _test .py
# @time: 2020/10/24 19:39
# @Software: PyCharm


import unittest

from astartool.random import random_string


class TestSM2(unittest.TestCase):
    def setUp(self):
        from pysmx.SM2 import generate_keypair
        import pysmx.SM2 as sm2
        self.pk, self.sk = generate_keypair()
        self.sm2 = sm2

    def test_rand_10000(self):
        s = random_string(1000)
        sb = s.encode()
        self.sm2.Encrypt()

