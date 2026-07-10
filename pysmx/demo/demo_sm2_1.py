#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @contact: astar@snowland.ltd
# @file: demo.py
# @time: 2018/11/19 1:16
# @Software: PyCharm

import time
from pysmx.SM3 import SM3Type, digest, KDF
from pysmx.crypto.hashlib import pbkdf2_hmac
from collections import namedtuple
if __name__ == '__main__':
    from pysmx.SM2 import generate_keypair
    KeyPair = namedtuple('KeyPair', ['publicKey', 'privateKey'])
    # key = generate_keypair()
    # pk = key.publicKey
    # sk = key.privateKey
    pk = 'ImApkSAqfgyNbC/SOpG8PjD8oaoAI58YEJVr4VzkUtehT9m5rol0Tuu2tLRcpz3YFk9LxmDfFacD5oDpapVpcw=='
    sk = 'jeoVpYYVff+BvNscZQ4XMl0RIfPaVgwwK4xVBgi2dSY='
    print("sk:", sk)
    print("pk:", pk)
    a = bytes("abc"*10000, encoding='utf8')
    st = time.process_time_ns()
    y = digest(a)
    et = time.process_time_ns()
    print("sm3:", y)
    print("time:", et - st)
    klen = 19
    print(KDF("57E7B63623FAE5F08CDA468E872A20AFA03DED41BF1403770E040DC83AF31A67991F2B01EBF9EFD8881F0A0493000603", klen))
    sm = SM3Type()
    sm.update('abc')
    print(sm.digest())
    st = time.process_time_ns()
    a = pbkdf2_hmac('sm3', password=b"abc", salt=b'234', iterations=1000)
    et = time.process_time_ns()
    print(et-st)
