#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: 深圳星河软通科技有限公司 A.Star
# @contact: astar@snowland.ltd
# @site: www.astar.ltd
# @file: _test_zuc .py
# @time: 2021/1/26 17:49
# @Software: PyCharm

from pysmx.ZUC import ZUC

if '__main__' == __name__:
    key = [0x00] * 16
    iv = [0x00] * 16
    zuc = ZUC(key, iv)
    # 加密过程
    import time

    b = (c for c in b"i love u" * 1000)
    t1 = time.clock()
    out = zuc.zuc_encrypt(b)
    t2 = time.clock()
    out_list = list(out)
    print("Lost time: ", t2 - t1)
    print("加密得到的字流", ["%08x" % e for e in out_list])
    # 解密过程
    zuc2 = ZUC(key, iv)
    dec = (e for e in out_list)
    t1 = time.clock()
    out2 = zuc2.zuc_encrypt(dec)
    t2 = time.clock()
    out2_list = list(out2)
    print("Lost time: ", t2 - t1)
    print("解密得到的字流", ["%08x" % e for e in out2_list])
    print(bytes(out2_list))
