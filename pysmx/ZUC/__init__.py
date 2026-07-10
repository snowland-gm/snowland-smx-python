#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @contact: astar@snowland.ltd
# @file: __init__.py.py
# @time: 2018/11/18 22:32
# @Software: PyCharm


from pysmx.ZUC._ZUC import ZUC

try:
    from pysmx.ZUC._cryptography import (
        ZUCAlgorithm,
        zuc_encrypt,
        zuc_decrypt,
    )
except ImportError:
    pass
