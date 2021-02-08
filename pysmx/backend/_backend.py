#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: 深圳星河软通科技有限公司 A.Star
# @contact: astar@snowland.ltd
# @site: www.astar.ltd
# @file: _backend .py
# @time: 2021/2/9 1:41
# @Software: PyCharm

from cryptography.hazmat.backends.interfaces import HashBackend, CipherBackend, HMACBackend
from cryptography import utils
from pysmx.SM3._backend import SM3HashBackend

@utils.register_interface(SM3HashBackend)
class PysmxBackend():
    name = "pysmx"
