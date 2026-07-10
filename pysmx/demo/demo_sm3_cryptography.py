#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @contact: astar@snowland.ltd
# @file: demo_sm3_cryptography .py
# @time: 2021/2/9 1:34
# @Software: PyCharm

from __future__ import print_function

import cryptography.hazmat.backends.openssl.backend
from cryptography.hazmat.primitives import hashes
from pysmx.SM3._algorithm import SM3HashAlgorithm
from pysmx.SM3._backend import SM3HashBackend


def run_sha256_test(testinput):
    backend = cryptography.hazmat.backends.openssl.backend
    sha256sum = hashes.Hash(hashes.SHA256(), backend=backend)
    sha256sum.update(testinput)
    testoutput = sha256sum.finalize()
    print('SHA256 Digest:', type(testoutput), testoutput)
    print(testoutput.hex())


def run_sha1_test(testinput):
    backend = cryptography.hazmat.backends.openssl.backend
    sha256sum = hashes.Hash(hashes.SHA256(), backend=backend)
    sha1sum = hashes.Hash(hashes.SHA1(), backend=backend)
    sha1sum.update(testinput)
    testoutput = sha1sum.finalize()
    print('SHA1 Digest:', type(testoutput), testoutput)
    print(testoutput.hex())


def run_sm3_test(testinput):
    backend = SM3HashBackend()
    sm3sum = hashes.Hash(SM3HashAlgorithm(), backend=backend)
    sm3sum.update(testinput)
    testoutput = sm3sum.finalize()
    print('sm3 Digest:', type(testoutput), testoutput)
    print(testoutput.hex())


def main():
    data = b"abc"
    print('Test input data:')
    print(data.decode('ascii'))
    run_sha256_test(data)
    run_sha1_test(data)
    run_sm3_test(data)


if '__main__' == __name__:
    main()
