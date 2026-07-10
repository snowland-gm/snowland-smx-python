#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @contact: astar@snowland.ltd
# @file: demo_sm3_cryptography .py
# @time: 2021/2/9 1:34
# @Software: PyCharm

from __future__ import print_function

import cryptography.hazmat.backends.openssl.backend
from cryptography.hazmat.primitives import hmac, hashes
from pysmx.SM3._algorithm import SM3HashAlgorithm
from pysmx.SM3._backend import SM3HashBackend, SM3HMACBackend



def run_sha256_test(key, testinput):
    backend = cryptography.hazmat.backends.openssl.backend
    sha256sum = hmac.HMAC(key, hashes.SHA256(), backend=backend)
    sha256sum.update(testinput)
    testoutput = sha256sum.finalize()
    print('SHA256 HMAC:', type(testoutput), testoutput)
    print(testoutput.hex())
    # print('verify:')
    # print(sha256sum.verify(testoutput))


def run_sha1_test(key, testinput):
    backend = cryptography.hazmat.backends.openssl.backend
    sha1sum = hmac.HMAC(key, hashes.SHA1(), backend=backend)
    sha1sum.update(testinput)
    testoutput = sha1sum.finalize()
    print('SHA1 HMAC:', type(testoutput), testoutput)
    print(testoutput.hex())
    # print('verify:')
    # print(sha1sum.verify(testoutput))

def run_sm3_test(key, testinput):
    backend = SM3HMACBackend()
    sm3sum = hmac.HMAC(key, SM3HashAlgorithm(), backend=backend)
    sm3sum.update(testinput)
    testoutput = sm3sum.finalize()
    print('sm3 HMAC:', type(testoutput), testoutput)
    print(testoutput.hex())
    # print('verify:')
    # print(sm3sum.verify(testoutput))


def main():
    data = b"abc"
    key = b"1234567890"
    print('Test input data:')
    print(data.decode('ascii'))
    # run_sha256_test(key, data)
    # run_sha1_test(key, data)
    run_sm3_test(key, data)


if '__main__' == __name__:
    main()
