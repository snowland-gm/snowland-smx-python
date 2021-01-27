#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: 深圳星河软通科技有限公司 A.Star
# @contact: astar@snowland.ltd
# @site: www.astar.ltd
# @file: demo_sm4 .py
# @time: 2021/1/26 18:51
# @Software: PyCharm

from pysmx.SM4 import SM4, ENCRYPT, DECRYPT
import time


if __name__ == "__main__":
    # log_init()
    import numpy as np
    input_data = b''.join(np.random.randint(256, size=1024))
    iv_data = [0] * 16
    time.clock()
    sm4_d = SM4()
    key_data = b'hello world, errr...'
    # key_data = [0x5a] * 16
    sm4_d.sm4_set_key(key_data, ENCRYPT)
    st = time.clock()
    en_data = sm4_d.sm4_crypt_ecb(input_data)
    print(en_data, "en_data:")
    sm4_d.sm4_set_key(key_data, DECRYPT)
    de_data = sm4_d.sm4_crypt_ecb(en_data)
    print(de_data, "de_data:")
    print(bytes(input_data))
    if de_data == input_data:
        print("ecb check pass")
    else:
        print("ecb check fail")
        raise BaseException("error")
    et = time.clock()
    print(et-st)
    sm4_d.sm4_set_key(key_data, ENCRYPT)
    en_data = sm4_d.sm4_crypt_cbc(iv_data, input_data)
    print(en_data, "en_data:")
    sm4_d.sm4_set_key(key_data, DECRYPT)
    de_data = sm4_d.sm4_crypt_cbc(iv_data, en_data)
    print(de_data, "de_data:")
    if de_data == input_data:
        print("cbc check pass")
    else:
        print("cbc check fail")
        raise BaseException("error")
    # file test
    file_path = r"../../test2.txt"
    ecb_path_en = r"../../test2k_ecb_en.txt"
    ecb_path_de = r"../../test2k_ecb_de.txt"
    cbc_path_en = r"../../test2k_cbc_en.txt"
    cbc_path_de = r"../../test2k_cbc_de.txt"

    key_data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    iv_data = [0x5a] * 16

    with open(file_path, 'rb') as f:
        file_data = f.read()
    # file_data_list = [ord(x) for x in file_data]
    file_data_list = file_data
    # 1. ECB
    sm4_d = SM4()
    sm4_d.sm4_set_key(key_data, ENCRYPT)
    en_data = sm4_d.sm4_crypt_ecb(file_data_list)
    with open(ecb_path_en, 'wb') as f:
        f.write(bytes(en_data))

    sm4_d.sm4_set_key(key_data, DECRYPT)
    de_data = sm4_d.sm4_crypt_ecb(en_data)
    with open(ecb_path_de, 'wb') as f:
        f.write(bytes(de_data))
    if de_data == file_data_list:
        print("file decode pass")
    else:
        print("file decode fail")
        raise BaseException('error')

    # 2. CBC
    sm4_d.sm4_set_key(key_data, ENCRYPT)
    en_data = sm4_d.sm4_crypt_cbc(iv_data, file_data_list)
    with open(cbc_path_en, 'wb') as f:
        f.write(bytes(en_data))

    sm4_d.sm4_set_key(key_data, DECRYPT)
    de_data = sm4_d.sm4_crypt_cbc(iv_data, en_data)
    with open(cbc_path_de, 'wb') as f:
        f.write(bytes(de_data))
    if de_data == file_data_list:
        print("file decode pass")
    else:
        print("file decode fail")
        raise BaseException("error")