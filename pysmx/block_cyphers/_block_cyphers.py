#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: 深圳星河软通科技有限公司 A.Star
# @contact: astar@snowland.ltd
# @site: www.astar.ltd
# @file: _block_cyphers .py
# @time: 2021/1/27 21:26
# @Software: PyCharm

from abc import ABCMeta, abstractmethod
from pysmx.common import padding_map, unpadding_map
import copy
from cryptography.hazmat.bindings.openssl.binding import *
ENCRYPT = 0
DECRYPT = 1

__all__ = [
    'ENCRYPT',
    'DECRYPT',
    'BlockCyphers'
]


def XOR(a, b):
    return list(map(lambda x, y: x ^ y, a, b))


def XOR_BYTES(a, b):
    return bytes(map(lambda x, y: x ^ y, a, b))


class BlockCyphers(metaclass=ABCMeta):
    block_size = 16
    name = None

    def __init__(self, padding_method='pkcs5', unpadding_method=None):
        self.sk = [0] * 32
        self.mode = ENCRYPT
        self.block_size = 16
        self.__class__.block_size = 16

        if isinstance(padding_method, str):
            padding_method = padding_method.lower()
            if padding_method in padding_map:
                self.padding = padding_map[padding_method]
                self.unpadding = unpadding_map[padding_method]
            else:
                raise ModuleNotFoundError("Module %s Not Found" % padding_method)
        elif callable(padding_method) and callable(unpadding_method):
            self.padding = padding_method
            self.unpadding = unpadding_method
        else:
            def __func(text, bloke_size=64):
                return text

            self.padding = __func
            self.unpadding = __func
            raise UserWarning('Padding Method not Found')

    @abstractmethod
    def set_key(self, key, mode):
        """
        :return:
        """
        assert mode in (ENCRYPT, DECRYPT)

    @abstractmethod
    def one_round(self, sk, input_data) -> bytes:
        """
        块加密的一轮
        :param sk:
        :param input_data:
        :return:
        """
        pass

    def crypt_ecb(self, input_data):
        # SM4-ECB block encryption/decryption
        if self.mode == ENCRYPT:
            input_data = self.padding(input_data, self.block_size)
        tmp = [input_data[i:i + 16] for i in range(0, len(input_data), 16)]
        # output_data = reduce(lambda a, b: a + b, map(lambda x: self.sm4_one_round(self.sk, x), tmp), bytearray())
        output_data = b''.join(map(lambda x: self.one_round(self.sk, x), tmp))
        if self.mode == DECRYPT:
            output_data = self.unpadding(output_data)
        return output_data

    def crypt_cbc(self, iv, input_data):
        # SM4-CBC buffer encryption/decryption
        i = 0
        output_data = bytearray()
        tmp_input = [0] * 16
        if self.mode == ENCRYPT:
            input_data = self.padding(input_data, self.block_size)
            length = len(input_data)
            while length > 0:
                tmp_input[0:16] = XOR(input_data[i:i + 16], iv[0:16])
                output_data += self.one_round(self.sk, tmp_input[0:16])
                iv = copy.deepcopy(output_data[i:i + 16])
                i += 16
                length -= 16
        else:
            ivs = [input_data[i:i + 16] for i in range(0, len(input_data), 16)]
            ivs.insert(0, iv)
            tmp = map(lambda x: self.one_round(self.sk, x), ivs[1:])
            # output_data = reduce(lambda a, b: a + b, map(XOR, tmp, ivs[:-1]), bytearray())
            output_data = b''.join(map(XOR_BYTES, tmp, ivs[:-1]))
            output_data = self.unpadding(output_data, self.block_size)
        return bytes(output_data)

    def crypt_pcbc(self, iv, input_data):
        """
        SM4-PCBC buffer encryption/decryption
        :param iv:
        :param input_data:
        :return:
        """

        i = 0
        output_data = bytearray()
        if self.mode == ENCRYPT:
            input_data = self.padding(input_data, self.block_size)
            length = len(input_data)
            while length > 0:
                tmp_input = input_data[i:i + 16]
                out = self.one_round(self.sk, XOR(iv, tmp_input[0:16]))
                output_data.extend(out)
                iv = copy.deepcopy(XOR(out, tmp_input))
                i += 16
                length -= 16
        else:
            length = len(input_data)
            while length > 0:
                tmp_input = input_data[i:i + 16]
                out = self.one_round(self.sk, tmp_input[0:16])
                out = XOR(out, iv)
                iv = copy.deepcopy(XOR(out, tmp_input))
                output_data.extend(out)
                i += 16
                length -= 16
            output_data = self.unpadding(output_data, self.block_size)
        return bytes(output_data)

    def crypt_ofb(self, iv, input_data) -> bytes:
        """
        SM4-OFB buffer encryption/decryption
        :param iv:
        :param input_data:
        :return:
        """
        i = 0
        output_data = bytearray()
        if self.mode == ENCRYPT:
            input_data = self.padding(input_data, self.block_size)
            length = len(input_data)
            while length > 0:
                tmp_input = input_data[i:i + 16]
                out = self.one_round(self.sk, iv)
                iv = out
                out = XOR(out, tmp_input)
                output_data.extend(out)
                i += 16
                length -= 16
        else:
            length = len(input_data)
            self.mode = ENCRYPT
            self.sk = self.sk[::-1]
            while length > 0:
                tmp_input = input_data[i:i + 16]
                out = self.one_round(self.sk, iv)
                iv = out
                out = XOR(out, tmp_input)
                output_data.extend(out)
                i += 16
                length -= 16
            self.mode = DECRYPT
            self.sk = self.sk[::-1]
            output_data = self.padding(output_data, self.block_size)
        return bytes(output_data)

    def crypt_cfb(self, iv, input_data) -> bytes:
        """
        SM4-CFB buffer encryption/decryption
        :param iv:
        :param input_data:
        :return:
        """

        i = 0
        output_data = bytearray()
        if self.mode == ENCRYPT:
            input_data = self.padding(input_data, self.block_size)
            length = len(input_data)
            while length > 0:
                tmp_input = input_data[i:i + 16]
                out = self.one_round(self.sk, iv)
                iv = XOR(tmp_input, out)
                output_data.extend(iv)
                i += 16
                length -= 16
        else:
            self.mode = ENCRYPT
            self.sk = self.sk[::-1]
            length = len(input_data)
            while length > 0:
                tmp_input = input_data[i:i + 16]
                out = self.one_round(self.sk, iv)
                out = XOR(out, tmp_input)
                iv = tmp_input
                output_data.extend(out)
                i += 16
                length -= 16
            self.mode = DECRYPT
            self.sk = self.sk[::-1]
            output_data = self.unpadding(output_data)
        return bytes(output_data)
