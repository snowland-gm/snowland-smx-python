#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @contact: astar@snowland.ltd
# @file: _SM4_stream.py
# @time: 2026/7/10
# @Software: PyCharm

"""
SM4 streaming (incremental) encryption/decryption.

Supports update()/finalize() pattern for processing large data without
loading everything into memory. All five modes are supported:
ECB, CBC, CFB, OFB, PCBC.
"""

from pysmx.SM4._SM4 import Sm4, XOR_BYTES
from pysmx.block_cyphers import ENCRYPT, DECRYPT
from pysmx.common import padding_map, unpadding_map


_METHODS = ('ecb', 'cbc', 'cfb', 'ofb', 'pcbc')


class SM4Stream:
    """Streaming SM4 cipher with incremental update()/finalize() interface.

    Supports ECB, CBC, CFB, OFB, PCBC modes.

    Basic usage::

        stream = SM4Stream(key, ENCRYPT, iv, method='cbc')
        ciphertext = stream.update(large_data_chunk1)
        ciphertext += stream.update(large_data_chunk2)
        ciphertext += stream.finalize()
    """

    block_size = 16

    def __init__(self, key, mode, iv=None, method='ecb',
                 padding_method='pkcs5'):
        if method not in _METHODS:
            raise ValueError(
                "Unknown method: %s. Must be one of %s" % (method, _METHODS))

        self._method = method
        self._mode = mode
        self._iv = bytes(iv[:self.block_size]) if iv else b'\x00' * self.block_size
        self._buffer = b''
        self._finished = False

        # Core Sm4 cipher with the requested mode key schedule
        self._sm4 = Sm4(padding_method=padding_method)
        self._sm4.set_key(bytes(key), mode)

        # For CFB/OFB, decryption also uses the encrypt-direction key schedule.
        # We keep a separate instance so update() can be called repeatedly
        # without mutating the shared key schedule.
        if method in ('cfb', 'ofb') and mode == DECRYPT:
            self._sm4_enc = Sm4(padding_method=padding_method)
            self._sm4_enc.set_key(bytes(key), ENCRYPT)
        else:
            self._sm4_enc = None

        # Resolve padding/unpadding callables
        self._padding, self._unpadding = self._resolve_padding(padding_method)

    @staticmethod
    def _resolve_padding(padding_method):
        if isinstance(padding_method, str):
            name = padding_method.lower()
            if name not in padding_map:
                raise ValueError("Unknown padding method: %s" % padding_method)
            return padding_map[name], unpadding_map[name]
        else:
            raise ValueError(
                "padding_method must be a string name, got %s" %
                type(padding_method))

    # -- Public API --------------------------------------------------------

    def update(self, data):
        """Feed data into the stream. Returns any processed output bytes.

        Args:
            data (bytes): Input data to process incrementally.

        Returns:
            bytes: Processed output (ciphertext for encryption,
                   plaintext for decryption). May be empty if there is not
                   enough data yet to form a complete block.
        """
        if self._finished:
            raise RuntimeError("Stream already finalized")
        if not data:
            return b''

        self._buffer += bytes(data)

        if self._mode == ENCRYPT:
            return self._dispatch_encrypt_update()
        else:
            return self._dispatch_decrypt_update()

    def finalize(self):
        """Finalize the stream and return remaining output.

        For encryption: pads the buffered data, processes the last block(s),
        and returns the final ciphertext.

        For decryption (ECB/CBC/PCBC): processes the remaining block(s),
        removes padding, and returns the final plaintext.

        For CFB/OFB decryption: processes remaining data (no padding).

        Returns:
            bytes: Remaining output after finalization.
        """
        if self._finished:
            raise RuntimeError("Stream already finalized")
        self._finished = True

        if self._mode == ENCRYPT:
            return self._finalize_encrypt()
        else:
            return self._finalize_decrypt()

    # -- Encrypt: update ------------------------------------------------

    def _dispatch_encrypt_update(self):
        m = self._method
        if m == 'ecb':
            return self._update_ecb()
        elif m == 'cbc':
            return self._update_cbc_encrypt()
        elif m == 'cfb':
            return self._update_cfb_ofb_common(self._sm4, feedback='output')
        elif m == 'ofb':
            return self._update_cfb_ofb_common(self._sm4, feedback='keystream')
        elif m == 'pcbc':
            return self._update_pcbc_encrypt()

    def _update_ecb(self):
        """ECB: process all complete 16-byte blocks."""
        n = (len(self._buffer) // self.block_size) * self.block_size
        if n == 0:
            return b''
        output = bytearray()
        for i in range(0, n, self.block_size):
            output += self._sm4.one_round(
                self._sm4.sk, self._buffer[i:i + self.block_size])
        self._buffer = self._buffer[n:]
        return bytes(output)

    def _update_cbc_encrypt(self):
        """CBC encrypt: XOR with IV, encrypt, output is new IV."""
        n = (len(self._buffer) // self.block_size) * self.block_size
        if n == 0:
            return b''
        output = bytearray()
        for i in range(0, n, self.block_size):
            block = XOR_BYTES(
                self._buffer[i:i + self.block_size], self._iv)
            cipher = self._sm4.one_round(self._sm4.sk, block)
            self._iv = cipher
            output += cipher
        self._buffer = self._buffer[n:]
        return bytes(output)

    def _update_cfb_ofb_common(self, sm4_instance, feedback):
        """CFB/OFB common: generate keystream, XOR with input.

        Returns processed output for complete blocks in buffer.
        """
        n = (len(self._buffer) // self.block_size) * self.block_size
        if n == 0:
            return b''
        output = self._process_cfb_ofb_blocks(
            sm4_instance, feedback, self._buffer[:n])
        self._buffer = self._buffer[n:]
        return output

    def _process_cfb_ofb_blocks(self, sm4_instance, feedback, data):
        """Process data in 16-byte blocks using CFB/OFB chaining.

        Returns output bytes and updates self._iv.
        """
        output = bytearray()
        for i in range(0, len(data), self.block_size):
            block = data[i:i + self.block_size]
            keystream = sm4_instance.one_round(sm4_instance.sk, self._iv)
            cipher = XOR_BYTES(block, keystream)
            if feedback == 'output':
                self._iv = cipher          # CFB
            else:
                self._iv = keystream       # OFB
            output += cipher
        return bytes(output)

    def _update_pcbc_encrypt(self):
        """PCBC encrypt: XOR(IV, plaintext), encrypt, IV = cipher XOR plain."""
        n = (len(self._buffer) // self.block_size) * self.block_size
        if n == 0:
            return b''
        output = bytearray()
        for i in range(0, n, self.block_size):
            block = self._buffer[i:i + self.block_size]
            cipher = self._sm4.one_round(
                self._sm4.sk, XOR_BYTES(self._iv, block))
            self._iv = XOR_BYTES(cipher, block)
            output += cipher
        self._buffer = self._buffer[n:]
        return bytes(output)

    # -- Decrypt: update ------------------------------------------------

    def _dispatch_decrypt_update(self):
        m = self._method
        if m == 'ecb':
            return self._update_withhold_last(self._decrypt_block_ecb)
        elif m == 'cbc':
            return self._update_withhold_last(self._decrypt_block_cbc)
        elif m == 'cfb':
            return self._update_withhold_last(self._decrypt_block_cfb_ofb)
        elif m == 'ofb':
            return self._update_withhold_last(self._decrypt_block_ofb)
        elif m == 'pcbc':
            return self._update_withhold_last(self._decrypt_block_pcbc)

    def _decrypt_block_cfb_ofb(self, data):
        """CFB decrypt: encrypt IV, XOR with ciphertext. Uses encrypt key.

        CFB feedback: IV = ciphertext (input block), not plaintext.
        """
        output = bytearray()
        for i in range(0, len(data), self.block_size):
            block = data[i:i + self.block_size]
            keystream = self._sm4_enc.one_round(self._sm4_enc.sk, self._iv)
            plain = XOR_BYTES(block, keystream)
            self._iv = block  # CFB: feedback ciphertext (input)
            output += plain
        return bytes(output)

    def _decrypt_block_ofb(self, data):
        """OFB decrypt: encrypt IV, XOR with ciphertext. Uses encrypt key."""
        return self._process_cfb_ofb_blocks(
            self._sm4_enc, 'keystream', data)

    def _update_withhold_last(self, process_func):
        """Process all but the last complete block.

        The last block is held back so that finalize() can decrypt and
        strip padding atomically.
        """
        block_count = len(self._buffer) // self.block_size
        if block_count <= 1:
            return b''  # hold the only/last block for finalize
        n = (block_count - 1) * self.block_size
        output = process_func(self._buffer[:n])
        self._buffer = self._buffer[n:]
        return output

    def _decrypt_block_ecb(self, data):
        output = bytearray()
        for i in range(0, len(data), self.block_size):
            output += self._sm4.one_round(
                self._sm4.sk, data[i:i + self.block_size])
        return bytes(output)

    def _decrypt_block_cbc(self, data):
        output = bytearray()
        for i in range(0, len(data), self.block_size):
            block = data[i:i + self.block_size]
            decrypted = self._sm4.one_round(self._sm4.sk, block)
            output += XOR_BYTES(decrypted, self._iv)
            self._iv = block  # next IV is the ciphertext
        return bytes(output)

    def _decrypt_block_pcbc(self, data):
        output = bytearray()
        for i in range(0, len(data), self.block_size):
            block = data[i:i + self.block_size]
            decrypted = self._sm4.one_round(self._sm4.sk, block)
            plain = XOR_BYTES(decrypted, self._iv)
            self._iv = XOR_BYTES(block, plain)  # IV = cipher XOR plain
            output += plain
        return bytes(output)

    # -- Encrypt: finalize ----------------------------------------------

    def _finalize_encrypt(self):
        data = self._buffer

        if self._method in ('ecb', 'cbc', 'pcbc', 'cfb', 'ofb'):
            data = self._padding(data, self.block_size)

        if not data:
            return b''

        if self._method == 'ecb':
            return self._encrypt_blocks_ecb(data)
        elif self._method == 'cbc':
            return self._encrypt_blocks_cbc(data)
        elif self._method == 'pcbc':
            return self._encrypt_blocks_pcbc(data)
        elif self._method == 'cfb':
            return self._process_cfb_ofb_blocks(
                self._sm4, 'output', data)
        elif self._method == 'ofb':
            return self._process_cfb_ofb_blocks(
                self._sm4, 'keystream', data)

    def _encrypt_blocks_ecb(self, data):
        output = bytearray()
        for i in range(0, len(data), self.block_size):
            output += self._sm4.one_round(
                self._sm4.sk, data[i:i + self.block_size])
        return bytes(output)

    def _encrypt_blocks_cbc(self, data):
        output = bytearray()
        for i in range(0, len(data), self.block_size):
            block = XOR_BYTES(data[i:i + self.block_size], self._iv)
            cipher = self._sm4.one_round(self._sm4.sk, block)
            self._iv = cipher
            output += cipher
        return bytes(output)

    def _encrypt_blocks_pcbc(self, data):
        output = bytearray()
        for i in range(0, len(data), self.block_size):
            block = data[i:i + self.block_size]
            cipher = self._sm4.one_round(
                self._sm4.sk, XOR_BYTES(self._iv, block))
            self._iv = XOR_BYTES(cipher, block)
            output += cipher
        return bytes(output)

    # -- Decrypt: finalize ----------------------------------------------

    def _finalize_decrypt(self):
        data = self._buffer

        if self._method in ('ecb', 'cbc', 'pcbc', 'cfb', 'ofb'):
            if len(data) % self.block_size != 0:
                raise ValueError(
                    "Incomplete block in %s mode decrypt: got %d bytes" %
                    (self._method, len(data)))
            if not data:
                raise ValueError("No data to finalize in %s mode" %
                                 self._method)
            result = self._decrypt_remaining(data)
            return self._unpadding(result)
        else:
            return b''

    def _decrypt_remaining(self, data):
        if self._method == 'ecb':
            return self._decrypt_block_ecb(data)
        elif self._method == 'cbc':
            return self._decrypt_block_cbc(data)
        elif self._method == 'pcbc':
            return self._decrypt_block_pcbc(data)
        elif self._method == 'cfb':
            return self._decrypt_block_cfb_ofb(data)
        elif self._method == 'ofb':
            return self._decrypt_block_ofb(data)
        return data
