#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @contact: astar@snowland.ltd
# @file: random.py
# @time: 2024/01/01
# @Software: PyCharm

"""Cryptographically secure random helpers (CSPRNG).

All helpers are backed by :mod:`secrets` / :mod:`os.urandom` so the output is
suitable for cryptographic material such as SM2 private keys and SM2/SM9
ephemeral values, complying with GM/T 0003 / GM/T 0009.

These helpers are the single source of randomness for the whole package.
"""

import os
import secrets


def random_bytes(n: int) -> bytes:
    """Return *n* cryptographically secure random bytes.

    Raises ``ValueError`` if *n* is negative.
    """
    if n < 0:
        raise ValueError('n must be non-negative')
    return os.urandom(n)


def random_int(upper: int) -> int:
    """Return a cryptographically secure random integer in ``[1, upper - 1]``.

    The result is directly usable as a scalar (private key / random value)
    over a prime-order group whose order is *upper*.

    Raises ``ValueError`` if *upper* is not greater than 2.
    """
    if upper <= 2:
        raise ValueError('upper must be greater than 2')
    return secrets.randbelow(upper - 1) + 1


def random_hex(n: int) -> str:
    """Return a cryptographically secure lower-case hex string of *2n* digits.

    The hex string is the hexadecimal encoding of *n* random bytes produced by
    :func:`random_bytes`.
    """
    return random_bytes(n).hex()
