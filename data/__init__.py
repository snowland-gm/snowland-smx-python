#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @file: __init__.py
#
# Data directory for test vectors, sample files, and demo assets.
# All pysmx/test/ and pysmx/demo/ modules should read data from here
# via get_data_path().
#

import pathlib


_DATA_DIR = pathlib.Path(__file__).resolve().parent


def get_data_path(*parts):
    """Return absolute path to a file in the data/ directory.

    Usage::

        from data import get_data_path
        path = get_data_path('test2.txt')
    """
    return str(_DATA_DIR.joinpath(*parts))
