#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/9/22 0005 下午 22:29
# @Author  : 河北雪域网络科技有限公司 A.Star
# @Site    : 
# @File    : setup.py
# @Software: PyCharm


from setuptools import setup, find_packages
from astartool.setuptool import load_install_requires
import pysmx

setup(
    name="snowland-smx",
    version=pysmx.__version__,
    description=(
        'Python implementation gm algorithm'
    ),
    long_description=open('README.en.md').read(),
    long_description_content_type="text/markdown",
    author='A.Star',
    author_email='astar@snowland.ltd',
    maintainer='A.Star',
    maintainer_email='astar@snowland.ltd',
    license='BSD License',
    packages=find_packages('pysmx'),
    platforms=["all"],
    url='https://gitee.com/snowlandltd/snowland-smx-python',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Operating System :: OS Independent',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python',
        'Programming Language :: Python :: Implementation',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Topic :: Software Development :: Libraries'
    ],
    install_requires=load_install_requires(),
    test_install_requires=load_install_requires('test_requirements.txt'),
)
