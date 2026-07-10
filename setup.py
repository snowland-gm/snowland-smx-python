#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/9/22 0005 下午 22:29
# @Author  : 河北雪域网络科技有限公司 A.Star
# @Site    : 
# @File    : setup.py
# @Software: PyCharm


import re
from pathlib import Path
from setuptools import setup, find_packages

HERE = Path(__file__).resolve().parent


def load_install_requires(filename='requirements.txt'):
    """Load install requirements from a file, skipping comments and blanks."""
    return [line.strip() for line in (HERE / filename).read_text().splitlines()
            if line.strip() and not line.strip().startswith('#')]


def get_version():
    """Extract version string from pysmx/__init__.py without importing."""
    content = (HERE / 'pysmx' / '__init__.py').read_text()
    match = re.search(r"__version__\s*=\s*['\"]([^'\"]+)['\"]", content)
    if match:
        return match.group(1)
    raise RuntimeError("Unable to find version string")


def get_readme():
    return (HERE / 'README.en.md').read_text(encoding='utf-8')


setup(
    name="snowland-smx",
    version=get_version(),
    description=(
        'Python implementation gm algorithm'
    ),
    long_description=get_readme(),
    long_description_content_type="text/markdown",
    author='A.Star',
    author_email='astar@snowland.ltd',
    maintainer='A.Star',
    maintainer_email='astar@snowland.ltd',
    license='BSD-3-Clause',
    packages=find_packages(include=['pysmx', 'pysmx.*']),
    platforms=["all"],
    url='https://github.com/snowland-gm/snowland-smx-python',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Operating System :: OS Independent',
        'Intended Audience :: Developers',
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
    extras_require={
        'test': load_install_requires('test_requirements.txt'),
    },
)
