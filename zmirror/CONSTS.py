# coding=utf-8
import os

__VERSION_TUPLE__ = (0, 29, 4, "")
__VERSION__ = ".".join(str(x) for x in __VERSION_TUPLE__).rstrip(".")
__AUTHOR__ = 'Aploium <i@z.codes>'
__GITHUB_URL__ = 'https://github.com/aploium/zmirror'
ZMIRROR_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
