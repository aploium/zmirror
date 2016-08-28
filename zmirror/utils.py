# coding=utf-8
import os

ZMIRROR_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))


def zmirror_root(filename):
    return os.path.join(ZMIRROR_ROOT, filename)
