# coding=utf-8
import os
import unittest
from tests import *

if __name__ == '__main__':
    os.environ['ZMIRROR_UNITTEST'] = "True"
    unittest.main()
