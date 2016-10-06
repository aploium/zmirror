# coding=utf-8
import os
import unittest
from zmirror.tests import *

os.environ['ZMIRROR_UNITTEST'] = "True"

if __name__ == '__main__':
    unittest.main()
