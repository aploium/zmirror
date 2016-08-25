# coding=utf-8
import os
import sys
import unittest

SCRIPT_DIR = os.path.dirname(os.path.realpath(os.path.join(os.getcwd(), os.path.expanduser(__file__))))
PARENT_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, '..'))
sys.path.append(os.path.normpath(os.path.join(SCRIPT_DIR, '..')))

from .test_default_mirror import TestDefaultMirror
from .test_httpbin import TestHttpbin
from .test_verification import TestVerification

if __name__ == '__main__':
    unittest.main()
