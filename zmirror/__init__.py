# coding=utf-8
import os
if "ZMIRROR_UNITTEST" not in os.environ:
    from .zmirror import *
else:
    print("unittest!")
