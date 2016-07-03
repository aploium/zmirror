#!/usr/bin/env python3
# coding=utf-8
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
if os.path.dirname(__file__) != '':
    os.chdir(os.path.dirname(__file__))
from zmirror import app as application

__author__ = 'Aploium <i@z.codes>'

if __name__ == '__main__':
    application.run(debug=True, port=80, threaded=True)
