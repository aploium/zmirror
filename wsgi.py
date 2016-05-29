#!/usr/bin/env python3
# coding=utf-8
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
from MagicWebsiteMirror import app as application

if __name__ == '__main__':
    application.run(debug=True, port=80, threaded=True)