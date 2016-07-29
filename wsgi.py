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
    from zmirror import my_host_port

    if my_host_port is None:
        my_host_port = 80

    application.run(
        port=my_host_port,
        threaded=True,

        debug=True,  # 如果你想直接用本程序给外网访问, 请把debug设置成 False (大小写敏感), 或者注释掉本行
        # host='0.0.0.0',  # 默认只允许本机访问, 如果你希望让外网访问, 请去掉本行的注释
    )
