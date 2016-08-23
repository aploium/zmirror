# coding=utf-8
import os
import shutil

basedir = os.path.dirname(os.path.abspath(__file__))
zmirror_dir = os.path.abspath(os.path.join(basedir, '..'))


def zmirror_file(filename):
    return os.path.join(zmirror_dir, filename)


def copy_default_config_file():
    if os.path.exists(zmirror_file('config.py')):
        print('[Waring] the config.py already exists, it would be temporary renamed to config.py._unittest_raw')
        shutil.move(zmirror_file('config.py'), zmirror_file('config.py._unittest_raw'))

    if os.path.exists(zmirror_file('custom_func.py')):
        print('[Waring] the custom_func.py already exists, it would be temporary renamed to custom_func.py._unittest_raw')
        shutil.move(zmirror_file('custom_func.py'), zmirror_file('custom_func.py._unittest_raw'))

    shutil.copy(zmirror_file('config_default.py'), zmirror_file('config.py'))
    shutil.copy(zmirror_file('custom_func.sample.py'), zmirror_file('custom_func.py'))


def restore_config_file():
    os.remove(zmirror_file('config.py'))
    os.remove(zmirror_file('custom_func.py'))
    if os.path.exists(zmirror_file('config.py._unittest_raw')):
        shutil.move(zmirror_file('config.py._unittest_raw'), zmirror_file('config.py'))
    if os.path.exists(zmirror_file('custom_func.py._unittest_raw')):
        shutil.move(zmirror_file('custom_func.py._unittest_raw'), zmirror_file('custom_func.py'))
