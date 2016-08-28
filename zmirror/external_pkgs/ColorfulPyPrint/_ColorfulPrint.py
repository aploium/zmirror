from .thirdparty import init as colorama_init, Fore
from os import environ

if 'PYCHARM_HOSTED' in environ:
    is_convert = False  # in PyCharm, we should disable convert
    is_strip = False
else:
    is_convert = None
    is_strip = None
colorama_init(strip=is_strip, convert=is_convert)
