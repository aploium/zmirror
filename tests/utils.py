# coding=utf-8
import os
import shutil
import json
import random
from flask import Response

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

    try:
        os.remove(zmirror_file('ip_whitelist.txt'))
    except:
        pass
    try:
        os.remove(zmirror_file('ip_whitelist.log'))
    except:
        pass
    try:
        os.remove(zmirror_file('automatic_domains_whitelist.log'))
    except:
        pass

        # 下面是flask的一个trick, 强行生成多个不同的flask client 对象
        # with open(zmirror_file('config.py'), 'a', encoding='utf-8') as fp:
        #     fp.write('\n')
        #     fp.write('import random\n')
        #     fp.write('from flask import Flask\n')
        #     fp.write("unittest_app = Flask('unittest' + str(random.random()).replace('.', ''))\n")


def restore_config_file():
    os.remove(zmirror_file('config.py'))
    os.remove(zmirror_file('custom_func.py'))
    if os.path.exists(zmirror_file('config.py._unittest_raw')):
        shutil.move(zmirror_file('config.py._unittest_raw'), zmirror_file('config.py'))
    if os.path.exists(zmirror_file('custom_func.py._unittest_raw')):
        shutil.move(zmirror_file('custom_func.py._unittest_raw'), zmirror_file('custom_func.py'))

    try:
        os.remove(zmirror_file('ip_whitelist.txt'))
    except:
        pass
    try:
        os.remove(zmirror_file('ip_whitelist.log'))
    except:
        pass
    try:
        os.remove(zmirror_file('automatic_domains_whitelist.log'))
    except:
        pass


def env(ip="1.2.3.4", **kwargs):
    """
    :rtype: dict
    """
    result = {"REMOTE_ADDR": ip}
    result.update(kwargs)
    return result


DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; WOW64) " \
                     "AppleWebKit/537.36 (KHTML, like Gecko) " \
                     "Chrome/52.0.2743.116 Safari/537.36"


def headers(
        accept_encoding="gzip, deflate, sdch, br",
        user_agent=DEFAULT_USER_AGENT,
        others=None,
        **kwargs
):
    """
    :rtype: dict
    """
    result = {"accept-encoding": accept_encoding,
              "user-agent": user_agent}
    result.update(kwargs)
    if others is not None:
        result.update(others)
    return result


def load_rv_json(rv):
    """

    :type rv: Response
    :rtype: dict
    """
    return json.loads(rv.data.decode(encoding='utf-8'))


def attributes(var):
    def _strx(*_args):
        """
        :return: str
        """
        _output = ''
        for _arg in _args:
            _output += str(_arg) + ' '
        _output.rstrip(' ')
        return _output

    output = ""
    for name in dir(var):
        if name[0] != '_' and name[-2:] != '__':
            value = str(getattr(var, name))
            length = len(value)

            if length > 1024:
                value = value[:1024] + "....(total:{})".format(length)
            output += _strx(name, ":", value, "\n")
    return output


def slash_esc(string):
    """
    :type string: str
    :rtype: str
    """
    return string.replace("/", r"\/")


def slash_unesc(string):
    """
    :type string: str
    :rtype: str
    """
    return string.replace(r"\/", "/")


def rand_unicode(length=8):
    """
    :type length: int
    :rtype: str
    """
    return "".join(chr(random.randint(0, 50000)) for _ in range(length))


def rv_dmp(rv):
    """
    :type rv: Response
    :rtype: str
    """
    from pprint import pformat
    dump = "\n------------- rv -------------\n"
    dump += attributes(rv)
    dump += "\n------------- rv.headers -------------\n"
    dump += pformat(rv.headers.items())
    dump += "\n------------- end dump -------------\n"
