# coding=utf-8
import tempfile
import time
import pickle
from datetime import datetime

EXPIRE_NOW = 0
EXPIRE_1MIN = 60
EXPIRE_5MIN = EXPIRE_1MIN * 5
EXPIRE_1HR = EXPIRE_1MIN * 60
EXPIRE_2HR = EXPIRE_1HR * 2
EXPIRE_6HR = EXPIRE_1HR * 6
EXPIRE_12HR = EXPIRE_1HR * 12
EXPIRE_1DAY = EXPIRE_1HR * 24
EXPIRE_1WEEK = EXPIRE_1DAY * 7
EXPIRE_1MOUTH = EXPIRE_1DAY * 31
EXPIRE_1YR = EXPIRE_1DAY * 365

DEFAULT_EXPIRE = EXPIRE_5MIN
mime_expire_list = {
    'application/javascript': EXPIRE_1YR,
    'application/x-javascript': EXPIRE_1YR,
    'text/javascript': EXPIRE_1YR,

    'text/css': EXPIRE_1MOUTH,

    'audio/ogg': EXPIRE_1MOUTH,
    'image/bmp': EXPIRE_1MOUTH,
    'image/gif': EXPIRE_1MOUTH,
    'image/jpeg': EXPIRE_1MOUTH,
    'image/png': EXPIRE_1MOUTH,
    'image/svg+xml': EXPIRE_1MOUTH,
    'image/webp': EXPIRE_1MOUTH,
    'video/mp4': EXPIRE_1MOUTH,
    'video/ogg': EXPIRE_1MOUTH,
    'video/webm': EXPIRE_1MOUTH,

    'application/vnd.ms-fontobject': EXPIRE_1MOUTH,
    'font/eot': EXPIRE_1MOUTH,
    'font/opentype': EXPIRE_1MOUTH,
    'application/x-font-ttf': EXPIRE_1MOUTH,
    'application/font-woff': EXPIRE_1MOUTH,
    'application/x-font-woff': EXPIRE_1MOUTH,
    'font/woff': EXPIRE_1MOUTH,
    'application/font-woff2': EXPIRE_1MOUTH,

    'image/vnd.microsoft.icon': EXPIRE_1WEEK,
    'image/x-icon': EXPIRE_1WEEK,
    'application/manifest+json': EXPIRE_1WEEK,
    'text/x-cross-domain-policy': EXPIRE_1WEEK,

    'application/atom+xml': EXPIRE_1HR,
    'application/rss+xml': EXPIRE_1HR,

    'application/json': EXPIRE_NOW,
    'application/ld+json': EXPIRE_NOW,
    'application/schema+json': EXPIRE_NOW,
    'application/vnd.geo+json': EXPIRE_NOW,
    'application/xml': EXPIRE_NOW,
    'text/xml': EXPIRE_NOW,
    'text/html': EXPIRE_NOW,
    'application/x-web-app-manifest+json': EXPIRE_NOW,
    'text/cache-manifest': EXPIRE_NOW,
}


def get_expire_from_mime(mime):
    return mime_expire_list.get(mime, DEFAULT_EXPIRE)


def _time_str_to_unix(timestring):
    try:
        t = int(time.mktime(datetime.strptime(timestring, '%a, %d %b %Y %H:%M:%S %Z').timetuple()))
    except:
        t = None
    return t


class FileCache:
    def __init__(self, max_size_kb=2048):
        self.cachedir = tempfile.TemporaryDirectory(prefix='mirror_')
        self.items_dict = {}
        self.max_size_byte = max_size_kb * 1024

    def put_obj(self, key, obj, expires=43200, obj_size=0, last_modified=None, info_dict=None):
        """

        :param last_modified: str  format: "Mon, 18 Nov 2013 09:02:42 GMT"
        :param obj_size: too big object should not be cached
        :param expires: seconds to expire
        :param info_dict: custom dict contains information, stored in memory, so can access quickly
        :type last_modified: str
        :type info_dict: dict or None
        :type obj: object
        """
        if expires <= 0:
            return False
        if obj_size > self.max_size_byte:
            return False

        temp_file = tempfile.TemporaryFile(dir=self.cachedir.name)
        pickle.dump(obj, temp_file)

        cache_item = (
            temp_file,  # 0 cache file object
            info_dict,  # 1 custom dict contains information
            int(time.time()),  # 2 added time (unix time)
            expires,  # 3 expires second
            _time_str_to_unix(last_modified),  # 4 last modified, unix time
        )
        self.items_dict[key] = cache_item
        return True

    def delete(self, key):
        if self._is_item_exist(key):
            self.items_dict[key][0].close()
            del self.items_dict[key]

    def check_all_expire(self):
        keys_to_delete = []
        for item_key in self.items_dict:
            if self.is_expires(item_key):
                keys_to_delete.append(item_key)
        for key in keys_to_delete:
            self.delete(key)

    def is_cached(self, key):
        if not self._is_item_exist(key):
            return False
        if self.is_expires(key):
            self.delete(key)
            return False
        else:
            return True

    def get_obj(self, key):
        if self._is_item_exist(key):
            fp = self.items_dict[key][0]
            fp.seek(0)
            return pickle.load(fp)
        else:
            return None

    def get_info(self, key):
        if self._is_item_exist(key):
            return self.items_dict[key][1]
        else:
            return None

    def is_unchanged(self, key, last_modified=None):

        if not self._is_item_exist(key) or last_modified is None:
            return False
        else:
            ct = self.items_dict[key][4]
            if ct is None:
                return False
            elif ct == _time_str_to_unix(last_modified):
                return True

    def is_expires(self, key):
        item = self.items_dict[key]
        if time.time() > item[2] + item[3]:
            return True
        return False

    def _is_item_exist(self, key):
        return key in self.items_dict
