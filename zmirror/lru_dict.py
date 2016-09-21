# coding=utf-8
from collections import OrderedDict


class LRUDictManual(OrderedDict):  # pragma: no cover
    """一个手动实现的LRUDict"""

    def __init__(self, size=32):
        super().__init__()
        self.maxsize = size

    def __getitem__(self, key):
        value = super().__getitem__(key)
        try:
            self.move_to_end(key)
        except:
            pass
        return value

    # noinspection PyMethodOverriding
    def __setitem__(self, key, value):
        if len(self) >= self.maxsize:
            self.popitem(last=False)

        if key in self:
            del self[key]
        super().__setitem__(key, value)

    def keys(self):
        return list(reversed(list(super().keys())))

    def values(self):
        return list(reversed(list(super().values())))

    def items(self):
        return list(reversed(list(super().items())))

    def get_size(self):
        return len(self)

    def set_size(self, size):
        self.maxsize = size


try:
    # 如果安装了 lru-dict, 则导入, 否则使用上面的手动实现的 LRUDict
    from lru import LRU
except:
    LRUDict = LRUDictManual
else:
    LRUDict = LRU
