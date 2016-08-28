# -*- coding: UTF-8 -*-
import sys

extra_print_dests = []


class ExternalPrintBuffer:
    def __init__(self):
        self.buff = ''
        self.__console__ = sys.stdout

    def replace_stdout(self):
        sys.stdout = self

    def write(self, output_stream):
        self.buff += output_stream
        self.__console__.write(output_stream)

    def reset(self):
        sys.stdout = self.__console__


def clean_extra_output_destination():
    """
    clean extra print destination(s)
    :rtype: None
    """
    global extra_print_dests
    extra_print_dests = []


def add_extra_output_destination(writeable_object, important_level=0, name=None):
    """
    add extra places to print output to, object with .write() method is required

    :type name: str
    :type important_level: int
    :type writeable_object: file-like object
    """
    global extra_print_dests
    extra_print_dests.append({'dest': writeable_object,
                              'name': name,
                              'important_level': important_level
                              })
