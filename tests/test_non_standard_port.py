# coding=utf-8
import json
from pprint import pprint
from flask import Response
import requests
from urllib.parse import quote_plus, unquote_plus

from .test_httpbin import TestHttpbin
from .utils import *


class TestNonStandardPort(TestHttpbin):
    """testing using https://httpbin.org/"""

    class C(TestHttpbin.C):
        my_host_port = 233

