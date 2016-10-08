# coding=utf-8
import json
from pprint import pprint
from flask import Response
import requests
from urllib.parse import quote_plus, unquote_plus, urlencode

from .base_class import ZmirrorTestBase
from .utils import *


class TestVerification(ZmirrorTestBase):
    """testing using https://httpbin.org/"""

    class C(ZmirrorTestBase.C):
        my_host_name = 'b.test.com'
        my_host_scheme = 'https://'
        target_domain = 'httpbin.org'
        target_scheme = 'https://'
        external_domains = ('eu.httpbin.org',)
        force_https_domains = 'ALL'
        enable_automatic_domains_whitelist = False
        # verbose_level = 4
        possible_charsets = None

        human_ip_verification_enabled = True
        identity_verify_required = True
        enable_custom_access_cookie_generate_and_verify = True

        human_ip_verification_questions = (
            ('Unittest question one', '答案', 'Placeholder (Optional)'),
        )
        human_ip_verification_identity_record = (
            ("Please input your student/teacher ID number", "student_id", "text"),
            ("Please input your student/teacher password", "password", "password"),
        )
        must_verify_cookies = True

    class CaseCfg(ZmirrorTestBase.CaseCfg):
        tip_texts_in_verification_page = "你需要回答出以下<b>所有问题</b>"

    def setUp(self):
        super().setUp()

        self.query_string_dict = {
            "zmirror": "love_lucia",
            "zhi": "撒吱吱pr(顺便测试中文)",
        }
        self.query_string = urlencode(self.query_string_dict)  # type: str
        self.verify_page_url = self.url(
            "/ip_ban_verify_page?origin=aHR0cDovL2Iud"
            "GVzdC5jb20vZ2V0P3ptaXJyb3I9bG92ZV9sdWNpY"
            "SZ6aGk95pKS5ZCx5ZCxcHIo6aG65L6_5rWL6K-V5"
            "Lit5paHKQ=="
        )  # type: str
        self.origin = self.verify_page_url[self.verify_page_url.find("origin=") + 7:]  # type: str

    def test_redirect_to_verification_page(self):
        """https://httpbin.org/get?zmirror=love_lucia"""

        self.rv = self.client.get(
            self.url("/get"),
            query_string=self.query_string_dict,
            environ_base=env(
                ip='1.2.3.4'
            ),
            headers=headers(),
        )  # type: Response

        # 当需要验证出现重定向
        self.assertEqual(302, self.rv.status_code, msg=self.dump())
        self.assertIn(
            "/ip_ban_verify_page?origin=",
            self.rv.location, msg=self.dump())
        self.assertIn(b"Redirecting...", self.rv.data, msg=self.dump())

        # verify_page_url = self.rv.location  # type: str
        # print("verify_page_url", verify_page_url)

    def test_verification_page(self):
        """验证页面本身"""
        self.rv = self.client.get(
            self.verify_page_url,
            environ_base=env(
                ip='1.2.3.4'
            ),
            headers=headers(),
        )  # type: Response

        page_content = self.rv.data.decode()  # type: str

        self.assertIn(self.CaseCfg.tip_texts_in_verification_page,
                      page_content, msg=self.dump())

        self.assertIn(self.zmirror.human_ip_verification_title,
                      page_content, msg=self.dump())

        self.assertIn(self.C.human_ip_verification_questions[0][0],
                      page_content, msg=self.dump())
        self.assertIn(self.C.human_ip_verification_questions[0][2],
                      page_content, msg=self.dump())
        self.assertIn('type="text" name="0"',
                      page_content, msg=self.dump())

        self.assertIn(self.C.human_ip_verification_identity_record[0][0],
                      page_content, msg=self.dump())
        self.assertIn(self.C.human_ip_verification_identity_record[1][0],
                      page_content, msg=self.dump())
        self.assertIn('type="password"', page_content, msg=self.dump())
        self.assertIn('type="hidden" name="origin"', page_content, msg=self.dump())
        self.assertIn('name="{}"'.format(self.C.human_ip_verification_identity_record[0][1]),
                      page_content, msg=self.dump())
        self.assertIn('name="{}"'.format(self.C.human_ip_verification_identity_record[1][1]),
                      page_content, msg=self.dump())
        self.assertIn("<form method='post'>", page_content, msg=self.dump())

    def test_not_answer_question(self):
        """未回答问题"""
        self.rv = self.client.post(
            self.verify_page_url,
            environ_base=env(
                ip='1.2.3.4'
            ),
            headers=headers(),
        )  # type: Response

        page_content = self.rv.data.decode()  # type: str

        self.assertIn("Please answer question: " +
                      self.C.human_ip_verification_questions[0][0],
                      page_content, msg=self.dump())

    def test_wrong_answer(self):
        """回答错误"""
        self.rv = self.client.post(
            self.verify_page_url,
            data={
                "0": "错误的答案",
                "origin": self.origin,
            },
            environ_base=env(
                ip='1.2.3.4'
            ),
            headers=headers(),
        )  # type: Response

        page_content = self.rv.data.decode()  # type: str

        self.assertIn("Wrong answer in: " +
                      self.C.human_ip_verification_questions[0][0],
                      page_content, msg=self.dump())

    def test_lost_identity(self):
        """答案正确, 但是没有填写 [student/teacher ID number] """

        self.rv = self.client.post(
            self.verify_page_url,
            data={
                "0": self.C.human_ip_verification_questions[0][1],
                "origin": self.origin,
            },
            environ_base=env(
                ip='1.2.3.4'
            ),
            headers=headers(),
        )  # type: Response

        page_content = self.rv.data.decode()  # type: str

        self.assertIn("Param Missing or Blank: " +
                      self.C.human_ip_verification_identity_record[0][0],
                      page_content, msg=self.dump())

    def test_correct_answer(self):
        """答案正确, 并且信息完全"""
        self.rv = self.client.post(
            self.verify_page_url,
            data={
                "0": self.C.human_ip_verification_questions[0][1],
                self.C.human_ip_verification_identity_record[0][1]: "Unittest",
                self.C.human_ip_verification_identity_record[1][1]: "!Password1",
                "origin": self.origin,
            },
            environ_base=env(
                ip='1.2.3.4'
            ),
            headers=headers(),
        )  # type: Response

        page_content = self.rv.data.decode()  # type: str

        self.assertIn("Page Redirect", page_content, msg=self.dump())
        self.assertIn(self.zmirror.human_ip_verification_success_msg, page_content, msg=self.dump())
        self.assertIn(self.query_string_dict["zhi"], page_content, msg=self.dump())
        self.assertIn(self.query_string_dict["zmirror"], page_content, msg=self.dump())

        self.assertTrue(os.path.exists(zmirror_file("ip_whitelist.log")), msg=self.dump())
        self.assertTrue(os.path.exists(zmirror_file("ip_whitelist.txt")), msg=self.dump())

        with open(zmirror_file("ip_whitelist.txt"), 'r', encoding='utf-8') as fp:
            self.assertIn(
                "1.2.3.4",
                fp.read(), msg=self.dump()
            )

        with open(zmirror_file("ip_whitelist.log"), 'r', encoding='utf-8') as fp:
            self.assertIn(
                "Unittest",
                fp.read(), msg=self.dump()
            )
        with open(zmirror_file("ip_whitelist.log"), 'r', encoding='utf-8') as fp:
            self.assertIn(
                "!Password1",
                fp.read(), msg=self.dump()
            )

        self.assertIn("zmirror_verify=", self.rv.headers.get("Set-Cookie"))

        # 再请求一次 httpbin, 确认已经被授权
        self.rv2 = self.client.get(
            self.url("/get"),
            query_string=self.query_string_dict,
            environ_base=env(
                ip='1.2.3.4'
            ),
            headers=headers(),
        )  # type: Response

    def test_add_whitelist_by_cookie(self):
        """当一个陌生IP访问时, 检查Cookie并放行"""
        # 首先需要获得一个Cookie
        self.rv = self.client.post(
            self.verify_page_url,
            data={
                "0": self.C.human_ip_verification_questions[0][1],
                self.C.human_ip_verification_identity_record[0][1]: "Unittest",
                self.C.human_ip_verification_identity_record[1][1]: "!Password1",
                "origin": self.origin,
            },
            environ_base=env(
                ip='1.2.3.4'
            ),
            headers=headers(),
        )  # type: Response

        self.rv2 = self.client.get(
            self.url("/get"),
            query_string=self.query_string_dict,
            environ_base=env(
                ip='2.33.233.233'  # 更改IP
            ),
            headers=headers(),
        )  # type: Response


class TestVerificationSingleAnswer(TestVerification):
    """testing using https://httpbin.org/"""

    class C(TestVerification.C):
        human_ip_verification_answer_any_one_questions_is_ok = True
        enable_custom_access_cookie_generate_and_verify = False
        human_ip_verification_questions = (
            ('Unittest question one', '答案', 'Placeholder (Optional)'),
            ('Unittest question two', '答案2', ''),
        )
        human_ip_verification_identity_record = (
            ("Id verify question 1 stuid", "student_id", "text"),
            ("Id verify question 2 passwd", "password", "password"),
        )

    class CaseCfg(TestVerification.CaseCfg):
        tip_texts_in_verification_page = "只需要回答出以下<b>任意一个</b>问题即可"

    def test_not_answer_question(self):
        """未回答问题"""
        with self.app.test_client() as c:
            self.rv = c.post(
                self.verify_page_url,
                environ_base=env(
                    ip='1.2.3.4'
                ),
                headers=headers(),
            )  # type: Response

            page_content = self.rv.data.decode()  # type: str

            self.assertIn("Please answer at least ONE question",
                          page_content, msg=self.dump())
