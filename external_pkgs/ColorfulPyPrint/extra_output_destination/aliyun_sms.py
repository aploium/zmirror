# -*- coding:utf-8 -*-
import hashlib
import json
import sys
from time import time, localtime, strftime

try:
    import requests
except Exception as e:
    print('缺少requests库,请安装requests库: pip3 install requests')
    raise e

DEFAULT_SMS_SEND_API_URL = 'http://gw.api.taobao.com/router/rest'
__VERSION__ = '0.1.7'
__author__ = 'aploium@aploium.com'


def mixStr_py2(pstr):
    if (isinstance(pstr, str)):
        return pstr
    elif (isinstance(pstr, unicode)):  # 此处在py3的pycharm会报错,忽略即可,这是py2的代码
        return pstr.encode('utf-8')
    else:
        return str(pstr)


def calc_md5_sign(secret, parameters):
    """
    根据app_secret和参数串计算md5 sign,参数支持dict(建议)和str
    :param secret: str
    :param parameters:
    :return:
    """
    if hasattr(parameters, "items"):
        keys = list(parameters.keys())
        keys.sort()

        parameters_str = "%s%s%s" % (secret,
                                     ''.join('%s%s' % (key, parameters[key]) for key in keys),
                                     secret)
    else:
        parameters_str = parameters
    if sys.version_info >= (3, 0):  # python3内置unicode支持,直接编码即可
        parameters_str = parameters_str.encode(encoding='utf-8')
    else:  # py2 还要检测unicode
        parameters_str = mixStr_py2(parameters_str)
    sign_hex = hashlib.md5(parameters_str).hexdigest().upper()
    return sign_hex


class AlidayuSMS:
    """
    阿里大鱼短信平台接口,在预先指定所有必须参数后.write()方法可用,能被用来覆盖stdout
    API官方文档: http://open.taobao.com/doc2/apiDetail?apiId=25450#s6
    """

    def send_sms(self,
                 sms_params_or_content,  # dict或str形式的消息内容
                 rec_num=None,  # 默认接受短信的手机号
                 sms_free_sign_name=None,  # 默认通知抬头
                 sms_template_code=None,  # 模板代码
                 partner_id=None,  # 默认合作伙伴身份标识,在自己的sdk的/top/api/base.py头部能找到
                 extend=None,  # 公共回传参数
                 api_url=None
                 ):
        """
        给定以dict形式或str形式的参数列表,发送信息到手机,返回服务器给出的json object

        :param sms_params_or_content:
        :param rec_num: str
        :param sms_free_sign_name: str
        :param sms_template_code: str
        :param partner_id: str
        :param extend: str
        :param api_url: str
        :return: dict
        """
        # 若传入的是str,则检查默认模板是否给定
        if not hasattr(sms_params_or_content, "items"):
            if not self.default_sms_param_dict and not self.default_sms_key_name:
                # 若未指定则报错
                raise ValueError('未设置默认消息模板,请使用set_sms_param()设置')
            else:
                # 若已设置默认模板则组装
                self.default_sms_param_dict[self.default_sms_key_name] = sms_params_or_content
                sms_param = self.default_sms_param_dict
        else:  # 若传入的是dict,则直接作为模板参数
            sms_param = sms_params_or_content

        # 以下参数若在上面指定了则用指定了的,否则用初始化时设置的默认值
        extend = extend if extend else self.default_extend
        api_url = api_url if api_url else self.api_url
        partner_id = partner_id if partner_id else self.default_partner_id
        sms_template_code = sms_template_code if sms_template_code else self.default_sms_template_code
        sms_free_sign_name = sms_free_sign_name if sms_free_sign_name else self.default_sms_free_sign_name
        rec_num = rec_num if rec_num else self.default_rec_num
        sms_param = json.dumps(sms_param, ensure_ascii=False)
        timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime(time()))  # 时间戳

        # 组装必选参数
        data = dict(
            app_key=self.app_key,
            format='json',
            method='alibaba.aliqin.fc.sms.num.send',
            rec_num=rec_num,
            sign_method='md5',
            sms_free_sign_name=sms_free_sign_name,
            sms_param=sms_param,
            sms_template_code=sms_template_code,
            sms_type='normal',
            timestamp=timestamp,
            v='2.0'
        )

        # 检查必选参数是否缺失
        for key in data:
            if key is None:
                raise ValueError("缺少必选参数: %s,请指定该参数" % key)

        # 组装可选参数
        if self.default_partner_id is not None:
            data['partner_id'] = partner_id
        if extend is not None:
            data['extend'] = extend

        # 计算签名
        data['sign'] = calc_md5_sign(self.app_secret, data)  # py3

        # 发送请求,并存储最仅一次请求的结果(requests.Respond类),便于debug
        self.last_request_obj = requests.post(
            api_url,
            data=data,
            headers={
                'Content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
                'User-Agent': 'curl/7.45.0'
            }
        )

        if self.last_request_obj:
            return json.loads(self.last_request_obj.text)
        else:
            return None

    def write(self, stream):
        """
        write()方法,可以用来替换stdout
        :type stream:
        """
        return self.send_sms(stream)

    def set_default_sms_param(self, default_sms_param_dict, default_sms_key_name):
        """
        指定一个默认消息模板(dict),和用于发送消息的默认键. 设置完后可以调用.write()方法
        如设置成:
            default_sms_param = {'program_name':'helloworld','sms_content':''}
            default_sms_key_name = 'sms_content'
        在调用.write()的时候,会执行
            default_sms_param[default_sms_key_name] = Some_Message_Content_To_Be_Sent
        然后发送

        :param default_sms_param_dict: dict
        :param default_sms_key_name: str
        :return:
        """
        self.default_sms_param_dict = default_sms_param_dict
        self.default_sms_key_name = default_sms_key_name

    def __init__(self, app_key, app_secret,
                 default_rec_num=None,  # 默认接受短信的手机号
                 default_sms_free_sign_name=None,  # 默认通知抬头
                 default_sms_template_code=None,  # 模板代码
                 default_partner_id=None,  # 默认合作伙伴身份标识,在自己的sdk的/top/api/base.py头部能找到
                 default_extend=None,  # 公共回传参数
                 api_url=None,  # 接口url
                 ):
        """
        初始化
        :param app_key: str
        :param app_secret: str
        :param default_rec_num: str
        :param default_sms_free_sign_name: str
        :param default_partner_id: str
        :param default_extend: str
        :param default_sms_template_code: str
        :param api_url: str
        :return: dict
        """
        self.app_key = app_key
        self.app_secret = app_secret
        self.default_rec_num = default_rec_num
        self.default_sms_free_sign_name = default_sms_free_sign_name
        self.default_partner_id = default_partner_id
        self.default_sms_template_code = default_sms_template_code
        self.default_extend = default_extend
        self.api_url = api_url if api_url else DEFAULT_SMS_SEND_API_URL
        self.default_sms_param_dict = {}
        self.default_sms_key_name = None
        self.last_request_obj = None


if __name__ == '__main__':  # 一个demo
    if sys.version_info <= (3, 0):
        print("You are using py2.x,the following chinese characters would not display normally")
        print("You should open the source code and add u prefix to every chinese strings")
        print("Well, this module is written and fully tested in py3 environment, py2.x is supported,"
              " but didn't tested by author in real py2.x products. ")
        print("If there is any bug in py2.x, please let me know")

    demo_app_key = input('请输入app_key: ')
    demo_app_secret = input('请输入app_secret: ')
    demo_rec_num = input('请输入目标手机号: ')
    demo_partner_id = input('请输入partner_id(可选),回车留空: ')
    demo_sms_free_sign_name = input('请输入签名,如身份验证: ')
    demo_sms_template_code = input('请输入模板,如SMS_5376067: ')
    demo_sms_default_param = json.loads(input('请输入参数格式,json形式: '))

    sms = AlidayuSMS(demo_app_key, demo_app_secret,
                     default_rec_num=demo_rec_num,
                     default_sms_free_sign_name=demo_sms_free_sign_name,
                     default_sms_template_code=demo_sms_template_code,
                     default_partner_id=demo_partner_id
                     )
    # sms.set_default_sms_param(dict(prgmname='self_written_alidayu_api',
    #                                sourceip='127.0.0.1',
    #                                type='INFO',
    #                                msgcontent=''
    #                                ),
    #                           'msgcontent'
    #                           )

    print(sms.send_sms(demo_sms_default_param))
