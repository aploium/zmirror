# -*- coding: utf-8 -*-
"""
用于内嵌到其他程序中,为其他程序添加发送到qq功能

参数格式:
_参数名_=_{{{{参数内容}}}}_


发送方式允许任意基于tcp的方式,如http等(比如说出现在url中、post表单中、http头、cookies、UA中)
本py使用的发送方式是urt-8的raw socket数据
参数名、内容、标示符_={} 都允许不编码(gbk/utf-8)或urlencode
只要发送的数据中出现上述格式的串,即会被解析

一个例子:
若想要发送一条信息'hello world'到QQ 345678901 (假设webqq消息服务器是127.0.0.1 端口为默认的34567)
则准备发送的内容为:
_token_=_{{{{sometoken}}}}_
_cmd_=_{{{{sendtoqq}}}}_
_msg_=_{{{{hello world}}}}_
_target_=_{{{{345678901}}}}_

发送方式:
    0.在其他python程序中发送信息(支持py2.6 2.7 3.4 3.5+)
        from webqq_client import WebqqClient
        ...下面的代码请看本文件底部的demo..

    1.以raw socket发送就是上面的样子,直接发送(换行只是为了阅读方便)

    2.以浏览器请求的方式发送
        在浏览器中直接访问
        http://127.0.0.1:34567/?_token_=_{{{{sometoken}}}}_&_cmd_=_{{{{sendtoqq}}}}_&_msg_=_{{{{hello world}}}}_&_target_=_{{{{345678901}}}}_
        即可

    3.以curl发送(注意{}的转义):
        curl "http://127.0.0.1:34567/?_token_=_\{\{\{\{sometoken\}\}\}\}_&_cmd_=_\{\{\{\{sendtoqq\}\}\}\}_&_msg_=_\{\{\{\{hello world\}\}\}\}_&_target_=_\{\{\{\{Xno0Pu7bnCB\}\}\}\}"


参数说明(目前服务器仅支持2个API):
    1.发送到QQ:
        token: 就是token,你在运行服务端程序时指定
        cmd: sendtoqq  固定值,表示命令为发送到QQ
        msg: 消息内容
        target: 目标QQ号

    2.发送到讨论组:
        token: 就是token,你在运行服务端程序时指定
        cmd: sendtodis  固定值,表示命令为发送到讨论组
        msg: 消息内容
        target: 目标讨论组的名称,请尽可能取得独特一点,建议不要纯数字,不保证对字母、数字外的符号支持

"""
import socket
import threading

DEFAULT_PORT = 34567
__VERSION__ = '0.2.0'


def assembly_payload(paras):
    """
    将dict参数组装为服务器可以理解的参数
    :param paras: dict
    """
    buffer = []
    for key in paras:
        buffer.append('_%s_=_{{{{%s}}}}_&' % (str(key), str(paras[key])))

    return (''.join(buffer)).encode()


class WebqqClient:
    def _send_and_receive(self, payload):
        """
        send bytes to server and receive echo

        :type payload: bytes
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server, self.port))
        except:
            return False
        self.socket.send(payload)
        buffer = []
        while True:
            d = self.socket.recv(1024)
            buffer.append(d)
            if len(d) < 1024:
                break
        self.socket.close()
        data = b''.join(buffer)
        try:
            data = data.decode(encoding='utf-8')
        except:
            data = data.decode(encoding='gbk')
        return data

    def handshake(self):
        payload = assembly_payload({
            'token': self.token,
            'cmd': 'handshake'
        })
        result = self._send_and_receive(payload)
        if 'handshakeOK' in result:
            return True

    def send_to_qq(self, msg_content, target_qq=None):
        target_qq = target_qq if target_qq is not None else self.target
        if target_qq is None:
            print('[ERR] an target qq must be given')
            return False
        payload = assembly_payload({
            'token': self.token,
            'cmd': 'sendtoqq',
            'msg': msg_content,
            'target': target_qq
        })
        result = self._send_and_receive(payload)
        if 'thank you' in result:
            return True
        else:
            return False

    def send_to_discuss(self, msg_content, target_discuss_name=None):
        target_discuss_name = target_discuss_name if target_discuss_name is not None else self.target
        if target_discuss_name is None:
            print('[ERR] an target discuss name must be given')
            return False
        payload = assembly_payload({
            'token': self.token,
            'cmd': 'sendtodis',
            'msg': msg_content,
            'target': target_discuss_name
        })
        result = self._send_and_receive(payload)
        if 'thank you' in result:
            return True
        else:
            return False

    def send_to_discuss_mt(self, msg_content, target_discuss_name=None):
        """
        an multi-threads version of send_to_discuss(), avoid lagging
        """
        s = threading.Thread(target=self.send_to_discuss, args=(msg_content, target_discuss_name))
        s.start()

    def write(self, stream):
        """
        若初始化时指定了 token,target,default_target_type 那么这个类可以当成一个file-like object使用
        消息会被发送到默认的目标
        """
        self._default_send_method(stream)
        return

    def send(self, msg_content):
        """
        只是WebqqClient.write()的别名
        """
        self._default_send_method(msg_content)
        return

    def __init__(self, server, token="", target=None, default_target_type='discuss', port=DEFAULT_PORT):
        self.server = server
        self.token = token
        self.target = target
        self.port = port
        if default_target_type == 'discuss':
            self._default_send_method = self.send_to_discuss
        elif default_target_type == 'qq':
            self._default_send_method = self.send_to_qq
        if self.target is None:
            print('[TIP] In personal use, you can give a target=YOUR_QQ param.')
        if not self.token:
            print('[WARN] maybe you forget your token')
        if not self.handshake():
            print('[ERR] handshake error')


if __name__ == '__main__':
    # 这下面是一个demo
    from time import time

    server = None
    target = None
    token = None
    port = None
    target_type = None  # 'qq'->QQ朋友 'discuss'->讨论组

    print('Version: ', __VERSION__)
    print('hhh你正在直接运行本程序,进入demo模式\n'
          '在给定一些参数后程序将用你指定的webqq消息服务器(需要你自己架设,请参考 https://github.com/Aploium/WebQQ_API )\n'
          '发送当前的unix时间戳到你的QQ(或者你指定的讨论组)\n'
          '注:截止目前(2016-03-07),WebQQ服务器出问题了(不是本程序的锅),私戳发送到QQ暂时失效,'
          '请与小号新建一个讨论组来接受信息\n\n')
    if server is None:
        server = input('请输入webqq消息服务器(如127.0.0.1): ')
    if port is None:
        port = input('请输入端口,什么都不输按回车使用默认端口(): ')
        if not port:
            port = DEFAULT_PORT
    if target is None:
        buff = input('请输入目标QQ或讨论组名称,若输入为纯数字则被认为是QQ号,否则视为讨论组名: ')
        try:
            target = int(buff)
        except:
            target = buff
            target_type = 'discuss'
        else:
            target_type = 'friend'

    if token is None:
        token = input('请输入token: ')

    q_client = WebqqClient(
        server,  # 服务器地址
        token=token,
        target=target,  # 默认的目标(一般就是你自己)
        default_target_type=target_type,  # 默认目标的类型,即上一行target的类型 'qq'->QQ朋友 'discuss'->讨论组
        port=port  # 端口,一般不需要指定,使用默认值即可
    )

    # 若初始化时指定了 token,target,default_target_type 那么这个类可以当成一个file-like object使用
    # 消息会被发送到默认的目标,相当方便的使用方法
    q_client.send('Hello world! Send by method .send() at unix time:' + str(time()))

    # 也可以手动指定target_type,target
    if target_type == 'discuss':
        q_client.send_to_discuss('Hello world! Send by method .send_to_discuss() at unix time:' + str(time()))
    elif target_type == 'friend':
        q_client.send_to_qq('Hello world! Send by method .send_to_qq() at unix time:' + str(time()))
