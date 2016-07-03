# coding=utf-8
# 这是为twitter(手机站)镜像配置的示例配置文件
# 各项设置选项的详细介绍请看 config_default.py 中对应的部分
#
# 使用方法:
#   复制本文件和 config_twitter_pc.py(有些重复选项依赖于它) 两个文件 到 zmirror.py 同级目录,
#       重命名 config_twitter_pc.py 为 config.py
#
# 本配置文件假定你的服务器本身在墙外
# 如果服务器本身在墙内(或者在本地环境下测试, 请修改`Proxy Settings`中的设置(在PC站的配置文件中)
#
# 由于twitterPC和twitterMobile实际上是相互独立的, 而且由于逻辑非常复杂, 即使使用镜像隔离功能, 也会导致手机站不正常
#   所以把twitterPC和twitterMobile分成两个配置文件
# 使用本配置文件运行的twitter镜像, 支持所有的twitter功能(暂时还没发现不能用的功能)
#
# ########################################
# 警告: twitter镜像在非https环境下可能会无法注册, 其他功能也可能会出现问题, 请在https环境下部署twitter镜像
# ########################################

# 由于很多设置跟twitterPC一样,所以从twitterPC的配置文件导入
from .config_twitter_pc import *

# ############## Local Domain Settings ##############
my_host_name = '127.0.0.1'
my_host_scheme = 'http://'

# ############## Target Domain Settings ##############
target_domain = 'mobile.twitter.com'
target_scheme = 'https://'

# 删除 mobile.twitter.com, 添加 twitter.com
external_domains.remove('mobile.twitter.com')
external_domains.append('twitter.com')

# 其他设置都跟twitterPC站配置文件相同
