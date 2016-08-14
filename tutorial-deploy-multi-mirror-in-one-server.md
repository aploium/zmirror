# zmirror如何实现同VPS多个镜像

## 前置需求

* 一台国外的服务器  
    * Ubuntu 14.04/15.10/16.04+  
      建议的系统为 Ubuntu16.04-x86_64  
    * 全新安装的系统  
  
* 至少*两个*(每个镜像一个)已经解析到你服务器的三级域名, 不支持中文域名  

    > 三级域名指类似于这样的: g.mydomain.com 域名里有两个点, 三部分的
    >
    > 至于如何将域名解析到你的服务器, 请自行Google相关说明  
      本教程以 `m2.zmirrordemo.com` 为例  


## 预先部署第一个镜像

请先按照[部署支持HTTPS和HTTP/2的镜像](tutorial-deploy-zmirror-with-HTTPS-and-HTTP2.md)中的步骤完成第一个镜像的部署, 并且测试可用以后, 再继续本教程  
  
后续部署步骤中, 假定部署者已经按照以上教程成功完成了第一个镜像的部署  

> 如果部署中出现任何问题或者不清楚的地方  
> 请 [点此发issue](https://github.com/aploium/zmirror/issues/new) 提出  
> 或者在 gitter 中请求实时帮助, 可以点击右边的图标进入gitter聊天室 [![Gitter](https://badges.gitter.im/zmirror/zmirror.svg)](https://gitter.im/zmirror/zmirror?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)  
> 如果提出的问题有价值, 您会被加入到 `CONTRIBUTORS.md` 的贡献者列表中  

## 第二个镜像

在本教程中, 以部署youtube-PC为第二镜像为例  

### 安装并配置zmirror本身

第一镜像是Google, 之前已经安装到了`/var/www/zmirror`  

> 很遗憾, 在目前, 一个zmirror文件夹只能放一个镜像  
> 不同的镜像只能放在不同的zmirror安装文件夹中  
> 所以如果需要部署第二镜像, 那么就需要单独开一个zmirror文件夹  

假设将第二镜像(youtube-PC)的安装到 `/var/www/youtube-pc`    

首先跟之前的教程一样, clone一份zmirror, 并且修改所有者为`www-data`(apache的用户, 给予写入权限)  

*以下脚本可以原样复制到shell中执行*  
```shell
cd /var/www &&
git clone https://github.com/aploium/zmirror.git youtube-pc &&
cd youtube-pc &&
chown -R www-data . && 
chgrp -R www-data .
```

youtube镜像需要使用自带的两个配置文件`config_youtube.py`和`custom_func_youtube.py` 需要把他们拷贝到程序根目录  

```shell
cp more_configs/config_youtube.py config.py &&
cp more_configs/custom_func_youtube.py.py custom_func.py
```

之后需要手动修改 `config.py`, 在里面加上自己的域名  

在大约第40行开始处, 的  
```python
# ############## Local Domain Settings ##############
my_host_name = 'www.localhost.com'
my_host_scheme = 'http://'
```
修改为如下, 修改两行, 添加一行    
```python
# ############## Local Domain Settings ##############
my_host_name = 'm2.zmirrordemo.com'
my_host_scheme = 'https://' # 注意把上面这行的http改成https
verbose_level = 2
```
请将其中的`m2.zmirrordemo.com`替换为你是自己实际的域名  

> 新添加的 `verbose_level = 2` 这一行, 把zmirror的日志级别设置为Warning, 减少日志产生量.  
> 默认是3级, 会产生大量debug日志  

> **注意**  
> 只需要修改`config.py`. *不需要*修改`custom_func.py`

### 使用let's encrypt获取证书

本步骤请参考上一篇教程中的部分 [部署支持HTTPS和HTTP/2的镜像-获取证书](https://github.com/aploium/zmirror/wiki/%E9%83%A8%E7%BD%B2%E6%94%AF%E6%8C%81HTTPS%E5%92%8CHTTP2.0%E7%9A%84%E9%95%9C%E5%83%8F#%E5%AE%89%E8%A3%85lets-encrypt%E5%B9%B6%E8%8E%B7%E5%BE%97%E8%AF%81%E4%B9%A6) 

```shell
sudo service apache2 stop &&
cd ~/certbot &&
./certbot-auto certonly --agree-tos -t --standalone -d m2.zmirrordemo.com
```
请将上面脚本中 `m2.zmirrordemo.com` 替换为你自己的域名  

### 配置Apache2

进入Apache2的配置文件夹, 将上一个教程中创建的配置文件复制一份为`youtube-pc.conf`  
原有配置文件不需要修改  
```shell
cd /etc/apache2/sites-enabled &&
cp my-first-mirror-site.conf youtube-pc.conf
```

然后修改里面对应的内容, 适应新部署的镜像, 在本例中, 修改后的`youtube-pc.conf`内容如下

```conf
<IfModule mod_ssl.c>
    SSLCipherSuite HIGH:MEDIUM:!aNULL:!MD5
    <VirtualHost *:443>
        # 域名, 记得修改成你自己的
        ServerName m2.zmirrordemo.com
        
        # 这个没用的
        ServerAdmin root@localhost
        
        
        # 下面两个log文件路径也建议按实际修改
        # 默认保存在 /var/log/apache2/ 文件夹下
        # ErrorLog 中包含了zmirror产生的stdout输出, 若需要debug可以看它
        ErrorLog ${APACHE_LOG_DIR}/zmirror-youtube_pc_ssl_error.log
        CustomLog ${APACHE_LOG_DIR}/zmirror-youtube_pc_access.log combined

        # ##### WSGI 这部分是重点  ######
        WSGIDaemonProcess zmirror_youtube_pc user=www-data group=www-data threads=16
        #这是刚刚安装的zmirror的路径
        WSGIScriptAlias / /var/www/youtube-pc/wsgi.py
        WSGIPassAuthorization On

        # 给予zmirror文件夹权限
        <Directory /var/www/youtube-pc>
            WSGIProcessGroup zmirror_youtube_pc
            WSGIApplicationGroup %{GLOBAL}
            Order deny,allow
            Allow from all
        </Directory>

       # ######### SSL部分 这部分告诉Apache你的证书和私钥在哪 #########
       # 下面使用的是刚刚let's encrypt给我们的证书, 你也可以用别的
        SSLEngine on
        # 私钥
        SSLCertificateFile /etc/letsencrypt/live/m2.zmirrordemo.com/cert.pem
        # 证书
        SSLCertificateKeyFile /etc/letsencrypt/live/m2.zmirrordemo.com/privkey.pem
        # 证书链
        SSLCertificateChainFile /etc/letsencrypt/live/m2.zmirrordemo.com/chain.pem
       
       # HTTP/2
        <IfModule http2_module>
            Protocols h2 h2c http/1.1
        </IfModule>
    </VirtualHost>
</IfModule>
```

### 完成
很好, 所有部署工作已经完成了!  
现在只需要重启一下Apache即可  
`sudo service apache2 restart` 

现在, 你的VPS上就同时运行了Google镜像和Youtube-PC镜像  
对应的域名(按你自己的域名为准)分别为`https://lovelucia.zmirrordemo.com`和`https://m2.zmirrordemo.com`  
两者互不干扰  

## 总结
同VPS多镜像, 主要是利用了Apache的`visual host`功能, 允许同一台服务器运行多个域名, 多个网站  
上面的步骤基本就是在重复部署第一个镜像,  

创建新的zmirror文件夹 --> 获取证书 --> 加一个新的Apache2配置文件


## 可选: 替换Google镜像中的Youtube为你的镜像域名

在默认情况下, 由于Google镜像并不知道你配置的Youtube镜像的存在,  
所以当搜索结果出现Youtube时, 跳转到的仍然是真正的youtube, 而不是你的Youtube镜像  
并且doodle中的视频也无法播放(因为依赖youtube)  

但是可以通过配置, 使用镜像Youtube来替换掉真正的Youtube  
替换方法非常简陋, 只是单纯的字符串替换, 但是却相当有效  
不仅对网页搜索结果有效, 还对视频搜索/Doodle等有效  

打开Google镜像的配置文件`/var/www/zmirror/config.py`  
在配置文件中加入以下内容
```python
url_custom_redirect_enable = True
plain_replace_domain_alias = [
    ('www.youtube.com','m2.zmirrordemo.com'),
]
```
把其中`m2.zmirrordemo.com`替换为你Youtube镜像的域名

然后保存, 重启Apache  
`sudo service apache2 restart`  

这样一来, 所有www.youtube.com都会被替换成你的域名  
效果可以看到, 当点击google搜索结果中的youtube时, 进入的是你的镜像  
https://g.zmirrordemo.com/search?q=youtube  
