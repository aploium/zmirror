本教程使用zmirror自带的配置文件, 在一台**全新安装**的Ubuntu服务器上部署部署支持HTTPS和HTTP/2的zmirror镜像  
本教程以Google镜像为例  
适用于 Ubuntu 14.04/15.10/16.04+  
建议的系统是 Ubuntu16.04-x86_64  

暂时没有撰写CentOS系/win/Mac下的部署教程  
部署有困难的请将VPS重装为Ubuntu  

暂时只能手动部署, 自动部署脚本 [zmirror-onekey](https://github.com/aploium/zmirror-onekey) 仍在开发中, 欢迎贡献代码  
  
部署完成后的镜像使用Apache2.4.23, 会启用HTTPS, 并且使用HTTP/2来提升访问性能  
在教程中使用 [let's encrypt](https://letsencrypt.org/) 来获取HTTPS证书  

## 前置需求
* 一台国外的服务器  
    * Ubuntu 14.04/15.10/16.04+  
      建议的系统为 Ubuntu16.04-x86_64  
    * 全新安装的系统  
* 一个已经解析到你服务器的三级域名, 不支持中文域名  

    > 三级域名指类似于这样的: g.mydomain.com 域名里有两个点, 三部分的  
      至于如何将域名解析到你的服务器, 请自行Google相关说明  
      本教程以 `lovelucia.zmirrordemo.com` 为例  

## 安装操作
### 安装初始化环境
以下脚本可以直接*整个原样*复制黏贴到terminal中运行  
每一行最后的`&&`表示本行执行成功后继续执行下一行  
```shell
sudo cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime &&
sudo apt-get update &&
sudo apt-get upgrade -y &&
sudo apt-get dist-upgrade -y &&
sudo apt-get install build-essential patch binutils make devscripts nano libtool libssl-dev libxml2 libxml2-dev software-properties-common python-software-properties dnsutils git wget curl python3 python3-pip iftop -y &&
sudo python3 -m pip install -U flask requests cchardet fastcache
```

### 安装Apache2
由于ubuntu14.04和16.04自带的Apache2均不支持HTTP/2, 所以需要安装不依赖ubuntu的最新版的Apache2  
同样, 下面的脚本也可以原样粘贴到terminal中运行  
```shell
LC_ALL=C.UTF-8 sudo add-apt-repository -y ppa:ondrej/apache2 &&
sudo apt-key update &&
sudo apt-get update &&
sudo apt-get upgrade -y &&
sudo apt-get --only-upgrade install apache2 -y &&
sudo a2enmod rewrite mime include headers filter expires deflate autoindex setenvif ssl http2 &&
sudo apt-get install libapache2-mod-wsgi-py3 -y
```
使用PPA中最新版的Apache2, 覆盖掉自带的源, 之后也支持使用`apt-get`来升级或者卸载  


### 安装并配置zmirror本身
假设将zmirror安装到 `/var/www/zmirror`

本教程以部署Google镜像为例  
即使用这个配置文件 `more_configs/config_google_and_zhwikipedia.py`  

```shell
cd /var/www &&
git clone https://github.com/aploium/zmirror &&
cd zmirror &&
chown -R www-data . && 
chgrp -R www-data . &&
cp more_configs/config_google_and_zhwikipedia.py config.py
```

之后需要手动修改 `config.py`, 在里面加上自己的域名  

在大约第38行开始处, 的  
```python
# ############## Local Domain Settings ##############
my_host_name = '127.0.0.1'
my_host_scheme = 'http://'
```
修改为如下, 修改两行, 添加一行    
```python
# ############## Local Domain Settings ##############
my_host_name = 'lovelucia.zmirrordemo.com'
my_host_scheme = 'https://' # 注意把上面这行的http改成https
verbose_level = 2
```
请将其中的`lovelucia.zmirrordemo.com`替换为你是自己实际的域名  

> 新添加的 `verbose_level = 2` 这一行, 把zmirror的日志级别设置为Warning, 减少日志产生量.  
> 默认是3级, 会产生大量debug日志  


### 安装let's encrypt并获得证书

> **证书来源**  
> 本教程使用let's encrypt证书, 获取非常快, 但是有效期只有90天, 到期前需要重新获取   
> 你也可以使用 [startSSL](https://www.startssl.com/) 或者 [沃通](https://buy.wosign.com/free/#ssl) 的免费SSL证书  
> 有效期分别为一年和两年  

请将下面脚本中 `lovelucia.zmirrordemo.com` 域名修改为你自己的域名, 修改后能直接复制进去运行  
为保证兼容性, 本教程使用standalone模式获取证书, 所以需要先停掉apache(包含在下面脚本中了)  
```shell
sudo service apache2 stop &&
cd ~ &&
git clone https://github.com/certbot/certbot &&
cd certbot &&
./certbot-auto certonly --agree-tos -t --standalone -d lovelucia.zmirrordemo.com
```

如果一切顺利, 此时你应该能看到如下的输出:  

> IMPORTANT NOTES:  
> \- Congratulations! Your certificate and chain have been saved at  
>   /etc/letsencrypt/live/lovelucia.zmirrordemo.com/fullchain.pem. Your cert  
>   will expire on 2016-10-30. To obtain a new or tweaked version of  
>   this certificate in the future, simply run certbot-auto again. To  
>   non-interactively renew \*all\* of your certificates, run  
>   "certbot-auto renew"  
> \- If you like Certbot, please consider supporting our work by:  
>   
>   Donating to ISRG / Let's Encrypt:   https://letsencrypt.org/donate  
>   Donating to EFF:                    https://eff.org/donate-le  

表示SSL证书已经成功获取, 并且已经存到了 `/etc/letsencrypt/live/lovelucia.zmirrordemo.com/` 目录中  

### 配置Apache2
现在需要给Apache2添加配置文件  
使用`apt-get`安装的情况下, apache2的配置文件存放在`/etc/apache2/`中  

下面下载的这个配置文件包含了一些功能和性能的优化, 如Gzip, 修改自h5bp
```shell
cd /etc/apache2/conf-enabled &&
wget https://gist.githubusercontent.com/aploium/8cd86ebf07c275367dd62762cc4e815a/raw/29a6c7531c59590c307f503b186493e559c7d790/h5.conf &&
cd /etc/apache2/sites-enabled &&
nano my-first-mirror-site.conf
```
加入以下内容(记得修改对应的域名和文件夹等东西)
```conf
<IfModule mod_ssl.c>
    SSLCipherSuite HIGH:MEDIUM:!aNULL:!MD5
    <VirtualHost *:443>
        # 域名, 记得修改成你自己的
        ServerName lovelucia.zmirrordemo.com
        
        # 这个没用的
        ServerAdmin root@localhost
        
        
        
        # 下面两个log文件路径也建议按实际修改
        # 默认保存在 /var/log/apache2/ 文件夹下
        # ErrorLog 中包含了zmirror产生的stdout输出, 若需要debug可以看它
        ErrorLog ${APACHE_LOG_DIR}/zmirror-google_ssl_error.log
        CustomLog ${APACHE_LOG_DIR}/zmirror-google_ssl_access.log combined

        # ##### WSGI 这部分是重点  ######
        WSGIDaemonProcess zmirror_google user=www-data group=www-data threads=16
        #这是刚刚安装的zmirror的路径
        WSGIScriptAlias / /var/www/zmirror/wsgi.py
        WSGIPassAuthorization On

        # 给予zmirror文件夹权限
        <Directory /var/www/zmirror>
            WSGIProcessGroup zmirror_google
            WSGIApplicationGroup %{GLOBAL}
            Order deny,allow
            Allow from all
        </Directory>

       # ######### SSL部分 这部分告诉Apache你的证书和私钥在哪 #########
       # 下面使用的是刚刚let's encrypt给我们的证书, 你也可以用别的
        SSLEngine on
        # 私钥
        SSLCertificateFile /etc/letsencrypt/live/lovelucia.zmirrordemo.com/cert.pem
        # 证书
        SSLCertificateKeyFile /etc/letsencrypt/live/lovelucia.zmirrordemo.com/privkey.pem
        # 证书链
        SSLCertificateChainFile /etc/letsencrypt/live/lovelucia.zmirrordemo.com/chain.pem
       
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

请访问`https://lovelucia.zmirrordemo.com`  

### 网络速度优化
建议OpenVZ用户使用 [net-speeder](https://github.com/snooda/net-speeder) 来加速网站  
使用net-speeder以后访问带宽会有非常大幅度的提升  

### 存在的一个小问题
按照上面的配置完成后, https的网站是可以直接访问了, 但是访问http无法直接跳转到https.  
请在 `/etc/apache2/sites-enabled/000-default.conf` 中加入以下设置, 使得HTTP能自动跳转到HTTPS  
加在\<VirtualHost\>\</VirtualHost\>括起来范围的里面  
```
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{HTTPS} !=on
    RewriteRule ^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]
</IfModule>
```