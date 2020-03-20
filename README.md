微信Proxy
====

基于ngx_lua，开发的微信proxy,在nginx进程内完成高访问，高计算量的工作，然后proxy到微信后台应用，支持队列方式的后台应用（只支持redis的队列应用）

解决的问题
-----

有关微信的应用时，都涉及到腾讯微信服务器对微信后台应用程序的访问．考虑到访问量大，频率高．而后台应用对xml拆包/封包，加密/解密效率较低（php的xmlparse,PKCS7和SHA1效率比较低），往往会导致丟包，重发，后台应用卡住，最后是用户体验极差．

描述
----

对来自腾讯微信服务器的微信信息，a.验证，b.直接返回，c.拆包加解密，d.转发/入队列,单向proxy

1. 验证

    1. redis 缓存验证；
    2. mysql 查表验证．

2. 直接返回
对GET请求直接返回空信息或echostr

3. 拆包/封包,解密
拆包和解密使用wxutil.so模块
封包使用lua程序

4. 转发/入队列
    １．转发时将body设成kv字符串
    ２．密文解码成明文后入队列

部署文件说明
----------

* wxMsgProxy.lua

为主控程序，植入nginx配置文件

* wxutil.so

lua　wechat C扩展，微信接入消息体descrypt、encrypt、xmlstring-to-luatable、luatable-to-xmlstring 等等

* cjson.so ，bit.so

* redis-lua、mysql.lua 

lua 扩展，功能如同名字

* config/init.lua 

按照init.lua.sample根据机器情况改写

部署说明
-------

* nginx 重新编译增加ngx_lua 模块 ，具体参考

* 对应的nginx的site conf 文件中增加以下代码,将微信服务器发来转由ngx_lua处理

```nginx
   lua_package_path  ";/srv/wxproxy/pkgs/lua/?.lua;/srv/wxproxy/pkgs/lua/?/init.lua;;";
   lua_package_cpath  "/srv/wxproxy/pkgs/lib/?.so;;";
   init_by_lua 'cjson = require "cjson"; require "wxutil"; bit = require "bit"';

    server {
     ...
     location ^~ /site/wechat_handler/index.html # 留在微信服务器端的url
      {
          default_type 'text/html';
          lua_code_cache off;  # just for development
          content_by_lua_file /srv/wxproxy/wxMsgProxy.lua; #
      }
    ...
    }  
```

* 根据config/init.lua.sample文件按照实际环境配置config/init.lua 文件
