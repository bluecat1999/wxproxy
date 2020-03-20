# 微信接入压力测试

纯PHP、NGX_LUA、NGX_LUAJIT

## 测试环境

CPU: 16 CORE
MEM: 32G
OS:　Ubuntu 18.04.1 LTS
PHP: 7.1.3
Nginx: 1.14.0 with core optimization
软件：ab
参数: -c 100 -n 10000
数据：wechat valite check and message　type-- Event、text(keywords etc)

## 测试结果

### 一）服务器认证

#### 1)php

![](./test/result/get_php.jpg)

#### 2)ngx_lua

![](./test/result/get_ngx_lua.jpg)

#### 3)ngx_luajit

![](./test/result/get_ngx_luajit.jpg)

### 二）微信明文消息

#### 1) php

![](./test/result/plain_php.jpg)

#### 2) ngx_lua

![](./test/result/plain_ngx_lua.jpg)

#### 3) ngx_luajit

![](./test/result/plain_ngx_luajit.jpg)

### 三）微信消息兼容模式

#### 1)  php

![](./test/result/cpt_php.jpg)

#### 2)  ngx_lua

![](./test/result/cpt_ngx_lua.jpg)

#### 3)  ngx_luajit

![](./test/result/cpt_ngx_luajit.jpg)

### 四微信消息安全模式

#### php

![](./test/result/safe_php.jpg)

#### ngx_lua

![](./test/result/safe_ngx_lua.jpg)

#### ngx_luajit

![](./test/result/safe_ngx_luajit.jpg)

## 结论

PHP模式:60-90 req/s,request最长处理时间接近４s(按微信的要求会重发消息)

Ngx_lua模式:3000-4000 req/s,request 最长处理时间0.６s

Ngx_luajit模式:4500 req/s,request最长处理时间0.24s

微信消息兼容模式下的测试情况最差
