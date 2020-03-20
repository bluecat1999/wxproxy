---Wechat Message  Proxy(Half Bi-directional)
-- 微信消息加解密
-- 明文模式 plian_mode：维持现有模式，没有适配加解密新特性，消息体明文收发，默认设置为明文模式
-- 兼容模式 cpt_mode：公众平台发送消息内容将同时包括明文和密文，消息包长度增加到原来的3倍左右；公众号回复明文或密文均可，不影响现有消息收发；开发者可在此模式下进行调试
-- 安全模式（推荐）safe_mode：公众平台发送消息体的内容只含有密文，公众账号回复的消息体也为密文，建议开发者在调试成功后使用此模式收发消息
--
--- Program Begin

---以下path env正式上线后可写入nginx的配置中
package.path = package.path .. ";/srv/wxproxy/pkgs/lua/?.lua;/srv/wxproxy/pkgs/lua/?/init.lua"
package.cpath = package.cpath .. ";/srv/wxproxy/pkgs/lib/?.so"

--模块加载

local redis = require("resty.redis")
local mysql = require("resty.mysql")
--以下线上植入nginx的配置中
local cjson = require("cjson")
require("wxutil")

---参数配置
dofile('/srv/wxproxy/config/init.lua')

-- -- local function Begin
local function close_redis(red)
    if not red then
        return
    end 
    local ok, err =red:close()
    if not ok then
        ngx.say("close redis error :" , err)
    end
end

local function close_mysql(db)
    if not db then
        return
    end
    local ok, err = db:close()
    if not ok then
        ngx.say('close mysql error : ', err)
    end
end

local function to_hex(str)
    return ({str:gsub(".", function(c) return string.format("%02X", c:byte(1)) end)})[1]
end
 --sha1
local function sha1(str)
   return string.lower(to_hex(ngx.sha1_bin(str)))
end

local function prTable(tbl) 
    for k,v in pairs(tbl) do
        if type(v) == 'table' then 
            ngx.say(k,":",table.concat(v))
        elseif type(v) == 'function' then
            ngx.say(k,":","function")
        else 
            ngx.say(k,":",v)
        end
    end
end

--微信服务器请求签名检测
local function checkSignature(timestamp,nonce,token,signature)
    local tmpArr={timestamp,token,nonce}
    table.sort(tmpArr)
    local tmpStr = table.concat(tmpArr)
    if signature == sha1(tmpStr) then
        return true;
    else 
        return false;
    end
end


----入队列 todo: 出错处理
local function push_queue(msg,channel,ttr,red)
    local id, err = red:incr(channel .. ".message_id")
    local res,err = red:hset(channel ..".messages", id, ttr ..";" ..msg)
    local res,err = red:lpush(channel .. ".waiting", id)
end

--　微信事件处理
-- 关注回复
local function subscribe_ev(wxobj,data)
    local ret,err = wxobj:toXml(
        {
        ToUserName   = data['FromUserName'],
        FromUserName = data['ToUserName'],
        CreateTime   = os.time(),
        MsgType      = 'text',
        Content      = data['subscription']
    })
    if  ret then 
        ngx.say(ret);
    else 
        ngx.say('')
    end     
end

local function unsubscribe_ev(red,id)
    -- 删除open_id对应的信息
    red:hdel("pstats",id) 
    ngx.say('')
   
end

--

local function exit(red,db,status)
    collectgarbage()
    close_redis(red)
    close_mysql(db)
    ngx.exit(status)
end
-- --function END

local setting =  getSetting()
local redis_conn = setting.redis_conn
local mysql_conn = setting.mysql_conn

--local variables

local method_name = ngx.req.get_method()
local uri = ngx.var.uri
local server_name = ngx.var.server_name
local scheme = ngx.var.scheme
local request = ngx.var.request
local remote_addr = ngx.var.remote_addr
local hostname  = ngx.var.hostname
local args, err = ngx.req.get_uri_args()
local ok, error, res, sqlstate, errno
local open_id, token, aeskey,keywords,appid,MsgSignature,subscription
local rtflag = { 
    OK=0,
    ValidateSignature_Error = -40001,
    ParseXml_Error = -40002,
    ComputeSignature_Error = -40003,
    IllegalAesKey = -40004,
    ValidateAppid_Error = -40005,
    EncryptAES_Error = -40006,
    DecryptAES_Error = -40007,
    IllegalBuffer = -40008,
    EncodeBase64_Error = -40009,
    DecodeBase64_Error = -40010,
    GenReturnXml_Error = -40011,
    GenLuaTable_error  = -40012,
    ValidateLuaTable_error =-40013,
}
local qMsg --入队信息结构
local idInfo --用户访问信息
local sql_1=''
local sql_2=''
local Event_trigger = {
    'scancode_waitmsg',  --扫码推事件且弹出“消息接收中”提示框的事件推送
    'scancode_push',     --扫码推事件的事件推送
    'CLICK',             --点击菜单拉取消息时的事件推送
    'SCAN'               --扫码事件
}
-- Wechat Event process function table
local wx_ev_fun_tbl ={
    subscribe=subscribe_ev,
    unsubscribe=unsubscribe_ev
}

if not args['shop_id'] or not args['timestamp'] or not args['nonce'] or not args['signature'] then
    ngx.say('params are invalid!')
    return 
end    
local red, err = redis:new()
red:set_timeout(1000) -- 1 sec

if redis_conn.host ~='' then
     ok, error = red:connect(redis_conn.host, redis_conn.port, redis_conn.database)
else
     ok, error = red:connect(redis_conn.unixsocket,redis_conn.database)
end 

if not ok then
    ngx.say("failed to connect: ", err)
    return exit(red,db,ngx.HTTP_INTERNAL_SERVER_ERROR)
end

red:select(redis_conn.database) --源库无法在connect方法选择数据库

if redis_conn.password ~='' then
    res, err = red:auth(redis_conn)
    if not res then
        ngx.say("failed to authenticate: ", err)
        return exit(red,db,ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
end

local wxset, err = red:get("wxbus:" .. args['shop_id'])

if args['openid'] then 
    open_id = args['openid']
    --设置用户:openid本次访问时间戳到缓存
    idInfo, err = red:hget("pstats", open_id)
    if idInfo ~=ngx.null or not idInfo then 
        idInfo = cjson.decode(tostring(idInfo))
        idInfo.timestamp = args['timestamp']
    else 
        idInfo = {}
        idInfo.open_id = open_id
        idInfo.timestamp = args['timestamp']
        sql_1 =  " select a.member_id ,a.tag_name,b.member_name,b.tele_sales_staff_id,b.sales_staff_id, b.shop_id from md_pam_bind_tag a inner join md_member b on a.member_id=b.member_id " ..
        "where a.open_id='" .. open_id ..  "' and a.tag_type='weixin' and a.flag=0;"  --and b.shop_id='" .. args['shop_id'] .."';"
     -- if not db then 
     -- end
     -- res, err, errno, sqlstate =
     --     db:query("select * from md_pam_bind_tag where open_id='" .. open_id .. "' and flag=0;")
     -- if not res then
     --         ngx.say("bad result: ", err, ": ", errno, ": ", sqlstate, ".")
     --     return exit(red,db,ngx.HTTP_INTERNAL_SERVER_ERROR)
     -- end
     -- red:set("wxbus_openid:" .. open_id,[[{"open_id":"]] ..open_id..[[","timestamp":"]]..args['timestamp']..[["}]])
    end
else 
    open_id = ''        
end         

if  wxset ~=ngx.null or not wxset then
    local wt = cjson.decode(tostring(wxset))
    token = wt['token']
    aeskey = wt['aeskey']
    keywords = wt['keywords']
    appid = wt['appid']
    subscription = wt['subscription']
    red:set("wxbus:" .. args['shop_id'], cjson.encode(wt))
else
    sql_2 = "select * from md_wechat_config where shop_id='" .. args['shop_id'] .. "';"..
    "select keywords,content from md_wechat_keywords where shop_id='" .. args['shop_id'] .. "' and flag<>'1';"
end    
  
if  sql_2 ~='' or sql_1 ~='' then 
    local db, err = mysql:new()
    if not db then
        ngx.say("failed to instantiate mysql: ", err)
        return exit(red,db,ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
    db:set_timeout(1000) -- 1 sec
    local dbconn = function()
       local ok, err, errno, sqlstate = db:connect{
             host = mysql_conn.host,
             port = mysql_conn.port,
             database = mysql_conn.database,
             user = mysql_conn.user,
             password = mysql_conn.password,
             max_packet_size = 1024 * 1024 }
        if not ok then
            ngx.say("failed to connect: ", err, ": ", errno, " ", sqlstate)
            return exit(red,db,ngx.HTTP_INTERNAL_SERVER_ERROR)
        end
    end
    -- ok, err = db:set_keepalive(10000, 100)
    -- if not ok then
    --     ngx.say("failed to set keepalive: ", err)
    --     return
    -- end
    --  Mysql Server 后台原因，resty-mysql 有问题,一次connection 送一次send_query后断开
    -- 按店铺设置缓存，PHP后台关键字回复、账号配置、关注回复需增添删除　wxbus:$shop_id 项
    if sql_2 ~='' then
        dbconn()     
        res, err, errno, sqlstate = db:query(sql_2)
        if not res then
            ngx.say("bad result: ", err, ": ", errno, ": ", sqlstate, ".")
            return exit(red,db,ngx.HTTP_INTERNAL_SERVER_ERROR)
        end    
        wxset = res[1]
    
        while err == "again" do
            res, err, errno, sqlstate = db:read_result()
            if not res then
                ngx.log(ngx.ERR, "bad result #2: ", err, ": ", errno, ": ", sqlstate, ".")
                return exit(red,db,ngx.HTTP_INTERNAL_SERVER_ERROR)
            end
        end    
        -- wxset.timestamp = args['timestamp']
        wxset['keywords'] = (not res and {}) or res
        
        red:set("wxbus:" .. args['shop_id'], cjson.encode(wxset))
        token = wxset['token']
        aeskey = wxset['aeskey']
        keywords = wxset['keywords']
        appid = wxset['appid']
        subscription = wxset['subscription']
    end
  

    -- 微信用户php绑定时需要处理，取消关注时需要将该idInfo删除
    if sql_1 ~= '' then 
        dbconn()     
        res, err, errno, sqlstate = db:query(sql_1)
        if not res then
            ngx.say("bad result: ", err, ": ", errno, ": ", sqlstate, ".")
            return exit(red,db,ngx.HTTP_INTERNAL_SERVER_ERROR)
        end    
        if res then 
            idInfo.member_info = res
            -- idInfo.member_id =res.member_id
            -- idInfo.member_name = res[1].member_name
            -- idInfo.tag_name = res[1].tag_name
        else
            -- idInfo.member_id = 0
            -- idInfo.member_name = 'Guest'    
            idInfo.member_info = {{member_id=0,member_name='Guest',shop_id=shop_id}}
        end
    end
    
  
end 

---Check Signature
if not checkSignature(args['timestamp'],args['nonce'],token,args['signature']) then
   return exit(red,db,ngx.HTTP_INTERNAL_SERVER_ERROR)
end

local encrypt_type  = (args['encrypt_type'] and "AES" ) or ''
local encrypt_mode = {'plain','cpt','safe'}
local msgStruct = {
    Msg_direc       = 'IN', --IN,OUT,PXY
    Msg_Plt_Type    = 'wechat', --kefu,wechat...
    Msg_Enc_Type    = 'plain', --plain,cpt,safe
    Msg_Enc_Sign    = '',
    Msg_Dep         = args['shop_id'],
    Msg_adapter     = '',
    Msg_Req_url     = '',
    Msg_lst_from    = {}, --from='kefu',user=xxx
    Msg_Param       = {},
    Msg_Body        = {},
}


if method_name == "GET" then
       
        if not args['echostr'] then
            ngx.print('')
        else 
           ngx.print(args['echostr'])    
        end
        exit(red,db,ngx.HTTP_OK)  
else

        if not args['openid'] then 
            return exit(red,db,ngx.HTTP_OK) 
        end
        ngx.req.read_body()
        local raw_body =ngx.req.get_body_data()-- ngx.req.read_body() --ngx.req.get_body_data
        if not raw_body then  exit(red,db,ngx.HTTP_OK) end

        local wxObj = wxutil:new(token, aeskey, appid, encrypt_type)
        MsgSignature = (args['msg_signature'] and args['msg_signature'] ) or ''
        -- open_id = args['openid']

        local En_mode = encrypt_mode[1]
             
        if  encrypt_type   then
            if string.find(raw_body,"<FromUserName>") then  
                En_mode=encrypt_mode[2]
            else
                En_mode=encrypt_mode[3]
                -- raw_body = "<xml><ToUserName><![CDATA[toUser]]></ToUserName><Encrypt><![CDATA["
                -- .. raw_body .. "]]></Encrypt></xml>"
            end 
            -- MsgSignature = args['msg_signature'] 
        end
        
        local ret,wxmsg_tbl = wxObj:getMsg(MsgSignature, args['timestamp'], args['nonce'], raw_body)
        if ret == 0 then 
            if not wxmsg_tbl['MsgType'] then 
                ngx.say('')
                return exit(red,db,ngx.HTTP_OK) 
            end
           
            if not idInfo.msgid then 
                idInfo.msgid = wxmsg_tbl['MsgId']
            else
                -- 调试关闭
                -- if idInfo.msgid == wxmsg_tbl['MsgId'] then
                --     ngx.say('')
                --     return exit(red,db,ngx.HTTP_OK) 
                -- end
            end 

            if wxmsg_tbl['MsgType'] == 'event' then
                --事件处理
                    local evt_fun = string.lower( wxmsg_tbl['Event'] )
                    if wx_ev_fun_tbl[evt_fun] then
                        if evt_fun =='subscribe' then 
                            wx_ev_fun_tbl[evt_fun](wxObj,wxmsg_tbl)
                        end 
                        if evt_fun == 'unsubscribe' then 
                            wx_ev_fun_tbl[evt_fun](red,open_id)
                        end   
                    else 
                        local args_proxy = ''
                        for k,v in pairs(args) do
                             if args_proxy == '' then 
                                args_proxy = k .. '=' .. v
                             else
                                args_proxy =args_proxy .. '&' .. k ..'='.. v
                             end
                        end
                        local body_str = 'ToUserName' .. wxmsg_tbl['ToUserName'] ..
                                         'FromUserName' .. wxmsg_tbl['FromUserName'] ..
                                         'CreateTime' .. wxmsg_tbl['CreateTime'] .. 
                                         'MsgType'  .. wxmsg_tbl['MsgType'] .. 
                                         'Event' .. wxmsg_tbl['Event'] .. 
                                         'EventKey' .. wxmsg_tbl['EventKey']
                                         
                        local res_in = ngx.location.capture(
                            setting.real_wx_url,
                            {method = ngx.HTTP_POST, args = args_proxy,body = body_str}
                        )
                        ngx.say(res_in.body)
                        -- return exit(red,db,ngx.HTTP_OK) 
                    end 
                else
                    msgStruct.Msg_Body =wxmsg_tbl; 
                    msgStruct.Msg_Body.ProxyTime = os.time();

                    if wxmsg_tbl['MsgType'] == "text" then 
                         ret = 0
                        -- 关键词回复
                            ret = table.foreach(keywords,function( i,v )
                                if wxmsg_tbl['Content']==keywords[i]['keywords']  then
                                  local key_ret,key_err =
                                    wxObj:toXml(
                                        { 
                                            ToUserName = wxmsg_tbl['FromUserName'],
                                            FromUserName = wxmsg_tbl['ToUserName'],
                                            CreateTime = os.time(),
                                            Content = keywords[i]['content'],
                                            MsgType = 'text'
                                        }
                                    )
                                    if key_ret then 
                                        ngx.say(key_ret)
                                        else 
                                        ngx.say('')
                                    end

                                    return 1;
                               end 
                        end)

                        msgStruct.Msg_adapter = setting.wxmsg_queue["text"].adapter
                        
                        if not idInfo.last_from then 
                            msgStruct.Msg_lst_from = {
                                from = idInfo.last_from,
                                user = idInfo.last_user
                            }
                        end 
                        if ret == nil then
                        --文本消息  
                        -- menu entry process
                        local wsg_content = wxmsg_tbl['Content']  
                        if string.len(wsg_content)==1  then
                            local sw_ret,sw_err
                            if tonumber(wsg_content) == 0 then -- using　(content)０　switch to kefu,1 to  AI
                                 -- idInfo.status =1 (kefu），　0(ai) 
                                    idInfo.status = 1
                                    sw_ret,sw_err =
                                        wxObj:toXml(
                                        { 
                                            ToUserName = wxmsg_tbl['FromUserName'],
                                            FromUserName = wxmsg_tbl['ToUserName'],
                                            CreateTime = os.time(),
                                            Content = "欢迎进入人工客服模式！ \n（１＝>AI智能应答模式)",
                                            MsgType = 'text'
                                        }
                                        )
                                    if sw_ret then 
                                        ngx.say(sw_ret)
                                        else
                                        ngx.say('')
                                    end
                                elseif tonumber(wsg_content) == 1 then
                                   idInfo.status = 0  
                                --    ngx.say("欢迎进入AI智能应答模式！")
                                    sw_ret,sw_err =
                                    wxObj:toXml(
                                    { 
                                        ToUserName = wxmsg_tbl['FromUserName'],
                                        FromUserName = wxmsg_tbl['ToUserName'],
                                        CreateTime = os.time(),
                                        Content = "欢迎进入AI智能应答模式！（０＝＞人工客服模式）",
                                        MsgType = 'text'
                                    }
                                     )
                                if sw_ret then 
                                    ngx.say(sw_ret)
                                 else
                                     ngx.say('')
                                 end                         
                            end     
                        else 

                            qMsg = cjson.encode(
                                {
                                    class=setting.wxmsg_queue["text"].class,
                                    data=msgStruct
                                }
                            )

                            push_queue(
                                qMsg,
                                setting.wxmsg_queue["text"].channel,
                                setting.wxmsg_queue["text"].ttr,red
                            )
                            ngx.say('') --返回空，防止重复发
                        end
                        end
                    else
                    --媒体消息
                        if next(setting.wxmsg_queue[wxmsg_tbl['MsgType']]) == nil then
                            ngx.log(ngx.WARN,'目前不支持：'.. setting.wxmsg_queue[wxmsg_tbl['MsgType']])
                            ngx.say('')
                            red.hset('pstats',open_id,red:encode(idInfo))
                            return exit(red,db,ngx.OK)
                        end 

                        if idInfo.member_id ==0 then 
                            ngx.say('未绑定用户不能发送'.. setting.wxmsg_queue[wxmsg_tbl['MsgType']].cn_name)
                            red.hset('pstats',open_id,red:encode(idInfo))
                            return exit(red,db,ngx.OK)
                        end 

                        qMsg = cjson.encode(
                            {
                                class=setting.wxmsg_queue[wxmsg_tbl['MsgType']].class,
                                data=msgStruct
                            }
                        )

                        push_queue(
                            qMsg,
                            setting.wxmsg_queue[wxmsg_tbl['MsgType']].channel,
                            setting.wxmsg_queue[wxmsg_tbl['MsgType']].ttr,red
                        )
                        ngx.say('') --返回空，防止重复发
                    end              
               end    
               red:hset('pstats',open_id,cjson.encode(idInfo))
               exit(red,db,ngx.HTTP_OK)
        else
            ngx.say('') --返回空
            table.foreach(rtflag,function(k,v)
                if ret == v then
                    ngx.say("error:",k," error_no:",v) --最后改写入log
                    exit(red,db,ngx.HTTP_OK) 
                end
        end)
    end
end
-- exit(red,db,ngx.HTTP_OK) 

---Program End