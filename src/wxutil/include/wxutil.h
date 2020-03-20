
#pragma once

#include <string>
#include <stdint.h>
#include <map>
#include "tinyxml2.h"
#include "lunar.h"

using namespace std;
static const unsigned int kAesKeySize = 32;
static const unsigned int kAesIVSize = 16;
static const unsigned int kEncodingKeySize = 43;
static const unsigned int kRandEncryptStrLen = 16;
static const unsigned int kMsgLen = 4;
static const unsigned int kMaxBase64Size = 1000000000;

enum ErrorCode
{
    OK = 0,
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
    GenLuaTable_error = -40012,
    ValidateLuaTable_error =-40013,
};

class wxutil
{
  public:
    wxutil(lua_State *L)
    {
        luaL_argcheck(L, lua_gettop(L) == 4, 4, "expected 4 argument");
        m_sToken = lua_tostring(L, 1);
        m_sEncodingAESKey = lua_tostring(L, 2);
        m_sAppid = lua_tostring(L, 3);
        m_sEncryptType = lua_tostring(L, 4);
    }
    int EncryptMsg(const std::string &sReplyMsg,
                    const std::string &sTimeStamp,
                    const std::string &sNonce,
                    std::string &sEncryptMsg);
    int getMsg(lua_State *L)
    {
        luaL_argcheck(L, lua_gettop(L) == 4, 4, "expected 5 argument");
        map<string, string> mMsg;
        string sMsgSignature =luaL_checkstring(L, 1);
        string sTimestamp = luaL_checkstring(L, 2);
        string sNonce   = luaL_checkstring(L, 3);
        string sPostData = luaL_checkstring(L, 4);
        this->m_sNonce = sNonce;
        this->m_sTimestamp = sTimestamp;
        int ret = DecryptMsg(
            sMsgSignature, sTimestamp, sNonce, sPostData, mMsg);
        //return result to lua script
        lua_pushinteger(L, ret);
        //lightuserdata can not process in lua script
        if (ret == OK)
        {
            lua_newtable(L);
            map<string, string>::iterator iter;
            iter = mMsg.begin();
            while (iter != mMsg.end())
            {
                lua_pushstring(L, iter->first.c_str());
                lua_pushstring(L, iter->second.c_str());
                lua_settable(L, -3);
                iter++;
            }
            //    lua_pushlightuserdata(L,(void*)&mMsg);
            //    lua_pushstring(L,sMsg.c_str());
        }else {
            lua_pushstring(L,"error!");
        }
        return 2;
    }
    int toXml(lua_State *L);
    ~wxutil(){};
    static const char className[];
    static Lunar<wxutil>::RegType methods[];

  private:
    string m_sToken;
    string m_sEncodingAESKey;
    string m_sAppid;
    string m_sEncryptType;
    string m_sTimestamp;
    string m_sNonce;

  private:
    int DecryptMsg(const string &sMsgSignature,
                   const string &sTimeStamp,
                   const string &sNonce,
                   const string &sPostData,
                   map<string, string> &sMsg);

    void travel(lua_State* L, tinyxml2::XMLDocument * Doc, int rableIndex, tinyxml2::XMLElement* ele);
    // AES CBC
    // AES CBC
    int AES_CBCEncrypt( const char * sSource, const uint32_t iSize,
            const char * sKey, unsigned int iKeySize, std::string * poResult );
    
    int AES_CBCEncrypt( const std::string & objSource,
            const std::string & objKey, std::string * poResult );

    int AES_CBCDecrypt(const char *sSource, const uint32_t iSize,
                       const char *sKey, uint32_t iKeySize, string *poResult);

    int AES_CBCDecrypt(const string &objSource,
                       const string &objKey, string *poResult);

    //base64

    int DecodeBase64(const string sSrc, string &sTarget);

    int EncodeBase64(const std::string sSrc, std::string & sTarget);


    //genkey
    int GenAesKeyFromEncodingKey(const string &sEncodingKey, string &sAesKey);

    //signature
    int ComputeSignature(const string sToken, const string sTimeStamp, const string &sNonce,
                         const string &sMessage, string &sSignature);

    int ValidateSignature(const string &sMsgSignature, const string &sTimeStamp,
                          const string &sNonce, const string &sEncryptMsg);

    //get , set data
    void GenRandStr(string &sRandStr, uint32_t len);

    void GenNeedEncryptData(const std::string &sReplyMsg,std::string & sNeedEncrypt );


    int GetXmlField(const string &sPostData, const string &sField, string &sEncryptMsg);

    int SetOneFieldToXml(tinyxml2::XMLDocument * pDoc, tinyxml2::XMLNode* pXmlNode, const char * pcFieldName, 
        const std::string & value, bool bIsCdata);

    int GenReturnXml(const std::string & sEncryptMsg, const std::string & sSignature, const std::string & sTimeStamp, 
        const std::string & sNonce, std::string & sResult);


    int Xml2Map(const string sMsg, map<string, string> &mMsg);
};
