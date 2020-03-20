#include "wxutil.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <iostream>

#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

using namespace std;
using namespace tinyxml2;

#define FREE_PTR(ptr)  \
    if (NULL != (ptr)) \
    {                  \
        free(ptr);     \
        (ptr) = NULL;  \
    }

#define DELETE_PTR(ptr) \
    if (NULL != (ptr))  \
    {                   \
        delete (ptr);   \
        (ptr) = NULL;   \
    }

int wxutil::DecryptMsg(const string &sMsgSignature,
                         const string &sTimeStamp,
                         const string &sNonce,
                         const string &sPostData,
                         map<string, string> &mMsg)
{
    string sMsg = sPostData;
    if (this->m_sEncryptType == "AES" ||this->m_sEncryptType == "aes")
    { //1.validate xml format
        string sEncryptMsg;
        if (0 != GetXmlField(sPostData, "Encrypt", sEncryptMsg))
        {
            return ParseXml_Error;
        }

        //2.validate signature
        if (0 != ValidateSignature(sMsgSignature, sTimeStamp, sNonce, sEncryptMsg))
        {
            return ValidateSignature_Error;
        }

        //3.decode base64
        string sAesData;
        if (0 != DecodeBase64(sEncryptMsg, sAesData))
        {
            return DecodeBase64_Error;
        }
        //4.decode aes
        string sAesKey;
        string sNoEncryptData;
        if (0 != GenAesKeyFromEncodingKey(m_sEncodingAESKey, sAesKey))
        {
            return IllegalAesKey;
        }
        if (0 != AES_CBCDecrypt(sAesData, sAesKey, &sNoEncryptData))
        {
            return DecryptAES_Error;
        }

        // 5. remove kRandEncryptStrLen str
        if (sNoEncryptData.size() <= (kRandEncryptStrLen + kMsgLen))
        {
            return IllegalBuffer;
        }
        uint32_t iNetLen = *((const uint32_t *)(sNoEncryptData.c_str() + kRandEncryptStrLen));
        uint32_t iMsgLen = ntohl(iNetLen);
        if (sNoEncryptData.size() <= (kRandEncryptStrLen + kMsgLen + iMsgLen))
        {
            return IllegalBuffer;
        }
        sMsg = sNoEncryptData.substr(kRandEncryptStrLen + kMsgLen, iMsgLen);

        //6. validate appid
        string sAppid = sNoEncryptData.substr(kRandEncryptStrLen + kMsgLen + iMsgLen);
        if (sAppid != m_sAppid)
        {
            return ValidateAppid_Error;
        }
    }
    if (Xml2Map(sMsg, mMsg) != 1)
    {
        return GenLuaTable_error;
    }
    return OK;
}

int wxutil::toXml(lua_State *L)
{
    //    luaL_checktype(L,-1,LUA_TTABLE); 
       int ret =0;
       if (!lua_istable(L, -1))
       {
            lua_pop(L, 1);
            lua_pushstring(L,"error:not a table");
            lua_pushnumber(L,ValidateLuaTable_error);
            return 2;
        }
 
       XMLDocument* Doc = new XMLDocument();
       XMLElement* root = Doc->NewElement("xml");
       Doc->InsertEndChild(root);
       int tableIndex = lua_gettop(L);
       
       travel(L, Doc, tableIndex,root);
       
       XMLPrinter* printer = new XMLPrinter(0,true,0);  
       Doc->Accept(printer);
       string Result = printer->CStr();
       if (this->m_sEncryptType == "AES" ||this->m_sEncryptType == "aes")
        {
            string sEncryptMsg;
            ret = EncryptMsg(Result,this->m_sTimestamp,this->m_sNonce,sEncryptMsg);
            lua_pushstring(L,sEncryptMsg.c_str());
        }else
         {
           lua_pushstring(L,Result.c_str());
         }  
       lua_pushnumber(L,ret);
       delete Doc;
       return 2;
}

void wxutil::travel(lua_State *L, XMLDocument *Doc,int tableIndex, XMLElement* ele)
{
    int keytype;

    lua_pushnil(L);
    while (lua_next(L, tableIndex))
    {
        lua_pushvalue(L,-2);
        // const char * key = lua_tostring(L,-1);
        // XMLElement* index = Doc->NewElement(key);      
        keytype = lua_type(L,-1);
        if (keytype == LUA_TTABLE)
        {
           int sub = lua_gettop(L);
            const char * sub_key = lua_tostring(L,-1);
            lua_pop(L,2);
            XMLElement* sub_Node = Doc->NewElement(sub_key);
            travel(L, Doc,sub,sub_Node);
            ele->InsertEndChild(sub_Node);
            return ;
        }
        else
        {
            const char * key = lua_tostring(L,-1);
            const char * value = lua_tostring(L,-2);
            XMLElement* Node = Doc->NewElement(key);
            XMLText* xText =  Doc->NewText(value);
            xText->SetCData(true);
            Node->InsertEndChild(xText);
            ele->InsertEndChild(Node);
            lua_pop(L, 2);
        }
    }
}

int wxutil::EncryptMsg(const std::string &sReplyMsg,
                const std::string &sTimeStamp,
                const std::string &sNonce,
                std::string &sEncryptMsg)
{
    if(0 == sReplyMsg.size())
    {
        return ParseXml_Error;
    }

    //1.add rand str ,len, appid
    std::string sNeedEncrypt;
    GenNeedEncryptData(sReplyMsg,sNeedEncrypt);
    
    //2. AES Encrypt
    std::string sAesData;
    std::string sAesKey;
    if(0 != GenAesKeyFromEncodingKey(m_sEncodingAESKey,sAesKey)) 
    {
        return IllegalAesKey;
    }
    if(0 != AES_CBCEncrypt(sNeedEncrypt, sAesKey, &sAesData))
    {
        return EncryptAES_Error;
    }    

    //3. base64Encode
    std::string sBase64Data;
    if( 0!= EncodeBase64(sAesData,sBase64Data) )
    {
        return EncodeBase64_Error;
    }
    
    //4. compute signature
    std::string sSignature;
    if(0!=ComputeSignature(m_sToken, sTimeStamp, sNonce, sBase64Data, sSignature))
    {
        return ComputeSignature_Error;
    }
    
    //5. Gen xml
    if(0 != GenReturnXml(sBase64Data, sSignature, sTimeStamp, sNonce, sEncryptMsg) )
    {
        return GenReturnXml_Error ;
    }
    return OK;
}

int wxutil::AES_CBCEncrypt( const std::string & objSource,
        const std::string & objKey, std::string * poResult )
{
    return AES_CBCEncrypt( objSource.data(), objSource.size(),
            objKey.data(), objKey.size(), poResult );
}

int wxutil::AES_CBCEncrypt( const char * sSource, const uint32_t iSize,
        const char * sKey,  uint32_t iKeySize, std::string * poResult )
{
    if ( !sSource || !sKey || !poResult || iSize <= 0)
    {
        return -1;
    }
    
    poResult->clear();

    int padding = kAesKeySize - iSize % kAesKeySize;

    char * tmp = (char*)malloc( iSize + padding );
    if(NULL == tmp)
    {
        return -1;
    }
    memcpy( tmp, sSource, iSize );
    memset( tmp + iSize, padding, padding );
    
    unsigned char * out = (unsigned char*)malloc( iSize + padding );
    if(NULL == out)
    {
        FREE_PTR(tmp);
        return -1;
    }

    unsigned char key[ kAesKeySize ] = { 0 };
    unsigned char iv[ kAesIVSize ] = { 0 };
    memcpy( key, sKey, iKeySize > kAesKeySize ? kAesKeySize : iKeySize );
    memcpy(iv, key, sizeof(iv) < sizeof(key) ? sizeof(iv) : sizeof(key));

    AES_KEY aesKey;
    AES_set_encrypt_key( key, 8 * kAesKeySize, &aesKey );
    AES_cbc_encrypt((unsigned char *)tmp, out,iSize + padding,  &aesKey, iv, AES_ENCRYPT);
    poResult->append((char*)out, iSize + padding);
    
    FREE_PTR(tmp);
    FREE_PTR(out);
    return 0;
}

int wxutil::AES_CBCDecrypt(const string &objSource,
                             const string &objKey, string *poResult)
{
    return AES_CBCDecrypt(objSource.data(), objSource.size(),
                          objKey.data(), objKey.size(), poResult);
}

int wxutil::AES_CBCDecrypt(const char *sSource, const uint32_t iSize,
                             const char *sKey, uint32_t iKeySize, string *poResult)
{
    if (!sSource || !sKey || iSize < kAesKeySize || iSize % kAesKeySize != 0 || !poResult)
    {
        return -1;
    }
    poResult->clear();

    unsigned char *out = (unsigned char *)malloc(iSize);
    if (NULL == out)
    {
        return -1;
    }

    unsigned char key[kAesKeySize] = {0};
    unsigned char iv[kAesIVSize] = {0};
    memcpy(key, sKey, iKeySize > kAesKeySize ? kAesKeySize : iKeySize);
    memcpy(iv, key, sizeof(iv) < sizeof(key) ? sizeof(iv) : sizeof(key));

    int iReturnValue = 0;
    AES_KEY aesKey;
    AES_set_decrypt_key(key, 8 * kAesKeySize, &aesKey);
    AES_cbc_encrypt((unsigned char *)sSource, out, iSize, &aesKey, iv, AES_DECRYPT);
    if (out[iSize - 1] > 0 && out[iSize - 1] <= kAesKeySize && (iSize - out[iSize - 1]) > 0)
    {
        poResult->append((char *)out, iSize - out[iSize - 1]);
    }
    else
    {
        iReturnValue = -1;
    }

    FREE_PTR(out);
    return iReturnValue;
}

int wxutil::EncodeBase64(const std::string sSrc, std::string & sTarget)
{
    if(0 == sSrc.size() || kMaxBase64Size < sSrc.size())
    {
        return -1;
    }
    
    uint32_t iBlockNum = sSrc.size() / 3;
    if (iBlockNum * 3 != sSrc.size())
    {
        iBlockNum++;
    }
    uint32_t iOutBufSize = iBlockNum * 4 + 1;
    
    char * pcOutBuf = (char*)malloc( iOutBufSize);
    if(NULL == pcOutBuf)
    {
        return -1;
    }
    int iReturn = 0;
    int ret = EVP_EncodeBlock((unsigned char*)pcOutBuf, (const unsigned char*)sSrc.c_str(), sSrc.size());
    if (ret > 0 && ret < (int)iOutBufSize)
    {
        sTarget.assign(pcOutBuf,ret);
    }
    else
    {
        iReturn = -1;
    }
    
    FREE_PTR(pcOutBuf);
    return iReturn;
}

int wxutil::DecodeBase64(const string sSrc, string &sTarget)
{
    if (0 == sSrc.size() || kMaxBase64Size < sSrc.size())
    {
        return -1;
    }
    int iEqualNum = 0;
    for (int n = sSrc.size() - 1; n >= 0; --n)
    {
        if (sSrc.c_str()[n] == '=')
        {
            iEqualNum++;
        }
        else
        {
            break;
        }
    }
    int iOutBufSize = sSrc.size();
    char *pcOutBuf = (char *)malloc(iOutBufSize);
    if (NULL == pcOutBuf)
    {
        return -1;
    }
    int iRet = 0;
    int iTargetSize = 0;
    iTargetSize = EVP_DecodeBlock((unsigned char *)pcOutBuf, (const unsigned char *)sSrc.c_str(), sSrc.size());
    if (iTargetSize > iEqualNum && iTargetSize < iOutBufSize)
    {
        sTarget.assign(pcOutBuf, iTargetSize - iEqualNum);
    }
    else
    {
        iRet = -1;
    }
    FREE_PTR(pcOutBuf);
    return iRet;
}

int wxutil::ComputeSignature(const string sToken, const string sTimeStamp, const string &sNonce,
                               const string &sMessage, string &sSignature)
{
    if (0 == sToken.size() || 0 == sNonce.size() || 0 == sMessage.size() || 0 == sTimeStamp.size())
    {
        return -1;
    }

    //sort
    vector<string> vecStr;
    vecStr.push_back(sToken);
    vecStr.push_back(sTimeStamp);
    vecStr.push_back(sNonce);
    vecStr.push_back(sMessage);
    sort(vecStr.begin(), vecStr.end());
    string sStr = vecStr[0] + vecStr[1] + vecStr[2] + vecStr[3];

    //compute
    unsigned char output[SHA_DIGEST_LENGTH] = {0};
    if (NULL == SHA1((const unsigned char *)sStr.c_str(), sStr.size(), output))
    {
        return -1;
    }

    // to hex
    sSignature.clear();
    char tmpChar[8] = {0};
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        snprintf(tmpChar, sizeof(tmpChar), "%02x", 0xff & output[i]);
        sSignature.append(tmpChar);
    }
    return 0;
}

int wxutil::ValidateSignature(const string &sMsgSignature, const string &sTimeStamp,
                                const string &sNonce, const string &sEncryptMsg)
{
    string sSignature;
    if (0 != ComputeSignature(m_sToken, sTimeStamp, sNonce, sEncryptMsg, sSignature))
    {
        return -1;
    }
    if (sMsgSignature != sSignature)
    {
        return -1;
    }
    return 0;
}

int wxutil::GenAesKeyFromEncodingKey(const string &sEncodingKey, string &sAesKey)
{
    if (kEncodingKeySize != sEncodingKey.size())
    {
        return -1;
    }
    string sBase64 = sEncodingKey + "=";
    int ret = DecodeBase64(sBase64, sAesKey);
    if (0 != ret || kAesKeySize != sAesKey.size())
    {
        return -1;
    }
    return 0;
}

int wxutil::GetXmlField(const string &sPostData, const string &sField, string &sEncryptMsg)
{
    tinyxml2::XMLDocument xmlDoc;
    if (tinyxml2::XML_SUCCESS != xmlDoc.Parse(sPostData.c_str(), sPostData.size()))
    {
        return -1;
    }
    tinyxml2::XMLElement *xmlElement = xmlDoc.FirstChildElement("xml");
    if (NULL == xmlElement)
    {
        return -1;
    }
    tinyxml2::XMLElement *msgElement = xmlElement->FirstChildElement(sField.c_str());
    if (NULL == msgElement)
    {
        return -1;
    }
    const char *pMsgBuf = msgElement->GetText();
    if (NULL == pMsgBuf)
    {
        return -1;
    }

    sEncryptMsg = pMsgBuf;
    return 0;
}

void wxutil::GenNeedEncryptData(const std::string &sReplyMsg,std::string & sNeedEncrypt )
{
    //random(16B)+ msg_len(4B) + msg + $AppId
    std::string sRandStr;
    GenRandStr(sRandStr,kRandEncryptStrLen);
    uint32_t iXmlSize = sReplyMsg.size();
    uint32_t iNSize  = htonl(iXmlSize);
    std::string sSize ;
    sSize.assign((const char *)&iNSize,sizeof(iNSize));
    
    sNeedEncrypt.erase();
    sNeedEncrypt = sRandStr;
    sNeedEncrypt += sSize;
    sNeedEncrypt += sReplyMsg;
    sNeedEncrypt += m_sAppid;
}

int wxutil::SetOneFieldToXml(tinyxml2::XMLDocument * pDoc, tinyxml2::XMLNode* pXmlNode, const char * pcFieldName, 
    const std::string & value, bool bIsCdata)
{
    if(!pDoc || !pXmlNode || !pcFieldName)
    {
        return -1;
    }
    
    tinyxml2::XMLElement * pFiledElement = pDoc->NewElement(pcFieldName);  
    if(NULL == pFiledElement)
    {
        return -1;
    }
    
    tinyxml2::XMLText * pText = pDoc->NewText(value.c_str()); 
    if(NULL == pText)
    {
        return -1;
    }
    
    pText->SetCData(bIsCdata);
    pFiledElement->LinkEndChild(pText);  
    
    pXmlNode->LinkEndChild(pFiledElement);  
    return 0;
}

int wxutil::Xml2Map(const string sMsg, map<string, string> &mMsg)
{

    tinyxml2::XMLDocument xmlDoc;
    if (tinyxml2::XML_SUCCESS != xmlDoc.Parse(sMsg.c_str(), sMsg.size()))
    {
        return -1;
    }
    tinyxml2::XMLElement *xmlElement = xmlDoc.FirstChildElement("xml");
    if (NULL == xmlElement)
    {
        return -1;
    }
    //Begin for test
    // string key ("wxmsg");
    // mMsg.insert(make_pair(key,sMsg));
    //end
    xmlElement = xmlElement->FirstChildElement();
    if (NULL == xmlElement)
    {
        return -1;
    }
    while (xmlElement)
    {
        const char *node_name = xmlElement->Name();
        const char *cdata = xmlElement->GetText();
        mMsg.insert(make_pair(node_name, cdata));
        xmlElement = xmlElement->NextSiblingElement();
    }
    return 1;
}

void wxutil::GenRandStr(string &sRandStr, uint32_t len)
{
    uint32_t idx = 0;
    srand((unsigned)time(NULL));
    char tempChar = 0;
    sRandStr.clear();
    while (idx < len)
    {
        tempChar = rand() % 128;
        if (isprint(tempChar))
        {
            sRandStr.append(1, tempChar);
            ++idx;
        }
    }
}

int wxutil::GenReturnXml(const std::string & sEncryptMsg, const std::string & sSignature, const std::string & sTimeStamp, 
    const std::string & sNonce, std::string & sResult)
{
    tinyxml2::XMLPrinter oPrinter;
    tinyxml2::XMLNode* pXmlNode = NULL;
    tinyxml2::XMLDocument * pDoc = new tinyxml2::XMLDocument();
    if(NULL == pDoc)
    {
        return -1;
    }
    
    pXmlNode = pDoc->InsertEndChild( pDoc->NewElement( "xml" ) );
    if(NULL == pXmlNode)
    {
        DELETE_PTR(pDoc);
        return -1;
    }

    if(0 != SetOneFieldToXml(pDoc,pXmlNode,"Encrypt",sEncryptMsg,true))
    {
        DELETE_PTR(pDoc);
        return -1;
    }

    if(0 != SetOneFieldToXml(pDoc,pXmlNode,"MsgSignature",sSignature,true))
    {
        DELETE_PTR(pDoc);
        return -1;
    }

    if(0 != SetOneFieldToXml(pDoc,pXmlNode,"TimeStamp",sTimeStamp,true))
    {
        DELETE_PTR(pDoc);
        return -1;
    }

    if(0 != SetOneFieldToXml(pDoc,pXmlNode,"Nonce",sNonce,true))
    {
        DELETE_PTR(pDoc);
        return -1;
    }

    //转成string
    pDoc->Accept(&oPrinter);
    sResult = oPrinter.CStr();
    
    DELETE_PTR(pDoc);
    return 0;    
}



const char wxutil::className[] = "wxutil";

Lunar<wxutil>::RegType wxutil::methods[] = {
    LUNAR_DECLARE_METHOD(wxutil, getMsg),
    LUNAR_DECLARE_METHOD(wxutil, toXml),
    {0, 0}};

extern "C"
{
    int luaopen_wxutil(lua_State *L)
    {

        Lunar<wxutil>::Register(L);

        return 1;
    }
}
