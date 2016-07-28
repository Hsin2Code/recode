#include <iostream>
#include <string.h>
#include <unistd.h>
#include "regesiter.h"
#include "common.h"
#include <sys/socket.h>
#include <sys/errno.h>
#include "old_functions.h"
#include "CSoftInstallHelper.h"
#include "CDeviceinfoHelper.h"

struct tag_S_Soft_Asset {
    void  *   pAdd ;
    void  *   pDel ;
    void  *   pModify ;
    bool      bFirst ;
    tag_S_Soft_Asset() {
        pAdd = NULL ;
        pDel = NULL ;
        pModify = NULL ;
        bFirst = false;
    }
};

struct tag_S_Hard_Asset {
    void *  pAdd ;
    void *  pDel ;
    void *  pModify ;
    void *  pFrontstr;
    void *  pOld;
    void *  pMap ;
    tag_S_Hard_Asset() {
        pAdd = NULL ;
        pDel = NULL ;
        pModify = NULL ;
    }
};


#define  SEND_LOG_BUF_LEN     (1024*256)
static char m_plogBuffer[SEND_LOG_BUF_LEN] = {0};
static char m_plogBufferDest [SEND_LOG_BUF_LEN * 2 + 1] = {0};

const  char * g_asset_desc[asset_count] = {
    "硬盘","光驱","处理器","主板","内存","显卡","键盘","声音,视频和游戏控制器","鼠标和其他指针设备","网卡","软盘驱动器","系统插槽",
    "USB接口类型","网卡速率","内存使用情况","硬盘使用情况"};

bool do_regesiter(const std::string &dev_id) {
    if(dev_id.empty()) {
        return false;
    }
    std::string basic_info = "DBField0=UserName\r\n"
        "DBValue0=";
    basic_info.append(dev_id + "\r\n");
    basic_info.append("DBField1=DeptName\r\n"
                      "DBValue1=NSEC\r\n"
                      "DBField2=OfficeName\r\n"
                      "DBValue2=NSEC\r\n"
                      "DBField3=RoomNumber\r\n"
                      "DBValue3=101\r\n"
                      "DBField4=Tel\r\n"
                      "DBValue4=190000101010\r\n"
                      "DBField5=Email\r\n"
                      "DBValue5=nsec@vrv.com\r\n"
                      "DBField6=Reserved2\r\n"
                      "DBValue6=2:Windows笔记本\r\n"
                      "DBField7=FloorNumber\r\n"
                      "DBValue7=8\r\n"
                      "DBFieldCount=8\r\n"
                      "SelectNicInfo=xxx.xxx.xxx.xxx/000c29d6b5d9\r\n"
                      "WebServerIP=192.168.131.94\r\n");


    /*extened*/
    basic_info.append("MACAddress0=xx-xx-xx-xx-xx-xx\r\n");
    basic_info.append("IPAddress0=" + g_self_ipaddr +"\r\n");
    basic_info.append("MACCount=1\r\n"
                      "IPCount=1\r\n");
    basic_info.append("DeviceIdentify=");
    basic_info.append(dev_id + "\r\n");
    basic_info.append("ComputerName=fake computer name\r\n");
    basic_info.append("EdpRegVersion=3.3.3.3\r\n");
    basic_info.append("OSVersion=2.6\r\n");
    basic_info.append("OSType=GNU/Linux\r\n");

    SM_LOG() << "get basic info suceess";

    int skt = socket(AF_INET,SOCK_STREAM,0);

    if(skt == -1) {
        SM_ERROR() << "create socket error";
        return false;
    }
    ///主动链接服务器
    if(!conn_serv(skt)) {
        SM_ERROR() << "connect server error";
        closeSocket(skt);
        return false ;
    }

    ///获取加密密钥
    unsigned int  pwd ;
    if(!get_pwd(skt,pwd)) {
        SM_ERROR() << "get pwd error and close socket ";
        closeSocket(skt);
        return false ;
    }

    VRVPacketEx pktEx;
    if(!pktEx.SendPktEx(skt,114,0,pwd,0,0,
                        (unsigned char *)basic_info.c_str(),basic_info.length())) {
        close_socket(skt, __LINE__);
        return false ;
    }

    if(!pktEx.RecvPktEx(skt,pwd))  {
        SM_ERROR() << "S_CMD_USER_REGISTER pktEx.RecvPkt recv error = " << errno;
        close_socket(skt, __LINE__);
        return false ;
    }

    if(pktEx.head.m_Flag != VRV_FLAG || pktEx.head.m_Type != EX_OK ) {
        if(pktEx.head.m_Flag != VRV_FLAG) {
            SM_ERROR() << "VRV_FLAG MISMATCH ";
        } else if(pktEx.head.m_Type != EX_OK) {
            SM_ERROR() << "head type MISMATCH: " << pktEx.head.m_Type;
        }
        close_socket(skt, __LINE__);
        return false ;
    }
    SM_LOG() << "REGESITER SUCCESS";
    close_socket(skt, __LINE__);
    return true;
}

/**
 *	@skt 已经链接上的套接子
 *	@vt  软件资产的数组
 *	@what 更新类型
 *	@pFront 标识前缀
 */
#define SOFT_MAX 1500
bool  report_soft_asset(int skt,unsigned int pwd , std::vector<tag_SoftInstallEx> & _vt, unsigned short what ,const char * pFront) {
    if(_vt.size() == 0) {
        return true ;
    }

    std::string strmac,strip,strid;
    strid = g_dev_id;
    strmac = g_dev_id; /*set mac address with dev_id*/
    strip = g_self_ipaddr;

    ///当前登录用户
    std::string user = "fake_user";

    VRVPacketEx pktEx;
    size_t     index = 0 ;
    size_t     data_len = 0 ;
    size_t     max = SOFT_MAX ;
    if(_vt.size() < max) {
        max = _vt.size() ;
    }

    ///判断是否第一次发送的第一个包
    bool bfirst = false ;
    if(what == SOFTWARE_REFRESH) {
        bfirst = true ;
    }

    ///获取日志头
    int  npos = get_logHeader(m_plogBuffer,
                              strip,strmac,strid,user);
    char  * pTmp = m_plogBuffer + npos ;
    sprintf(pTmp,"%sCount=%d%s",pFront,max,STRITEM_TAG_END);
    int  head_len = strlen(m_plogBuffer);
    pTmp = m_plogBuffer + head_len ;

    int  send_item_count = 0 ;
    std::vector<tag_SoftInstallEx>::iterator iter = _vt.begin();
    while(iter != _vt.end()) {
        sprintf(pTmp,"%sCRC%d=%s%s"\
                "%sName%d=%s%s"\
                "%sTime%d=%s%s"\
                "%sVersion%d=%s%s", pFront, index,ins_soft_hash(iter->name.c_str(),iter->version.c_str()).c_str(),STRITEM_TAG_END,
                pFront,index,iter->name.c_str(),STRITEM_TAG_END,
                pFront,index,iter->time.c_str(),STRITEM_TAG_END,
                pFront,index,iter->version.c_str(),STRITEM_TAG_END);
        data_len += strlen(pTmp);
        ///获取下一次的的指针位置
        pTmp = m_plogBuffer + head_len +  data_len;
        index++;

        if(index==max) {
            if(!bfirst && SOFTWARE_REFRESH == what) {
                what = SOFTWARE_ADDTAIL;
            }
            if(bfirst) {
                bfirst = false ;
            }
            int  send_len = SEND_LOG_BUF_LEN*2 + 1 ;

            ///可能含有中文，需要转码
            if(!code_convert("utf-8","gb2312",(char *)m_plogBuffer,head_len+data_len,m_plogBufferDest,send_len)) {
                return false ;
            }
            SM_LOG() << "send max in loop: " << max << " send len: " << send_len;
            send_len = strlen(m_plogBufferDest);
            if(!pktEx.SendPktEx(skt,AGENT_RPT_SOFTWARE,what,pwd,0,ENC_VERSION1,(BYTE*)m_plogBufferDest,send_len)) {
                char log[32]="";
                sprintf(log,"发送失败:what =  %d\n",what);
                SM_ERROR() << log;
                return false ;
            }
            if(!pktEx.RecvPktEx(skt, pwd)) {
                return false ;
            }
            if(pktEx.head.m_Flag != VRV_FLAG) {
                SM_ERROR() << "接受ＦＬＡＧ失败";
                return false ;
            }
            send_item_count += max ;

            ///计算剩下的数量
            pTmp = m_plogBuffer + npos ;
            max = _vt.size() - send_item_count ;
            if(max > SOFT_MAX) {
                max = SOFT_MAX ;
            }
            sprintf(pTmp,"%sCount=%d%s",pFront,max,STRITEM_TAG_END);
            head_len = strlen(m_plogBuffer);
            pTmp = m_plogBuffer + head_len ;
            index = 0 ;
            data_len = 0 ;
        }
        iter++ ;
    }
    return true ;
}

bool report_hard_asset(int skt ,unsigned int pwd ,
                       tag_S_Hard_Asset * pAsset) {
    CDeviceInfoMap *  pAdd = (CDeviceInfoMap *)pAsset->pAdd;
    CDeviceInfoMap *  pDel = (CDeviceInfoMap *)pAsset->pDel;
    CDeviceInfoMap *  pModify = (CDeviceInfoMap *)pAsset->pModify;
    CDeviceInfoMap *  pOld = (CDeviceInfoMap *)pAsset->pOld;
    CDeviceInfoMap *  pMap = (CDeviceInfoMap *)pAsset->pMap ;
    std::string    *  pStr = (std::string    *)pAsset->pFrontstr;

    std::string strmac,strip,strid;
    strid = g_dev_id;
    strmac = g_dev_id; /*set mac address with dev_id*/
    strip = g_self_ipaddr;

    ///当前登录用户
    std::string user = "fake_user";

    VRVPacket packet;
    ///获取日志头
    get_logHeader(m_plogBuffer,
                  strip,strmac,strid,user);


    std::string tmp ;
    int  index = 0 ;
    char num_buf[16] = "";

    if(pMap->size() > 0) {
        CDeviceInfoMap::iterator iter = pMap->begin();
        while(iter != pMap->end()) {
            sprintf(num_buf,"%d",index++);
            tmp = tmp + "DEVICE_"+num_buf+"_DESC="+g_asset_desc[iter->first]+STRITEM_TAG_END;
            tmp = tmp + "DEVICE_"+num_buf+"="+iter->second+STRITEM_TAG_END;
            iter++ ;
        }
    }
    if(pAdd->size()  >  0) {
        index = 0;
        CDeviceInfoMap::iterator iter = pAdd->begin();
        while(iter != pAdd->end()) {
            sprintf(num_buf,"%d",index++);
            tmp = tmp + "NEW_DEVICE_"+num_buf+"_DESC="+g_asset_desc[iter->first]+STRITEM_TAG_END;
            tmp = tmp + "NEW_DEVICE_"+num_buf+"="+iter->second+STRITEM_TAG_END;
            iter++ ;
        }
    }
    if(pDel->size() > 0) {
        index = 0;
        CDeviceInfoMap::iterator iter = pDel->begin();
        while(iter != pDel->end()) {
            sprintf(num_buf,"%d",index++);
            tmp = tmp + "DEL_DEVICE_"+num_buf+"_DESC="+g_asset_desc[iter->first]+STRITEM_TAG_END;
            tmp = tmp + "DEL_DEVICE_"+num_buf+"="+iter->second+STRITEM_TAG_END;
            iter++ ;
        }
    }
    if(pModify->size() > 0) {
        index = 0;
        ///先删除旧的
        CDeviceInfoMap::iterator iter = pModify->begin();
        while(iter != pModify->end()) {
            SM_LOG() << "old soft: " << pOld->size() << " modify: " << iter->second;
            CDeviceInfoMap::iterator iterold = pOld->find(iter->first);
            if(iterold != pOld->end()) {
                sprintf(num_buf,"%d",pDel->size() + index);
                tmp = tmp + "DEL_DEVICE_"+num_buf+"_DESC="+g_asset_desc[iter->first]+STRITEM_TAG_END;
                tmp = tmp + "DEL_DEVICE_"+num_buf+"="+iterold->second+STRITEM_TAG_END;
                sprintf(num_buf,"%d",pAdd->size() + index);
                tmp = tmp + "NEW_DEVICE_"+num_buf+"_DESC="+g_asset_desc[iter->first]+STRITEM_TAG_END;
                tmp = tmp + "NEW_DEVICE_"+num_buf+"="+iter->second+STRITEM_TAG_END;
            }
            index++;
            iter++ ;
        }
    }

    SM_LOG() << "add: " << pAdd->size() << " modify: " << pModify->size() << " Del: " << pDel->size();
    sprintf(m_plogBuffer+strlen(m_plogBuffer),"%s%sListCount=%d%sNewCount=%d%sDelCount=%d%s",pStr->c_str(),tmp.c_str(),
            pMap->size(),STRITEM_TAG_END,pAdd->size()+pModify->size(),STRITEM_TAG_END,pDel->size()+pModify->size(),STRITEM_TAG_END);
    int  data_len = strlen(m_plogBuffer);
    int  send_len = (data_len)*2 + 1 ;

    ///可能含有中文，需要转码
    if(!code_convert("utf-8","gb2312",(char *)m_plogBuffer,data_len,m_plogBufferDest,send_len)) {
        return false ;
    }
    send_len = strlen(m_plogBufferDest);

    if(!packet.SendPkt(skt,AGENT_RPTDEVEX,0,pwd,0,
                       (BYTE *)m_plogBufferDest,send_len)) {
        return false ;
    }

    if(!packet.RecvPkt(skt,pwd)) {
        return false ;
    }

    if(packet.head.m_Flag  != VRV_FLAG) {
        return false ;
    }

    return true ;
}



static bool _send_hard_assert(struct tag_S_Hard_Asset &passert) {
#if 1
    int skt = socket(AF_INET,SOCK_STREAM,0);

    if(skt == -1) {
        return false;
    }
    ///主动链接服务器
    if(!conn_serv(skt)) {
        closeSocket(skt);
        return false ;
    }

    ///获取加密密钥
    unsigned int  pwd ;
    if(!get_pwd(skt,pwd)) {
        SM_ERROR() << "get pwd error and close socket ";
        closeSocket(skt);
        return false ;
    }
#endif
    tag_S_Hard_Asset * pAsset = &passert ;
    if(!report_hard_asset(skt,pwd,pAsset)) {
        close_socket(skt, __LINE__);
        return false ;
    }
    close_socket(skt, __LINE__);
    return true;
}



static bool _send_soft_assert(struct tag_S_Soft_Asset &passert) {

#if 1
    int skt = socket(AF_INET,SOCK_STREAM,0);

    if(skt == -1) {
        return false;
    }
    ///主动链接服务器
    if(!conn_serv(skt)) {
        closeSocket(skt);
        return false ;
    }

    ///获取加密密钥
    unsigned int  pwd ;
    if(!get_pwd(skt,pwd)) {
        SM_ERROR() << "get pwd error and close socket " ;
        closeSocket(skt);
        return false ;
    }
#endif

    tag_S_Soft_Asset * pAsset = &passert;

    std::vector<tag_SoftInstallEx> * pAdd = (std::vector<tag_SoftInstallEx> *)pAsset->pAdd ;
    std::vector<tag_SoftInstallEx> * pDel = (std::vector<tag_SoftInstallEx> *)pAsset->pDel ;
    std::vector<tag_SoftInstallEx> * pModify = (std::vector<tag_SoftInstallEx> *)pAsset->pModify ;

    char  sz[128]="";
    sprintf(sz,"add: %d, del: %d, modify: %d\n",pAdd->size(),pDel->size(),pModify->size());
    SM_LOG() << sz;

    ///第一次初始化
    if(pAsset->bFirst) {
        if(!report_soft_asset(skt,pwd,*pAdd,SOFTWARE_REFRESH,"Add")) {
            close_socket(skt, __LINE__);
            return false ;
        }
    } else {
        if(!report_soft_asset(skt,pwd,*pAdd,SOFTWARE_ADDTAIL,"Add")) {
            close_socket(skt, __LINE__);
            return false ;
        }
    }
    if(!report_soft_asset(skt,pwd,*pDel,SOFTWARE_DELETE,"Del")) {
        close_socket(skt, __LINE__);
        return false ;
    }

    if(pModify->size()) {
        if(!report_soft_asset(skt,pwd,*pModify,SOFTWARE_DELETE,"Del")) {
            close_socket(skt, __LINE__);
            return false ;
        }
        if(!report_soft_asset(skt,pwd,*pModify,SOFTWARE_ADDTAIL,"Add")) {
            close_socket(skt, __LINE__);
            return false ;
        }
    }
    close_socket(skt, __LINE__);
    return true;
}

void _report_soft_assert() {
    CSoftInstallHelper helper;
    CSoftinstallmap  oldsoftmap;
    std::vector<tag_SoftInstallEx> vt_add ; //增加软件列表
    std::vector<tag_SoftInstallEx> vt_modify; //改变的软件列表
    std::vector<tag_SoftInstallEx> vt_del ;   //删除的软件列表

    ///先处理软件资产
    CSoftInstallHelper install_helper ;
    if(install_helper.Init()) {
        install_helper.Check(oldsoftmap,vt_add,vt_del,vt_modify);

        tag_S_Soft_Asset send ;
        send.pAdd = &vt_add ;
        send.pDel = &vt_del ;
        send.pModify = &vt_modify ;
        if(oldsoftmap.size() == 0) {
            send.bFirst = true ;
        } else {
            send.bFirst = false ;
        }
        if(vt_add.size() || vt_del.size() || vt_modify.size()) {
            if(!_send_soft_assert(send)) {
                SM_ERROR() <<  "send soft info false";
            }
        }
    } else {
        SM_ERROR() << "install_helper.Init()  failded!";
    }


}
void _report_hard_assert() {
    CDeviceinfoHelper  hard_Helper ;

    CDeviceInfoMap   oldhardmap ;
    CDeviceInfoMap   map_add ;
    CDeviceInfoMap   map_modify;
    CDeviceInfoMap   map_del ;

    if(hard_Helper.init()) {
        CDeviceInfoMap   oldhardmap1 =  oldhardmap;
        hard_Helper.check(oldhardmap,map_add,map_del,map_modify);

        tag_S_Hard_Asset sendEx;
        sendEx.pAdd = &map_add ;
        sendEx.pDel = &map_del ;
        sendEx.pModify = &map_modify ;
        sendEx.pFrontstr = &hard_Helper.getfront();
        sendEx.pOld = &oldhardmap1 ;
        sendEx.pMap = &hard_Helper.getMap();
        if(map_add.size() || map_del.size() || map_modify.size()) {
            if(!_send_hard_assert(sendEx)) {
                SM_ERROR() << "send hard assert failed";
            }
        }
    }
}

void report_assert() {
    _report_hard_assert();
    _report_soft_assert();
}


static bool _do_heart_beat() {

    std::string strmac,strip,strid;
    strmac = g_dev_id;
    strip = g_self_ipaddr;
    strid = g_dev_id;

    int skt = socket(AF_INET,SOCK_STREAM,0);

    if(skt == -1) {
        return false;
    }
    ///主动链接服务器
    if(!conn_serv(skt)) {
        closeSocket(skt);
        return false ;
    }

    ///获取加密密钥
    unsigned int  pwd ;
    if(!get_pwd(skt,pwd)) {
        SM_ERROR() << "get pwd error and close socket ";
        closeSocket(skt);
        return false ;
    }

    char sz[256] = "";
    sprintf(sz,"MACAddress0=%s%s"
            "IPAddress0=%s%s"
            "MACCount=1%s"
            "IPCount=1%s"
            "DeviceIdentify=%s%s"
            ,strmac.c_str(),STRITEM_TAG_END,
            strip.c_str(),STRITEM_TAG_END,STRITEM_TAG_END,STRITEM_TAG_END,
            strid.c_str(),STRITEM_TAG_END);

    VRVPacketEx pktEx;
    if(!pktEx.SendPktEx(skt,AGENT_GETCONFIG_STRING, 0, pwd
                        , 0, ENC_VERSION1, (BYTE*)sz,strlen(sz))) {
        close_socket(skt, __LINE__);
        return false ;
    }

    if(!pktEx.RecvPktEx(skt,pwd))  {
        close_socket(skt, __LINE__);
        return false ;
    }
    if(pktEx.head.m_Flag != VRV_FLAG) {
        close_socket(skt, __LINE__);
        return false ;
    }
    close_socket(skt, __LINE__);
    return true;
}

void *heart_beat_worker(void *args) {
    while(1) {
        if(!_do_heart_beat()) {
            SM_ERROR() << "heart failed ";
        }
        /*30s*/
        //usleep(30000000);
        usleep(3000000);
        SM_LOG() << "send heart beat..";
    }
    return NULL;

}
