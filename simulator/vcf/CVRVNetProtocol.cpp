/*
 * CVRVNetProtocol.cpp
 *
 *  Created on: 2014-12-8
 *      Author: sharp
 */

#include "CVRVNetProtocol.h"
#include "stdlib.h"
#include <string.h>
#include "common/CLocker.h"
#include <netdb.h>
#include <stdio.h>
#include "ldbdefine.h"
#include <vector>
#include <iconv.h>
#include "common/Commonfunc.h"
using namespace YCommonTool ;
#include "VCFCmdDefine.h"
#include "vrcport_tool.h"
#include "CDeviceinfoHelper.h"
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "policys/policysExport.h"
#include "../include/MCInterface.h"
#include "CVCFApp.h"

IVCFAppSendinterface * g_GetSendInterface();
const char * g_pBodyTag[10] = {
    "Body0=","Body1=","Body2=","Body3=","Body4=","Body5=","Body6=","Body7=","Body8=","Body9"
};

extern ILocalogInterface * g_GetlogInterface() ;
extern ILocalCfginterface * g_GetlcfgInterface();

struct  tag_Client {
    int  fd ;
    struct sockaddr_in addr ;
    char * pBuffer;
    unsigned int    buff_len ;
    unsigned int    recv_len ;
    DWORD  pw  ;
    tag_Client() {
        memset(this,0,sizeof(tag_Client));
        pBuffer = new char[1024];
        buff_len = 1024 ;
        fd = -1;
    }
    void  assign(int len) {
        delete []pBuffer ;
        pBuffer = new char[len];
        buff_len = len;
    }
    ~tag_Client() {
        if(pBuffer) {
            delete []pBuffer;
            pBuffer = NULL ;
        }
    }
};

/**
 *  VRV 两个包的结构提容易引起歧义
 *  综合两种包， 重新定义包头的为下个结构体, 即为PktHead。
 *  定义都沿用以前的。
 */
#define VRV_VER  0x56525610
struct tag_VRVPktHeader {
    ///VRV1.0=0x56525610
    DWORD m_Flag;
    ///类型，是上报注册信息，变化，还是错误信息
    WORD  m_Type;
    ///信息内容
    WORD  m_What;
    ///
    DWORD m_Pwd;
    ///CRC 校验，TCP协议没有必要计算这个,TCP协议可以保证数据的完整性，暂时先照以前做。
    DWORD PktCrc;
    ///包括包头的数据报的长度
    DWORD PktLen;
    char  data[0] ;
};


int code_convert(const char *from_charset,const char *to_charset,
                 char *inbuf,int inlen,
                 char *outbuf,int & outlen) {
    ///LINUX服务器，不用转码
    if(!g_GetlcfgInterface()->is_WinSrv()) {
        outlen = inlen;
        strcpy(outbuf,inbuf);
        return 1;
    }

    iconv_t cd;
    char **pin = &inbuf;
    char **pout = &outbuf;
    size_t t_outlen = outlen ;
    size_t t_inlen = inlen ;
    cd = iconv_open(to_charset,from_charset);
    if (cd==0) {
        std::cout << " iconv open failed " << std::endl;
        return 0;
    }
    memset(outbuf,0,outlen);

    if ((int)iconv(cd,pin,(size_t *)&t_inlen,pout,(size_t *)&t_outlen)== -1) {
        std::cout << " iconv code_convert failed error : " << errno << ":"<< strerror(errno) << std::endl;
    	iconv_close(cd);
        return 0;
    }
    outlen = t_outlen ;
    iconv_close(cd);
    strncpy(outbuf,inbuf,outlen);
    return 1;
}


void   *   plisten_worker(void * pdata) {
    CVRVNetProtocol * pVrv = (CVRVNetProtocol *)pdata ;
    return pVrv->listen_worker();
}

struct tag_RShelper {
    int skt ;
    CVRVNetProtocol * pVrv ;
};


CVRVNetProtocol::CVRVNetProtocol() {
    m_pEngine = NULL ;
    m_listSkt = INVALID_SOCKET ;
    m_plocker =  new YCommonTool::CLocker;
    m_lstenTrdid = 0 ;
    m_plogBuffer[0] = '\0';
    m_plogBufferDest[0]= '\0';
    m_nlistPort = 0 ;
}

CVRVNetProtocol::~CVRVNetProtocol() {
    close();
}

void   CVRVNetProtocol::close() {
    if(m_listSkt != INVALID_SOCKET) {
        ::close(m_listSkt);
        m_listSkt = INVALID_SOCKET ;
        if(m_lstenTrdid) {
            void * status = NULL ;
            pthread_join(m_lstenTrdid,&status);
            m_lstenTrdid = 0 ;
        }
    }
}

bool   CVRVNetProtocol::create(INetEngineinterface * pEngine) {
    m_pEngine = pEngine  ;
    ///获取监听端口
    std::string  key = CLI_LISTEN_PORT ;
    std::string  strpport = pEngine->get_Param(key);

    char sz[100] = "";

    int nport = atoi(strpport.c_str());
    if(m_listSkt==INVALID_SOCKET) {
        m_listSkt = socket(AF_INET,SOCK_STREAM,0);
        if(m_listSkt == INVALID_SOCKET) {
            return false ;
        }
    band_again:
        struct sockaddr_in  addr ;
        addr.sin_family = AF_INET ;
        addr.sin_port = htons(nport);
        addr.sin_addr.s_addr = INADDR_ANY ;
        memset(addr.sin_zero,0,sizeof(addr.sin_zero));

        if(bind(m_listSkt,(struct sockaddr *)&addr,sizeof(struct sockaddr)) == -1) {
            sprintf(sz,"bind failed prot = %d",nport);
            g_GetlogInterface()->log_error(sz);
            if(nport >= 22205) {
                return false ;
            }
            nport++ ;
            goto band_again ;
        }
        m_nlistPort = nport ;

        if(listen(m_listSkt,10) == -1) {
            return false ;
        }
        fcntl(m_listSkt, F_SETFD, fcntl(m_listSkt, F_GETFD) | FD_CLOEXEC);
        int ret = pthread_create(&m_lstenTrdid,NULL,plisten_worker,this);
        if(ret!=0) {
            return false ;
        }
    }
    return true ;
}

int       CVRVNetProtocol::getRworkercount() {
    CLockHelper helper((CLocker *)m_plocker);
    return m_workeridArray.size();
}

void  *   CVRVNetProtocol::listen_worker() {
#define MAXBUF 2048
#define MAXCLI 100
    int i,n,maxi = -1;
    int nready;
    int sockfd,maxfd=-1,connectfd;

    struct timeval tv;
    struct sockaddr_in addr;
    socklen_t len;
    fd_set rset,allset;
    tag_Client client[MAXCLI];

    FD_ZERO(&allset);
    FD_SET(m_listSkt, &allset);
    maxfd = m_listSkt;
    unsigned int    header_len = sizeof(tag_VRVPktHeader);
    while(true) {
        rset = allset;
        tv.tv_sec = 0;
        tv.tv_usec = 100000;

        nready = select(maxfd + 1, &rset, NULL, NULL, &tv);
        ///超时
        if(nready == 0)
            continue;
        else if(nready < 0) {///错误
            break;
        } else {
            if(FD_ISSET(m_listSkt,&rset)) {
                len = sizeof(struct sockaddr);
                if((connectfd = accept(m_listSkt,(struct sockaddr*)&addr,&len)) == -1) {
                    continue;
                }
                if(!m_pEngine->get_Sink()->onAccept(connectfd,&addr)) {
                    ::close(connectfd);
                    usleep(100000);
                    continue ;
                }
                for(i=0;i<MAXCLI;i++) {
                    if(client[i].fd < 0) {
                        client[i].fd = connectfd;
                        client[i].addr = addr;
                        break;
                    }
                }
                if(i == MAXCLI) {
                    ::close(connectfd);
                } else {
                    FD_SET(connectfd,&allset);
                    if(connectfd > maxfd)
                        maxfd = connectfd;
                    if(i > maxi)
                        maxi = i;
                }
            } else {
                for(i=0;i<=maxi;i++) {
                    if((sockfd = client[i].fd)<0)
                        continue;

                    if(FD_ISSET(sockfd,&rset)) {
                        n  =  recv(sockfd,client[i].pBuffer + client[i].recv_len,client[i].buff_len - client[i].recv_len,0);
                        if(n > 0) {
                            client[i].recv_len += n ;
                            tag_VRVPktHeader * pHeader = (tag_VRVPktHeader *)client[i].pBuffer ;
                            if(client[i].recv_len >= header_len) {
                                if(pHeader->PktLen > client[i].buff_len) {
                                    client[i].assign(pHeader->PktLen + 1);
                                } else {
                                    int tmp_len = 0 ;
                                    while(client[i].recv_len >= pHeader->PktLen) {
                                        if(!msg_worker(sockfd,pHeader->m_Flag,pHeader->m_Type
                                                       ,pHeader->m_What,client[i].pw,pHeader->data,pHeader->PktLen-header_len)) {
                                            break ;
                                        }
                                        client[i].recv_len -= pHeader->PktLen ;
                                        tmp_len += pHeader->PktLen ;
                                    }
                                    ///转移数据
                                    if(tmp_len) {
                                        memcpy(client[i].pBuffer,client[i].pBuffer + tmp_len,client[i].recv_len);
                                    }
                                }
                            }
                        } else {
                            g_GetlogInterface()->log_trace("链接关闭 Lisenworker");
                            close_socket(sockfd, __LINE__);
                            FD_CLR(sockfd,&allset);
                            client[i].fd = -1;
                        }
                    }
                }
            }
        }
    }
    if(m_listSkt) {
        ::close(m_listSkt);
        m_listSkt = 0 ;
    }
    return 0 ;
}

int       CVRVNetProtocol::getSO_ERROR(int fd) {
    int err = 1;
    socklen_t len = sizeof err;
    if (-1 == getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &len))
        g_GetlogInterface()->log_trace("error when get socket error\n");
    if (err)
        errno = err;              // set errno to the socket SO_ERROR
    return err;
}

void CVRVNetProtocol::closeSocket(int fd) {
    if (fd >= 0) {
        // first clear any errors, which can cause close to fail
        getSO_ERROR(fd);
        // secondly, terminate the 'reliable' delivery
        if (shutdown(fd, SHUT_RDWR) < 0) {
            // SGI causes EINVAL
            if (errno != ENOTCONN && errno != EINVAL) {
                g_GetlogInterface()->log_trace("close socket error when shutdown\n");
            }
        }
        if (::close(fd) < 0) {
            g_GetlogInterface()->log_trace("inner close socket error\n");
        }
    }
}

void    CVRVNetProtocol::close_socket(SOCKET skt, int line) {
    if(line != -1) {
        char buf[128] = {0};
        sprintf(buf, "%s: %d\n", "close socket at line: ", line);
        g_GetlogInterface()->log_trace(buf);
    }
    closeSocket(skt);
}

bool      CVRVNetProtocol::conn_serv(SOCKET skt, const std::string &server_ip) {
    ///连接
    ///获取服务器地址，也可以只获取一次，保存下来。
    bool ret = false;
    std::string  addr_key = SRV_ADDRESS ;
    std::string  port_key = SRV_LISTEN_PORT ;
    std::string  str_addr = "";
    if(server_ip.empty()) {
        str_addr = m_pEngine->get_Sink()->get_Param(addr_key);
    } else {
        str_addr = server_ip;
    }
    std::string  str_port = m_pEngine->get_Sink()->get_Param(port_key);

    struct hostent * he = NULL;
    he = gethostbyname(str_addr.c_str());
    if(he == NULL) {
        LOG_ERR("Can't get hostent value connect return");
        return ret;
    }

    struct sockaddr_in their_addr;
    their_addr.sin_family = AF_INET;
    their_addr.sin_port = htons(atoi(str_port.c_str()));
    their_addr.sin_addr = *((struct in_addr *)he->h_addr);
    memset(&(their_addr.sin_zero), '\0', 8);

#ifndef __APPLE__
    ///绑定网卡
    std::string nic ;
    g_GetlcfgInterface()->get_lconfig(lcfg_regnic,nic);
    if(nic.length()) {
        struct ifreq ifr;
        memset(&ifr, 0x00, sizeof(ifr));
        int len = (nic.length() > IFNAMSIZ ? IFNAMSIZ : nic.length());
        strncpy(ifr.ifr_name, nic.c_str(), len);
        if(setsockopt(skt, SOL_SOCKET, SO_BINDTODEVICE, (char *)&ifr, sizeof(ifr)) != 0) {
            g_GetlogInterface()->log_error("CVRVNetProtocol::conn_serv(SOCKET skt) 绑定注册网卡失败");
        }
    }
#endif


    int flags = 0;
    int connect_timeout = 2;
    int error = -1;
    int len = sizeof(socklen_t);
    fcntl(skt, F_GETFL, &flags);
    flags |= O_NONBLOCK;
    fcntl(skt, F_SETFL, flags);

    timeval tm;
    memset(&tm, 0, sizeof(tm));
    fd_set conn_set;
    if (connect(skt, (struct sockaddr *)&their_addr, sizeof(struct sockaddr)) == -1) {
        tm.tv_sec = connect_timeout;
        tm.tv_usec = 0;
        FD_ZERO(&conn_set);
        FD_SET(skt, &conn_set);
        if(select(skt + 1, NULL, &conn_set, NULL, &tm) > 0) {
            getsockopt(skt, SOL_SOCKET, SO_ERROR, &error, (socklen_t *)&len);
            if(error == 0){
                ret = true;
            } else {
                ret = false;
            }
        } else {
            ret = false;
        }
    } else {
        ret = true;
    }
    fcntl(skt, F_GETFL, &flags);
    flags &= (~O_NONBLOCK);
    fcntl(skt, F_SETFL, flags);

    if(ret == false) {
        m_pEngine->get_Sink()->onConnect(-1);
    } else {
        m_pEngine->get_Sink()->onConnect(0) ;
    }
    return ret;
}

/**
 *	@skt 已经链接上的套接子
 *	@vt  软件资产的数组
 *	@what 更新类型
 *	@pFront 标识前缀
 */
#define SOFT_MAX 1500
bool  CVRVNetProtocol::report_soft_asset(SOCKET skt,unsigned int pwd , std::vector<tag_SoftInstallEx> & _vt, unsigned short what ,const char * pFront) {
    if(_vt.size() == 0) {
        return true ;
    }


    std::string strmac,strip,strid;
    g_GetlcfgInterface()->get_lconfig(lcfg_regip,strip);
    g_GetlcfgInterface()->get_lconfig(lcfg_regmac,strmac);
    g_GetlcfgInterface()->get_lconfig(lcfg_devid,strid);
    ///当前登录用户
    std::string user ;
    YCommonTool::get_loginUser(user);

    VRVPacketEx pktEx;
    int     index = 0 ;
    int     data_len = 0 ;
    int     max = SOFT_MAX ;
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
                g_GetlogInterface()->log_error("转化失败，　跳出");
                return false ;
            }
            printf("循环中到最大值发送，　最大值　＝　%d　send_len = %d\n",max,send_len);
            send_len = strlen(m_plogBufferDest);
            if(!pktEx.SendPktEx(skt,AGENT_RPT_SOFTWARE,what,pwd,0,ENC_VERSION1,(BYTE*)m_plogBufferDest,send_len)) {
                char log[32]="";
                sprintf(log,"发送失败:what =  %d\n",what);
                g_GetlogInterface()->log_error(log);
                return false ;
            }
            if(!pktEx.RecvPktEx(skt, pwd)) {
                return false ;
            }
            if(pktEx.head.m_Flag != VRV_FLAG) {
                g_GetlogInterface()->log_error("接受ＦＬＡＧ失败");
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

//上报硬件信息
bool      CVRVNetProtocol::report_hard_asset(SOCKET skt ,unsigned int pwd ,
                                             tag_S_Hard_Asset * pAsset) {
    CDeviceInfoMap *  pAdd = (CDeviceInfoMap *)pAsset->pAdd;
    CDeviceInfoMap *  pDel = (CDeviceInfoMap *)pAsset->pDel;
    CDeviceInfoMap *  pModify = (CDeviceInfoMap *)pAsset->pModify;
    CDeviceInfoMap *  pOld = (CDeviceInfoMap *)pAsset->pOld;
    CDeviceInfoMap *  pMap = (CDeviceInfoMap *)pAsset->pMap ;
    std::string    *  pStr = (std::string    *)pAsset->pFrontstr;

    std::string strmac,strip,strid;
    g_GetlcfgInterface()->get_lconfig(lcfg_regip,strip);
    g_GetlcfgInterface()->get_lconfig(lcfg_regmac,strmac);
    g_GetlcfgInterface()->get_lconfig(lcfg_devid,strid);

    ///当前登录用户
    std::string user ;
    YCommonTool::get_loginUser(user);
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
            printf("pold = %lu , modify: %s\n",pOld->size(),iter->second.c_str());
            CDeviceInfoMap::iterator iterold = pOld->find(iter->first);
            if(iterold != pOld->end()) {
                sprintf(num_buf,"%lu",pDel->size() + index);
                tmp = tmp + "DEL_DEVICE_"+num_buf+"_DESC="+g_asset_desc[iter->first]+STRITEM_TAG_END;
                tmp = tmp + "DEL_DEVICE_"+num_buf+"="+iterold->second+STRITEM_TAG_END;
                sprintf(num_buf,"%lu",pAdd->size() + index);
                tmp = tmp + "NEW_DEVICE_"+num_buf+"_DESC="+g_asset_desc[iter->first]+STRITEM_TAG_END;
                tmp = tmp + "NEW_DEVICE_"+num_buf+"="+iter->second+STRITEM_TAG_END;
            }
            index++;
            iter++ ;
        }
    }

    printf("add = %lu ,modify = %lu, del = %lu\n",pAdd->size(),pModify->size(),pDel->size());

    sprintf(m_plogBuffer+strlen(m_plogBuffer),"%s%sListCount=%lu%sNewCount=%lu%sDelCount=%lu%s",pStr->c_str(),tmp.c_str(),
            pMap->size(),STRITEM_TAG_END,pAdd->size()+pModify->size(),STRITEM_TAG_END,pDel->size()+pModify->size(),STRITEM_TAG_END);
    int  data_len = strlen(m_plogBuffer);
    int  send_len = (data_len)*2 + 1 ;

    printf("->>>->>> = %s\n",m_plogBuffer);

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
/**
 * 在这里把数据翻译成 VRVPacket
 */
bool      CVRVNetProtocol::sendData(enNetSmsg msg , void * pData , int len) {

    /*TODO: server block*/
    SOCKET skt = socket(AF_INET,SOCK_STREAM,0);

    if(skt == -1) {
        LOG_ERR("socket not avaliable");
        return false;
    }
    bool connect_ret = false;
    if(msg == S_CMD_DETECT_SERVER && pData != NULL && len > 0) {
        std::string *server_ip = static_cast<std::string *>(pData);
        if(server_ip != NULL) {
            connect_ret = conn_serv(skt, *server_ip);
        }
    } else {
        connect_ret = conn_serv(skt);
    }
    if(!connect_ret) {
        m_pEngine->get_Sink()->onClose(skt,false);
        g_GetlogInterface()->log_trace("connect server error and close socket\n");
        closeSocket(skt);
        return false ;
    }

    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    if(setsockopt(skt, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
        g_GetlogInterface()->log_trace("set socket recive timeout error");
    }
    if(setsockopt(skt, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
        g_GetlogInterface()->log_trace("set socket send timeout error");
    }
    ///获取加密密钥
    unsigned int  pwd ;
    if(!get_pwd(skt,pwd)) {
        g_GetlogInterface()->log_trace("get pwd error and close socket\n");
        closeSocket(skt);
        return false ;
    }

    ///发送,如果需要接收消息的命令，在这里接收消息，，不用接收回复消息的命令直接RETURN
    switch(msg) {
    case S_CMD_UPLOAD_LOG_NOW :
    case S_CMD_UPLOAD_LOG_NOWEX:{
        T_localog * plog = (T_localog *)pData ;
        VRVPacket packet;
        VRVPacketEx packetEx;

        std::string strmac,strip,strid;
        g_GetlcfgInterface()->get_lconfig(lcfg_regip,strip);
        g_GetlcfgInterface()->get_lconfig(lcfg_regmac,strmac);
        g_GetlcfgInterface()->get_lconfig(lcfg_devid,strid);
        ///当前tty1登录用户
        std::string user ;
        YCommonTool::get_loginUser(user);

        ///获取日志头
        size_t  npos = get_logHeader(m_plogBuffer,
                                     strip,strmac,strid,user);
        std::string logheader(m_plogBuffer);

        char * pTmp = m_plogBuffer + npos ;
        if(msg !=S_CMD_UPLOAD_LOG_NOWEX) {
            if(strncmp(plog->pContent,"Body0=",6) != 0) {
                sprintf(pTmp,"%s%s%sBodyCount=1%s",g_pBodyTag[0],plog->pContent,STRITEM_TAG_END,STRITEM_TAG_END);
            } else {
                sprintf(pTmp,"%s",plog->pContent);
            }
        }
        else
            sprintf(pTmp,"%s%s",plog->pContent,STRITEM_TAG_END);

        npos += strlen(pTmp);
        ///进行转换UTF8-GB2312
        int dstlen = npos * 2+1;
        if(!code_convert("utf-8","gb2312",m_plogBuffer,npos,m_plogBufferDest,dstlen)) {
            break ;
        }
        dstlen = strlen(m_plogBufferDest);
        ///发送
        if(plog->type < 88) {

            if(!packet.SendPkt(skt,plog->type,plog->what,pwd,0,
                               (BYTE *)m_plogBufferDest,dstlen)) {
                close_socket(skt, __LINE__);
                return false ;
            }

            if(!packet.RecvPkt(skt,pwd)) {
                close_socket(skt, __LINE__);
                return false ;
            }

            if(packet.head.m_Flag  != VRV_FLAG) {
                close_socket(skt, __LINE__);
                return false ;
            }

        } else {
            if(!packetEx.SendPktEx(skt,plog->type,plog->what, pwd, 0,
                                   ENC_VERSION1, (BYTE *)m_plogBufferDest,dstlen)) {
                close_socket(skt, __LINE__);
                return false ;
            }
            packetEx.RecvPktEx(skt, pwd);
            if(packetEx.head.m_Flag != VRV_FLAG) {
                close_socket(skt, __LINE__);
                return false ;
            }
        }
        break ;
    }
    case S_CMD_HARD_ASSET: {
        char  sz[128]="";
        sprintf(sz,"%s", "report hardware assert");
        g_GetlogInterface()->log_trace(sz);

        tag_S_Hard_Asset * pAsset = static_cast<tag_S_Hard_Asset *>(pData) ;
        if(!report_hard_asset(skt,pwd,pAsset)) {
            close_socket(skt, __LINE__);
            return false ;
        }
        break ;
    }
    case S_CMD_SOFT_ASSET : {
        tag_S_Soft_Asset * pAsset = (tag_S_Soft_Asset *)pData ;

        std::vector<tag_SoftInstallEx> * pAdd = (std::vector<tag_SoftInstallEx> *)pAsset->pAdd ;
        std::vector<tag_SoftInstallEx> * pDel = (std::vector<tag_SoftInstallEx> *)pAsset->pDel ;
        std::vector<tag_SoftInstallEx> * pModify = (std::vector<tag_SoftInstallEx> *)pAsset->pModify ;

        char  sz[128]="";
        sprintf(sz,"*********************** add: %lu, del: %lu, modify: %lu\n",pAdd->size(),pDel->size(),pModify->size());
        g_GetlogInterface()->log_trace(sz);

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
        break;
    }
    case S_CMD_GET_POLICY_INFO: {
        tag_S_GetPlockyGEN * pGen = (tag_S_GetPlockyGEN *)pData ;
        std::string * psend = (std::string *)pGen->pSendStr ;
        std::string * pget = (std::string *)pGen->pGetStr ;
        char * pbuffer = const_cast<char *>(psend->c_str()) ;

        VRVPacket pkt;
        if(!pkt.SendPkt(skt,DOWNLOAD_POLICY,GET_POLICY,pwd,0,(BYTE*)pbuffer,psend->length())) {
            close_socket(skt, __LINE__);
            return false ;
        }

        if(!pkt.RecvPkt(skt,pwd)) {
            close_socket(skt, __LINE__);
            return false ;
        }
        *pget =  pkt.m_data ;
        break;
    }
        ///获取策略概况
    case S_CMD_GET_POLICY_GENERAL: {
        tag_S_GetPlockyGEN * pGen = (tag_S_GetPlockyGEN *)pData ;
        std::string * psend = (std::string *)pGen->pSendStr ;
        std::string * pget = (std::string *)pGen->pGetStr ;
        char * pbuffer = const_cast<char *>(psend->c_str()) ;

        VRVPacket pkt;
        if(!pkt.SendPkt(skt,DOWNLOAD_POLICY,DETECT_POLICY,pwd,0,(BYTE*)pbuffer,psend->length())) {
            close_socket(skt, __LINE__);
            return false ;
        }

        if(!pkt.RecvPkt(skt,pwd)) {
            close_socket(skt, __LINE__);
            return false ;
        }

        *pget =  pkt.m_data ;
        break ;
    }
        ///用户注册
    case S_CMD_USER_REGISTER: {
        int dstlen = len * 2+1;
        int t_len = len;
        char * dst = new char[dstlen];
        memset(dst,0,sizeof(dstlen));

        ///可能含有中文，需要转码
        if(!code_convert("utf-8","gb2312",(char *)pData,t_len,dst,dstlen)) {
            g_GetlogInterface()->log_trace("S_CMD_USER_REGISTER utf-8  to gb2312 is error");
            delete []dst ;
            dst = NULL;
            break ;
        }
        dstlen=strlen(dst)+1;

        printf("*****int = %d,out = %d  pwd = %d  \n%s",t_len,dstlen,pwd,dst);

        VRVPacketEx pktEx;
        if(!pktEx.SendPktEx(skt,114,0,pwd,0,0,(BYTE*)dst,dstlen)) {
            delete []dst;
            close_socket(skt, __LINE__);
            return false ;
        }

        delete []dst;
        if(!pktEx.RecvPktEx(skt,pwd))  {
            char log[64]="";
            printf(log,"S_CMD_USER_REGISTER pktEx.RecvPkt recv error = %d",errno);
            g_GetlogInterface()->log_error(log);
            close_socket(skt, __LINE__);
            return false ;
        }

        if(pktEx.head.m_Flag != VRV_FLAG || pktEx.head.m_Type != EX_OK ) {
            printf("%s\n", " flag mismatch--> reg");
            close_socket(skt, __LINE__);
            return false ;
        }
        break;
    }
        ///上报日志
    case S_CMD_UPLOAD_LOG: {
        if(!update_log(skt,pData,pwd)) {
            close_socket(skt, __LINE__);
            return false ;
        }
        break;
    }
    case S_CMD_HEART_BEAT : {
        std::string strmac,strip,strid;
        g_GetlcfgInterface()->get_lconfig(lcfg_regip,strip);
        g_GetlcfgInterface()->get_lconfig(lcfg_regmac,strmac);
        g_GetlcfgInterface()->get_lconfig(lcfg_devid,strid);
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

        break ;
    }
    case S_CMD_CLIENT_UPGRADE : {
        std::string strmac,strip,strid;
        g_GetlcfgInterface()->get_lconfig(lcfg_regip,strip);
        g_GetlcfgInterface()->get_lconfig(lcfg_regmac,strmac);
        g_GetlcfgInterface()->get_lconfig(lcfg_devid,strid);
        char sz[512] = "";
        sprintf(sz,"MACAddress0=%s%s"
                "IPAddress0=%s%s"
                "MACCount=1%s"
                "IPCount=1%s"
                "DeviceIdentify=%s%s"
                "ClientVersion=%s%s"
                ,strmac.c_str(),STRITEM_TAG_END,
                strip.c_str(),STRITEM_TAG_END,STRITEM_TAG_END,STRITEM_TAG_END,
                strid.c_str(),STRITEM_TAG_END,CLIENT_VERSION,STRITEM_TAG_END);

        VRVPacket pkt;
        pkt.SendPkt(skt,VRV_UPGRADE, REQUEST_UPGRAD, pwd,0, (BYTE*)sz,strlen(sz));
        if(!pkt.RecvPkt(skt,pwd))  {
            close_socket(skt, __LINE__);
            return false ;
        }

        if(pkt.head.m_Flag != VRV_FLAG) {
            close_socket(skt, __LINE__);
            return false ;
        }
        printf("-----upgrade------%d----\n",pkt.head.m_What);
        if(ECHO_UPGRAD == pkt.head.m_What)
        {
            if(0 == access("EdpSetup.sh",F_OK))
            {
                g_GetlogInterface()->log_trace("执行升级开始");
                system("./EdpSetup.sh -U &");
                g_GetlogInterface()->log_trace("执行升级结束");
            }
        }
        break ;
    }
    case S_CMD_GET_SERVER_TIME: {
        if(pData == NULL) {
            g_GetlogInterface()->log_trace("pData is NULL when get server_time");
            close_socket(skt, __LINE__);
            return false ;
        }
        std::string strmac,strip,strid;
        g_GetlcfgInterface()->get_lconfig(lcfg_regip,strip);
        g_GetlcfgInterface()->get_lconfig(lcfg_regmac,strmac);
        g_GetlcfgInterface()->get_lconfig(lcfg_devid,strid);
        char sz[512] = "";
        sprintf(sz,"MACAddress0=%s%s"
                "IPAddress0=%s%s"
                "MACCount=1%s"
                "IPCount=1%s"
                "DeviceIdentify=%s%s"
                "ClientVersion=%s%s"
                ,strmac.c_str(),STRITEM_TAG_END,
                strip.c_str(),STRITEM_TAG_END,STRITEM_TAG_END,STRITEM_TAG_END,
                strid.c_str(),STRITEM_TAG_END,CLIENT_VERSION,STRITEM_TAG_END);
        VRVPacket pkt;
        pkt.SendPkt(skt,AGENT_SYNTIME, AGENT_REQUEST, pwd,0, (BYTE*)sz,strlen(sz));
        if(!pkt.RecvPkt(skt,pwd))  {
            close_socket(skt, __LINE__);
            return false ;
        }

        if(pkt.head.m_Flag != VRV_FLAG) {
            close_socket(skt, __LINE__);
            return false ;
        }
        std::string *pout_param = static_cast<std::string *>(pData);
        if(!pout_param) {
            close_socket(skt, __LINE__);
            return false;
        }
        pout_param->clear();
        pout_param->append(pkt.m_data);
        break;
    }
    case S_CMD_DETECT_SERVER: {
        VRVPacket pkt;
        if(!pkt.SendPkt(skt,DETECT_ACTIVE,DETECT_ACTIVE_PROBE, pwd,0, NULL ,0)) {
            close_socket(skt, __LINE__);
            return false ;
        }

#ifdef WINSRV
        /*detect win server just send success*/
        break;
#else
        if(!pkt.RecvPkt(skt,pwd)) {
            close_socket(skt, __LINE__);
            return false ;
        }
        if(pkt.head.m_What != DETECT_ACTIVE_PROBE_RETURN) {
            close_socket(skt, __LINE__);
            return false;
        }
#endif
        break;
    }
    }
    close_socket(skt, __LINE__);
    return true;
}


bool    CVRVNetProtocol::update_log(SOCKET skt,void * pData,int pwd) {
    tag_S_UPLOAD_LOGS * pLogs = (tag_S_UPLOAD_LOGS *)pData ;
    std::vector<T_localog> * pArray = (std::vector<T_localog> *)pLogs->pArray;
    int  * pCurid =pLogs->curid ;
    int  & curid = *pCurid ;
    std::vector<T_localog>::iterator iter = pArray->begin();
    VRVPacket packet;
    VRVPacketEx packetEx;

    std::string strmac,strip,strid;
    g_GetlcfgInterface()->get_lconfig(lcfg_regip,strip);
    g_GetlcfgInterface()->get_lconfig(lcfg_regmac,strmac);
    g_GetlcfgInterface()->get_lconfig(lcfg_devid,strid);
    ///当前tty1登录用户
    std::string user ;
    YCommonTool::get_loginUser(user);
    ///获取日志头
    int  npos = get_logHeader(m_plogBuffer,
                              strip,strmac,strid,user);
    std::string logheader(m_plogBuffer);

    char * pTmp = m_plogBuffer + npos ;
    ///求CRC
    //ULONG crc32 = 0;
    int dest_len = SEND_LOG_BUF_LEN*2+1 ;
    while(iter != pArray->end()) {
        ///是否已经批量格式化过了
        if(iter->type != FIND_DAILUP
           && IPORMAC_CHANGE != iter->type) {
            if(strncmp(iter->pContent,"Body0=",6) != 0) {
                sprintf(pTmp,"%s%s%sBodyCount=1%s",g_pBodyTag[0],iter->pContent,STRITEM_TAG_END,STRITEM_TAG_END);
            } else {
                sprintf(pTmp,"%s",iter->pContent);
            }
        } else {
            sprintf(pTmp,"%s%s",iter->pContent,STRITEM_TAG_END);
        }

        int data_size = npos + strlen(pTmp);
        dest_len = data_size * 2 + 1 ;

        ///进行转换UTF8-GB2312
        if(!code_convert("utf-8","gb2312",m_plogBuffer,data_size,m_plogBufferDest,dest_len)) {
            printf("conv error, %d %d,%lu | %s\n%s\n",errno,data_size,strlen(m_plogBuffer),
                   m_plogBuffer,&(m_plogBuffer[data_size-2]));
            break ;
        }

        //crc32 =	CRC32(crc32,(BYTE *)m_plogBufferDest,dest_len);
        ///发送
        if(iter->type < 88) {
            if(!packet.SendPkt(skt,iter->type,iter->what,pwd,0,
                               (BYTE *)m_plogBufferDest,strlen(m_plogBufferDest))) {
                return false ;
            }
            if(!packet.RecvPkt(skt,pwd)) {
                return false ;
            }
            if(packet.head.m_Flag  != VRV_FLAG) {
                return false ;
            }
        } else {
            if(!packetEx.SendPktEx(skt,iter->type,iter->what, pwd, 0,
                                   ENC_VERSION1, (BYTE *)m_plogBufferDest,strlen(m_plogBufferDest))) {
                return false ;
            }
            packetEx.RecvPktEx(skt, pwd);
            if(packetEx.head.m_Flag != VRV_FLAG) {
                return false ;
            }
        }
        curid++;
        iter++ ;
    }
    return true ;
}


bool     CVRVNetProtocol::msg_worker(int skt,DWORD flag,WORD type ,WORD what ,DWORD & pw , char * pData, int len)
{
    unsigned short  cmd  = 0;
    void *  pBuffer = NULL ;
    int     buf_len = 0 ;
    /*在这里对数据进行转换*/
    if(flag != VRV_FLAG &&
       flag != VRV_FLAG10
       && flag != VRV_FLAG11) {
        return false ;
    }
    ///解密
    if(pw) {
        Decrypt_V1(pw,(LPVOID)pData,(LPVOID)pData,len,0);
    }

    tag_NetRmsg msg ;
    pBuffer = &msg ;
    buf_len = sizeof(msg);
    msg.len = len ;
    msg.pData = pData ;

    switch(type) {
	///探测是否加密
    case DETECT_ENCRYPT: {

        VRVPacket  pkt ;
        int ret = pkt.SendPkt(skt,DETECT_ENCRYPT,0,0x56000001,0,NULL,0);

        if(ret == 0) {
            return false;
        }

        ret = pkt.RecvPkt(skt);
        if(ret == 0) {
            return false ;
        }
        pw = pkt.head.m_Pwd ;
        break;
    }
	///服务端分发策略概况
    case DISTRIBUTE_POLICY: {
        g_GetlogInterface()->log_trace("策略分发");
        cmd = R_CMD_DISTRIBUTE_POLICY ;
        return m_pEngine->get_Sink()->recvnetmsg((enNetRmsg)cmd,pBuffer,buf_len) ;
    }
	///上报客户端进程信息
    case GET_AGENTPROCESS: {
        g_GetlogInterface()->log_trace("上报客户端进程");
        break;
    }
	///通知攻击某各IP
    case SCAN_HACK_IP: {
        FILE * fp = fopen("hack_ip.txt","w");
        if(fp) {
            fputs(pData,fp);
            fclose(fp);
        }
        break;
    }
	///杀死客户端进程
    case KILL_AGENTPROCESS: {
        g_GetlogInterface()->log_trace("杀掉其他进程");
        break ;
    }
	///点对点获取共享目录
    case T_POINT_GET_SHAREPATH: {
        switch(what) {
        case 1 : {

            break;
        }
        case 0 : {

            break;
        }
        }
        break;
    }
	///上报日志
    case 139: {

        break ;
    }
	///上报服务
    case 81: {

        break ;
    }
    case T_WHOCAN_DISCON: {
        printf("由谁来进行阻断\n");
        break ;
    }
	///重启
    case T_REQUEST_SHUTDOWN: {

        break;
    }
	///关闭网络
    case T_REQUEST_DISCON: {
        ///AttackMode ； 4 阻断网络，包含永久阻断， 3 阻断网络，非永久阻断，1 回复网络
        char buffer[2048]="";
        int outlen = 2048 ;
        code_convert("gb2312","utf-8",pData,strlen(pData),buffer,outlen);
        g_GetlogInterface()->log_trace(buffer);

        char Prompt[256] = "";
        getVal_fromTarget(Prompt,"PromptInfo",buffer,255);
        char mode[10]="";
        getVal_fromTarget(mode,"AttackMode",buffer,9);

        switch(atoi(mode)) {
        case 1: {///恢复网络
            tag_openNet open ;
            open.policy = en_policytype_count;
            g_GetlogInterface()->log_trace("T_REQUEST_DISCON 服务器，恢复网络");
            g_GetSendInterface()->sendto_Main(VCF_CMD_OPEN_NET, &open,sizeof(tag_openNet));
            break ;
        }
        case 3: {///阻断网络
            tag_closeNet  tmp ;
            tmp.policy = en_policytype_count;
            g_GetlogInterface()->log_trace("T_REQUEST_DISCON 服务器，阻断网络");
            g_GetSendInterface()->sendto_Main(VCF_CMD_CALL_CLOSENET, &tmp,sizeof(tag_closeNet));
            break;
        }
        case 4: {///永久阻断
            tag_closeNet  tmp ;
            tmp.policy = en_policytype_count;
            tmp.bAlaways = true ;
            g_GetlogInterface()->log_trace("T_REQUEST_DISCON 服务器，永久阻断");
            g_GetSendInterface()->sendto_Main(VCF_CMD_CALL_CLOSENET, &tmp,sizeof(tag_closeNet));
            break ;
        }
        }
        ///提示信息
        if(strlen(Prompt)) {
            char buffer[512] = "";
            tag_GuiTips * pTips = (tag_GuiTips *)buffer;
            pTips->sign = en_TipsGUI_btnOK | en_TipsGUI_timeOut;
            pTips->defaultret = en_TipsGUI_None ;
            pTips->pfunc = NULL;
            pTips->param.timeout = 1000;//以毫秒为单位
            sprintf(pTips->szTitle,"提示");
            sprintf(pTips->szTips,"%s",Prompt);
            g_GetlogInterface()->log_trace(pTips->szTips);
            g_GetSendInterface()->sendto_Imc(VCF_CMD_GUI_TIPS, buffer, sizeof(tag_GuiTips));
        }
        break;
    }
	///点对点消息
    case  T_POINT_MESSAGE: {
        g_GetlogInterface()->log_trace(pData);
        break;
    }
	///unknown
    case 140: {

        break;
    }
    }

    return m_pEngine->get_Sink()->recvnetmsg((enNetRmsg)cmd,pBuffer,buf_len) ;
}
