/*
 * online_deal_ctrl.cpp
 *
 *  Created on: 2015-2-4
 *      Author: sharp
 */
#include "online_deal_ctrl.h"
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <stdio.h>
#include <fcntl.h>
#include "../../common/ping.h"
#include "../../vrvprotocol/VRVProtocol.hxx"
#include "../../../include/MCInterface.h"
#include "../../VCFCmdDefine.h"
extern int code_convert(const char *from_charset,const char *to_charset,char *inbuf,int inlen,char *outbuf,int & outlen);
extern ILocalogInterface * g_GetlogInterface() ;

static int    g_max_timer_cnt = 0 ;
static int    g_timer_cnt = 0 ;
static unsigned int    g_oldcrc = 0 ;
static int    g_bcloseNet = false ;
std::string   g_closeNetPromptFile = "closeNetPromptFile";
char    g_lastofflineTime[32] = "";

extern ILocalCfginterface * g_GetlcfgInterface();

static void    online_deal_ctrl(CPolicyOnlinedealctrl * pPolicy);

bool    CPolicyOnlinedealctrl::import_xml(const char * pxml) {
    if(pxml == NULL) {
	return false ;
    }

    CMarkup  xml ;
    if(!xml.SetDoc(pxml)) {
	return false ;
    }
    std::string tmp ;
    if(xml.FindElem("vrvscript")) {
	xml.IntoElem();
	while(xml.FindElem("item")) {
	    tmp = xml.GetAttrib("AllowClientDetect");
	    if(tmp.length()) {
		m_allowDetect = atoi(tmp.c_str());
		xml_item1(xml);
	    } else {
		tmp = xml.GetAttrib("DisobeyMode0");
		if(tmp.length()) {
		    xml_item2(xml);
		} else {
		    xml_item3(xml);
		}
	    }
	}
	xml.OutOfElem();
    }
    ///GB2312 - UTF8
    return CPolicy::import_xmlobj(xml) ;
}

void     CPolicyOnlinedealctrl::xml_item1(CMarkup & xml) {
    m_UseDetectWan = atoi(xml.GetAttrib("UseDetectWAN").c_str());
    std::string tmp ;
    m_Wanip1 = xml.GetAttrib("WANIP1");
    m_Wanip2 = xml.GetAttrib("WANIP2");
    m_Wanipchar1 = xml.GetAttrib("WANIP1Char");
    m_Wanipchar2 = xml.GetAttrib("WANIP2Char");
    tmp = xml.GetAttrib("AccessIPRange");

    if(tmp.length()) {
	int pos  = tmp.find("-");
	if(pos !=(int) std::string::npos) {
	    m_IPStart = tmp.substr(0,pos);
	}
	const char * pStr = tmp.c_str();
	m_IPEnd = pStr+pos+1;
    }
    m_DetectInterVal = atoi(xml.GetAttrib("DetectIntervalTime").c_str());

    char szlog[256]="";
    sprintf(szlog,"ip1:%s ,ip2: %s, ipstart: %s, ipend: %s  %d\n",m_Wanip1.c_str(),m_Wanip2.c_str(),m_IPStart.c_str(),m_IPEnd.c_str(),m_DetectInterVal);
    g_GetlogInterface()->log_warning(szlog);

    m_detectNum = atoi(xml.GetAttrib("DetectDataDeviceNum").c_str());
    m_disEnableProxy = atoi(xml.GetAttrib("DisableProxy").c_str());
    m_disEnableProxyConn = atoi(xml.GetAttrib("DisConnProxyIP").c_str());
    m_RebootPrompt = xml.GetAttrib("PersistAttackPrompt");
    m_EnableSpecCode = atoi(xml.GetAttrib("OnlyAllowSpecCode").c_str());
    m_EnableSpecNumber = xml.GetAttrib("AllowDialCode").c_str();
    m_Detectproxy = atoi(xml.GetAttrib("DeepInspectionAgent").c_str());
    m_DetectUdp = atoi(xml.GetAttrib("DeepInspectionUD").c_str());
    m_IsSavepacket = atoi(xml.GetAttrib("IsSaveOnlinePacket").c_str());
}
void     CPolicyOnlinedealctrl::xml_item2(CMarkup & xml) {
    m_lanAndwan.mode = atoi(xml.GetAttrib("DealMode0").c_str());
    m_lanAndwan.Prompt = xml.GetAttrib("PromptInfo01");
    m_lanAndwan.Prompt2 = xml.GetAttrib("PromptInfo02");
    m_lanAndwan.Prompt4 = xml.GetAttrib("PromptInfo04");
    m_lanAndwan.Prompt8 = xml.GetAttrib("PromptInfo08");
    m_lanAndwan.convert();
    m_lanAndwan.shutDownTime = atoi(xml.GetAttrib("OnlineShutdownTime0").c_str()) * 1000;

}
void     CPolicyOnlinedealctrl::xml_item3(CMarkup & xml) {
    m_onlyWan.mode = atoi(xml.GetAttrib("DealMode1").c_str());
    m_onlyWan.Prompt = xml.GetAttrib("PromptInfo11");
    m_onlyWan.Prompt2 = xml.GetAttrib("PromptInfo12");
    m_onlyWan.Prompt4 = xml.GetAttrib("PromptInfo14");
    m_onlyWan.Prompt8 = xml.GetAttrib("PromptInfo18");
    m_onlyWan.Prompt16 = xml.GetAttrib("PromptInfo116");
    m_onlyWan.convert();
    m_onlyWan.shutDownTime = atoi(xml.GetAttrib("OnlineShutdownTime1").c_str()) * 1000;
}
static int  get_maxlength(std::string & str, int max) {
    return  (str.length() >(unsigned int) max ? (unsigned int)max : str.length());
}
void    CPolicyOnlinedealctrl::tag_Item::convert() {
    char  szBuffer[513] = "";
    char  szout[1024] = "";
    int oulen = 1024 ;
    if(Prompt.length()) {
	oulen = 1024 ;
	strncpy(szBuffer,Prompt.c_str(),get_maxlength(Prompt,512));
	code_convert("gb2312","utf-8",szBuffer,Prompt.length(),szout,oulen);
	Prompt = szout ;
	memset(szBuffer,0,sizeof(szBuffer));
    }

    if(Prompt2.length()) {
	oulen = 1024 ;
	strncpy(szBuffer,Prompt2.c_str(),get_maxlength(Prompt2,512));
	code_convert("gb2312","utf-8",szBuffer,Prompt2.length(),szout,oulen);
	Prompt2 = szout ;
	memset(szBuffer,0,sizeof(szBuffer));
    }

    if(Prompt4.length()) {
	oulen = 1024 ;
	strncpy(szBuffer,Prompt4.c_str(),get_maxlength(Prompt4,512));
	code_convert("gb2312","utf-8",szBuffer,Prompt4.length(),szout,oulen);
	Prompt4 = szout ;
	memset(szBuffer,0,sizeof(szBuffer));
    }

    if(Prompt8.length()) {
	oulen = 1024 ;
	strncpy(szBuffer,Prompt8.c_str(),get_maxlength(Prompt8,512));
	code_convert("gb2312","utf-8",szBuffer,Prompt8.length(),szout,oulen);
	Prompt8 = szout ;
	memset(szBuffer,0,sizeof(szBuffer));
    }

    if(Prompt16.length()) {
	oulen = 1024 ;
	strncpy(szBuffer,Prompt16.c_str(),get_maxlength(Prompt16,512));
	code_convert("gb2312","utf-8",szBuffer,Prompt16.length(),szout,oulen);
	Prompt16 = szout ;
	memset(szBuffer,0,sizeof(szBuffer));
    }
}

void    CPolicyOnlinedealctrl::copy_to(CPolicy * pDest) {
    if(pDest->get_type() != ONLINE_DEAL_CTRL)
	return ;
    CPolicyOnlinedealctrl * pCtrl = (CPolicyOnlinedealctrl *)pDest ;
    pCtrl->m_allowDetect = m_allowDetect ;
    pCtrl->m_UseDetectWan = m_UseDetectWan ;
    pCtrl->m_DetectInterVal = m_DetectInterVal ;
    pCtrl->m_Wanip1 = m_Wanip1 ;
    pCtrl->m_Wanip2 = m_Wanip2 ;
    pCtrl->m_Wanipchar1 = m_Wanipchar1 ;
    pCtrl->m_Wanipchar2 = m_Wanipchar2 ;
    pCtrl->m_IPStart = m_IPStart ;
    pCtrl->m_IPEnd = m_IPEnd ;
    pCtrl->m_disEnableProxy = m_disEnableProxy ;
    pCtrl->m_disEnableProxyConn = m_disEnableProxyConn ;
    pCtrl->m_RebootPrompt = m_RebootPrompt ;
    pCtrl->m_EnableSpecCode = m_EnableSpecCode ;
    pCtrl->m_EnableSpecNumber = m_EnableSpecNumber ;
    pCtrl->m_Detectproxy = m_Detectproxy ;
    pCtrl->m_DetectUdp = m_DetectUdp ;
    pCtrl->m_IsSavepacket = m_IsSavepacket ;
    pCtrl->m_lanAndwan = m_lanAndwan ;
    pCtrl->m_onlyWan = m_onlyWan ;
    pCtrl->m_detectNum = m_detectNum ;

    CPolicy::copy_to(pDest);
}

bool  online_deal_ctrl_init() {
    YCommonTool::get_local_time(g_lastofflineTime);
    g_bcloseNet = false ;
    return true ;
}

bool  online_deal_ctrl_worker(CPolicy * pPolicy, void * pParam) {
    if(pPolicy->get_type() != ONLINE_DEAL_CTRL) {
	return true ;
    }

    CPolicyOnlinedealctrl * pCtrl = (CPolicyOnlinedealctrl *)pPolicy ;
    if(g_oldcrc == 0) {
	online_deal_ctrl(pCtrl);
	g_oldcrc = pPolicy->get_crc() ;
	///重新计算间隔
	if(pCtrl->get_DetectInterVal() * 1000 < ONLINE_DEAL_CTRL_INTERVAL ) {
	    g_max_timer_cnt = 1 ;
	} else {
	    g_max_timer_cnt = (pCtrl->get_DetectInterVal()*1000) / ONLINE_DEAL_CTRL_INTERVAL ;
	}
	printf("%d %d g_max_timer_cnt == %d\n",(pCtrl->get_DetectInterVal()*1000),ONLINE_DEAL_CTRL_INTERVAL,g_max_timer_cnt);
	g_timer_cnt = 0 ;
	return true ;
    } else if(g_oldcrc != pPolicy->get_crc()) {
	g_oldcrc = pPolicy->get_crc() ;
	///重新计算间隔
	if(pCtrl->get_DetectInterVal() * 1000 < ONLINE_DEAL_CTRL_INTERVAL ) {
	    g_max_timer_cnt = 1 ;
	} else {
	    g_max_timer_cnt = (pCtrl->get_DetectInterVal() * 1000) / ONLINE_DEAL_CTRL_INTERVAL ;
	}

	g_timer_cnt = 0 ;
    }
    g_timer_cnt++ ;
    printf("g_timer_cnt = %d ,g_max_timer_cnt == %d\n",g_timer_cnt,g_max_timer_cnt);
    if(g_timer_cnt >= g_max_timer_cnt) {
	online_deal_ctrl(pCtrl);
	g_timer_cnt = 0 ;
    }
    return true ;
}

extern void  online_deal_ctrl_uninit() {
    if(g_bcloseNet) {
	///开启网络
	tag_openNet open ;
	open.policy =ONLINE_DEAL_CTRL ;
	g_GetSendInterface()->sendto_Main(VCF_CMD_OPEN_NET,&open,sizeof(open));
	g_bcloseNet = false ;
    }
    return  ;
}

static  int  get_host_ip(const char * pHost , std::vector<std::string> & ipvt) {
    ipvt.clear();
    struct addrinfo *answer, hint, *curr;
    char ipstr[32] = "";
    bzero(&hint, sizeof(hint));
    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_STREAM;
    char log[32] = "";

    int ret = getaddrinfo(pHost, NULL, &hint, &answer);
    if (ret != 0) {
	sprintf(log,"域名解析失败%s %d\n",pHost,errno);
	g_GetlogInterface()->log_trace(log);
	return -1;
    }

    for (curr = answer; curr != NULL; curr = curr->ai_next) {
	sprintf(ipstr,"%s",inet_ntoa(((struct sockaddr_in *)(curr->ai_addr))->sin_addr)) ;
	g_GetlogInterface()->log_trace(ipstr);
	ipvt.push_back(ipstr);
    }
    freeaddrinfo(answer);
    return ipvt.size();
}

/*must be valid socket fd*/
static bool _timeout_connect(int socket_fd, struct sockaddr_in &sock_addr, int time) {
    bool ret = false;
    int flags = 0;
    int error = -1;
    int len = sizeof(socklen_t);
    flags = fcntl(socket_fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(socket_fd, F_SETFL, flags);

    timeval tm;
    memset(&tm, 0, sizeof(tm));
    fd_set conn_set;
    if(connect(socket_fd, (struct sockaddr *)&sock_addr, sizeof(struct sockaddr)) == -1) {
        tm.tv_sec = time;
        tm.tv_usec = 0;
        FD_ZERO(&conn_set);
        FD_SET(socket_fd, &conn_set);
        if(select(socket_fd + 1, NULL, &conn_set, NULL, &tm) > 0) {
            getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, &error, (socklen_t *)&len);
            if(error == 0) {
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
    fcntl(socket_fd, F_GETFL, &flags);
    flags &= (~O_NONBLOCK);
    fcntl(socket_fd, F_SETFL, flags);
    return ret;
}


///链接服务器，成功返回true
static bool   connect_remote(const char * Ip , unsigned short port, std::string & str) {
  std::list<std::string> niclst;
  std::list<std::string>::iterator it;
  YCommonTool::get_Nicinfo(niclst);
  for(it = niclst.begin(); it != niclst.end() ; it++) {
    std::string ip = YCommonTool::get_ip(*it);
    if(ip.empty()) {
      continue;
    }else {
      struct sockaddr_in their_addr;
      their_addr.sin_family = AF_INET;
      their_addr.sin_port = htons(port);
      their_addr.sin_addr.s_addr = inet_addr(Ip);
      memset(&(their_addr.sin_zero), '\0', 8);
      SOCKET skt = socket(AF_INET,SOCK_STREAM,0);
      if(skt == -1) {
	return false;
      }
      bool ret = _timeout_connect(skt, their_addr, 2);
      if(ret == false) {
	close(skt);
      } else {
	if(str.length() != 0) {
	  send(skt,str.c_str(),str.length(),MSG_WAITALL);
	}
	close(skt);
      }
      return ret;
    }
  }
  return false;
}

bool   check_addr(std::string & addr_str , std::string & key) {
    if(addr_str.length() == 0) {
	return false ;
    }
    char log[128] = "";
    sprintf(log,"探测地址 %s\n",addr_str.c_str());
    g_GetlogInterface()->log_trace(log);
    size_t pos = addr_str.find(':');
    ///含有端口
    if(pos != std::string::npos) {
	std::string ip = addr_str.substr(0,pos) ;
	std::string port = addr_str.substr(pos+1,addr_str.length()-pos);
	sprintf(log,"含有端口探测%s,%s\n",ip.c_str(),port.c_str());
	g_GetlogInterface()->log_trace(log);

	if(connect_remote(ip.c_str(),atoi(port.c_str()) ,key)) {
	    return true ;
	} else { ///没有连接成功, PING一下
            g_GetlogInterface()->log_trace("Ping Start");
	    PingResult result ;
	    Ping ping ;
	    if(ping.ping(ip,result)) {
		return true ;
	    }
            g_GetlogInterface()->log_trace("Ping failed");
	}

	///连接一下80端口
	if(connect_remote(ip.c_str(),80 ,key)) {
	    return true ;
	}
    } else {
	sprintf(log,"不含有端口探测 %s\n",addr_str.c_str());
	g_GetlogInterface()->log_trace(log);
	std::vector<std::string> ipvt ;
	PingResult result ;
	Ping ping ;
	if(ping.ping(addr_str,result)) {
	    return true ;
	} else {
	    if(get_host_ip(addr_str.c_str(),ipvt) > 0) {
		sprintf(log,"%s 获取域名地址成功",addr_str.c_str());
		g_GetlogInterface()->log_trace(log);

		std::vector<std::string>::iterator iter = ipvt.begin();
		while(iter != ipvt.end()) {
		    if(connect_remote(iter->c_str(),80,key)) {
			sprintf(log,"PING: %s failed ,connect 80 fucc",iter->c_str());
			g_GetlogInterface()->log_trace(log);
			return true ;
		    } else {
			sprintf(log,"PING: %s failed ,connect 80 failed",iter->c_str());
			g_GetlogInterface()->log_trace(log);
		    }
		    iter++ ;
		}
	    } else {
		sprintf(log,"%s 域名解析失败",addr_str.c_str());
		g_GetlogInterface()->log_trace(log);
	    }
	}
    }
    return false ;
}

///关机提示
static void tipsRet_shutDown(unsigned int sign) {
    g_GetSendInterface()->sendto_Main(VCF_CMD_CALL_SHUTDOWN,NULL,0);
}

void   closeNetAndShutDown(bool bAlaways,int timeout,std::string & info) {
    ///断网
    tag_closeNet  tmp ;
    tmp.policy = ONLINE_DEAL_CTRL;
    tmp.bAlaways = bAlaways ;
    g_GetSendInterface()->sendto_Main(VCF_CMD_CALL_CLOSENET,&tmp,sizeof(tmp));
    g_bcloseNet = true ;
    ///提示关机
    char buffer[512] = "";
    tag_GuiTips * pTips = (tag_GuiTips *)buffer ;
    pTips->sign = en_TipsGUI_btnOK|en_TipsGUI_timeOut ;
    pTips->defaultret = en_TipsGUI_btnOK ;
    pTips->pfunc = &tipsRet_shutDown ;
    pTips->param.timeout = timeout ;
    sprintf(pTips->szTitle,"提示");
    sprintf(pTips->szTips,"%s",info.c_str());
    g_GetSendInterface()->sendto_Imc(VCF_CMD_GUI_TIPS,buffer,sizeof(tag_GuiTips));
}

void   record_prompt(std::string & prompt) {
    FILE * fp = fopen(g_closeNetPromptFile.c_str(),"w");
    if(fp==NULL) {
	return ;
    }
    fputs(prompt.c_str(),fp);
    fclose(fp);
}

void   online_deal_ctrl(CPolicyOnlinedealctrl * pPolicy) {
    static std::string nicname = "";
    if(pPolicy->get_allowDetect()==0) {
	printf("pPolicy->get_allowDetect() == 0\n");
	return ;
    }
    char log[128] = "";
    char szTime[32]="";


    YCommonTool::get_local_time(szTime);
    ///获取网关
    std::string gatway ;
    bool  bisGetout = false ;
    char  log_buffer[1024] = "";
    tag_Policylog * plog = (tag_Policylog *)log_buffer;

    //如果已经断网，则不探测
    if(g_GetlcfgInterface()->get_offlstat()) {
	g_GetlogInterface()->log_trace("已经断网， 不探测！");
	if(g_bcloseNet) {
	    sprintf(log_buffer,"mod = %d",pPolicy->get_lanAndwan().mode);
	    g_GetlogInterface()->log_trace(log_buffer);
	    if((pPolicy->get_lanAndwan().mode == 0
		|| pPolicy->get_lanAndwan().mode == 4) && 
	       (pPolicy->get_onlyWan().mode == 0 || pPolicy->get_onlyWan().mode == 4)) {
		g_GetlogInterface()->log_trace("已经断网， 不探测！ >> 不处理， 仅提示，打开网络");
		goto open_net;
	    }
	}
	return ;
    }

    g_GetlcfgInterface()->get_lconfig(lcfg_regnic,nicname);
    gatway = YCommonTool::get_gatWay(nicname);

    sprintf(log,"获取网关: %s",gatway.c_str());
    g_GetlogInterface()->log_trace(log);

    plog->type = FIND_DAILUP ;
    plog->what = FIND_DAILUPING ;

    ///是否探测外网地址
    if(pPolicy->get_UseDetectWan()) {
	std::vector<std::string> ipvt ;
	std::string   addr_str = pPolicy->get_Wanip1() ;
	sprintf(log,"外网地址1: %s",addr_str.c_str());
	g_GetlogInterface()->log_trace(log);
	if(addr_str.length()) {
	    bisGetout = check_addr(addr_str,pPolicy->get_Wanipchar1());
	    if(bisGetout) {
		sprintf(plog->log,"StartTime=%s%sEndTime=%s%sRouteTable=%s%sclassaction=%d%sriskrank=%d",
			g_lastofflineTime,STRITEM_TAG_END,szTime,STRITEM_TAG_END,gatway.c_str(),STRITEM_TAG_END,Illegal_Behavior,STRITEM_TAG_END,
			Event_Alarm);
		g_GetlogInterface()->log_trace(plog->log);
	    }
	}
	if(!bisGetout) {
	    addr_str = pPolicy->get_Wanip2();
	    sprintf(log,"外网地址2: %s",addr_str.c_str());
	    g_GetlogInterface()->log_trace(log);
	    bisGetout = check_addr(addr_str ,pPolicy->get_Wanipchar2());
	    if(bisGetout) {
		sprintf(plog->log,"StartTime=%s%sEndTime=%s%sRouteTable=%s%sclassaction=%d%sriskrank=%d",g_lastofflineTime,STRITEM_TAG_END,
			szTime,STRITEM_TAG_END,gatway.c_str(),STRITEM_TAG_END,Illegal_Behavior,STRITEM_TAG_END,
			Event_Alarm);
		g_GetlogInterface()->log_trace(plog->log);
	    }
	}
    }

    sprintf(log,"探测地址: %s , %s",pPolicy->get_IPStart().c_str(),pPolicy->get_IPEnd().c_str());
    g_GetlogInterface()->log_trace(log);

    ///探测地址不为空
    if(pPolicy->get_IPStart().length()) {
	std::string  ip ;
	unsigned int ipstart = ntohl(inet_addr(pPolicy->get_IPStart().c_str()));
	unsigned int ipend = ntohl(inet_addr(pPolicy->get_IPEnd().c_str()));
	if(ipstart < ipend) {
	    std::list<std::string>  niclst;
	    if(YCommonTool::get_Nicinfo(niclst)) {
		std::list<std::string>::iterator iter = niclst.begin() ;
		while(iter != niclst.end()){
		    if(*iter == "lo") {
			iter++;
			continue ;
		    }
		    ip = YCommonTool::get_ip(*iter) ;
		    if(ip.length()) {
			unsigned int nIP = ntohl(inet_addr(ip.c_str()));
			if(nIP < ipstart || nIP > ipend) { ///超出范围
			    bisGetout = true;
			    sprintf(plog->log,"StartTime=%s%sEndTime=%s%sRouteTable=%s%sclassaction=%d%sriskrank=%d",
				    g_lastofflineTime,STRITEM_TAG_END,szTime,STRITEM_TAG_END,gatway.c_str(),STRITEM_TAG_END,Illegal_Behavior,STRITEM_TAG_END,
				    Event_Alarm);
			    break;
			}
		    }
		    iter++ ;
		}
	    }
	}
    }

    if(bisGetout) {
	///判断是否联到内网
	std::string  server_ip ;
	g_GetlcfgInterface()->get_lconfig(lcfg_srvip,server_ip);
	server_ip = server_ip + ":88";
	bool   bisGetIn = false ;
	std::string  tmp ;
	if(check_addr(server_ip,tmp))
	    bisGetIn = true;
        if(!bisGetIn) {
            plog->what = FIND_DAILUPED;
        }
	///上报审计日志
	report_policy_log_spec(plog);
	///违规处理
	if(bisGetIn) { ///  同时处于内外网
	    CPolicyOnlinedealctrl::tag_Item & item = pPolicy->get_lanAndwan();
	    switch(item.mode) {
	    case 0: { ///不处理
		g_GetlogInterface()->log_trace("同时处于内外网，不上报");
		if(g_bcloseNet) {
		    g_GetlogInterface()->log_trace("不处理的情况下，断网状态， 打开网络\n");
		    goto open_net;
		}
		break;
	    }
	    case 1: { ///断开网络并关机
		g_GetlogInterface()->log_trace("同时处于内外网，断开网络并关机");
		closeNetAndShutDown(false,item.shutDownTime,item.Prompt);
		break ;
	    }
	    case 2: { ///断开网络
		g_GetlogInterface()->log_trace("同时处于内外网，断开网络 重启恢复");
		char buffer[512] = "";
		tag_GuiTips * pTips = (tag_GuiTips *)buffer ;
		pTips->sign = en_TipsGUI_btnOK|en_TipsGUI_timeOut ;
		pTips->defaultret = en_TipsGUI_None ;
		pTips->pfunc = NULL ;
		pTips->param.timeout = item.shutDownTime ;
		sprintf(pTips->szTitle,"提示");

		g_GetlogInterface()->log_trace(item.Prompt2.c_str());
		sprintf(pTips->szTips,"%s",item.Prompt2.c_str());
		g_GetSendInterface()->sendto_Imc(VCF_CMD_GUI_TIPS,buffer,sizeof(tag_GuiTips));
		tag_closeNet  tmp ;
		tmp.policy = ONLINE_DEAL_CTRL;
		tmp.bAlaways = false ;
		g_GetSendInterface()->sendto_Main(VCF_CMD_CALL_CLOSENET,&tmp,sizeof(tmp));
		g_bcloseNet = true ;
		break ;
	    }
	    case 4: { ///提示
		g_GetlogInterface()->log_trace("同时处于内外网 仅提示\n");
		char buffer[512] = "";
		tag_GuiTips * pTips = (tag_GuiTips *)buffer ;
		pTips->sign = en_TipsGUI_btnOK|en_TipsGUI_timeOut;
		pTips->defaultret = en_TipsGUI_None ;
		pTips->pfunc =NULL;
		sprintf(pTips->szTitle,"提示");
		sprintf(pTips->szTips,"%s",item.Prompt4.c_str());
		g_GetSendInterface()->sendto_Imc(VCF_CMD_GUI_TIPS,buffer,sizeof(tag_GuiTips));
		if(g_bcloseNet) {
		    g_GetlogInterface()->log_trace("仅提示的情况下，断网， 打开网络\n");
		    goto open_net;
		}
		break;
	    }
	    case 8: { ///断开网络并关机
		g_GetlogInterface()->log_trace("同时处于内外网  yongjiu 断开网络并关机\n");
		closeNetAndShutDown(true,item.shutDownTime,item.Prompt8);
		if(pPolicy->get_RebootPrompt().length()) {
		    record_prompt(pPolicy->get_RebootPrompt());
		}
		break ;
	    }
	    }
	} else {
	    CPolicyOnlinedealctrl::tag_Item & item = pPolicy->get_onlyWan();
	    switch(item.mode) {
	    case 0: { ///不处理
		g_GetlogInterface()->log_trace("只处于外网，  不处理\n");
		if(g_bcloseNet) {
		    g_GetlogInterface()->log_trace("不处理的情况下，断网， 打开网络\n");
		    goto open_net;
		}
		break ;
	    }
	    case 1: { ///断开网络并关机(重启恢复) shutDownTime有效
		g_GetlogInterface()->log_trace("只处于外网，  断开网络并关机(重启恢复)\n");
		closeNetAndShutDown(false,item.shutDownTime,item.Prompt);
		break ;
	    }
	    case 2: { ///断开网络(重启恢复)
		g_GetlogInterface()->log_trace("只处于外网，  断开网络(重启恢复)\n");
		char buffer[512] = "";
		tag_GuiTips * pTips = (tag_GuiTips *)buffer ;
		pTips->sign = en_TipsGUI_btnOK|en_TipsGUI_timeOut ;
		pTips->defaultret = en_TipsGUI_None ;
		pTips->pfunc = NULL ;
		pTips->param.timeout = item.shutDownTime ;
		sprintf(pTips->szTitle,"提示");
		sprintf(pTips->szTips,"%s",item.Prompt2.c_str());
		g_GetSendInterface()->sendto_Imc(VCF_CMD_GUI_TIPS,buffer,sizeof(tag_GuiTips));

		tag_closeNet  tmp ;
		tmp.policy = ONLINE_DEAL_CTRL;
		tmp.bAlaways = false ;
		g_GetSendInterface()->sendto_Main(VCF_CMD_CALL_CLOSENET,&tmp,sizeof(tmp));
		g_bcloseNet = true ;

		break ;
	    }
	    case 4: { ///仅提示 Prompt 有效
		g_GetlogInterface()->log_trace("只处于外网， 只提示\n");
		char buffer[512] = "";
		tag_GuiTips * pTips = (tag_GuiTips *)buffer ;
		pTips->sign = en_TipsGUI_btnOK|en_TipsGUI_timeOut;
		pTips->defaultret = en_TipsGUI_None ;
		pTips->pfunc =NULL;
		sprintf(pTips->szTitle,"提示");
		sprintf(pTips->szTips,"%s",item.Prompt4.c_str());
		g_GetSendInterface()->sendto_Imc(VCF_CMD_GUI_TIPS,buffer,sizeof(tag_GuiTips));
		if(g_bcloseNet) {
		    goto open_net;
		}
		break ;
	    }
	    case 8: { ///接回内网后进行安全检查
		g_GetlogInterface()->log_trace("只处于外网， 接回内网后进行安全检查 没有做\n");
		break ;
	    }
	    case 16: {///断开网络并关机(需解锁) shutDownTime有效
		g_GetlogInterface()->log_trace("只处于外网， 断开网络并关机(需解锁)\n");
		closeNetAndShutDown(true,item.shutDownTime,item.Prompt16);
		if(pPolicy->get_RebootPrompt().length()) {
		    record_prompt(pPolicy->get_RebootPrompt());
		}
		break;
	    }
	    }
	}
	strcpy(g_lastofflineTime,szTime);

    } else {
	g_GetlogInterface()->log_trace("探测无外联情况发生");
	YCommonTool::get_local_time(g_lastofflineTime);
    }

    if(false) {
      open_net:
	tag_openNet open ;
	open.policy = ONLINE_DEAL_CTRL;
	g_GetlogInterface()->log_trace("发送打开网络请求");
	g_GetSendInterface()->sendto_Main(VCF_CMD_OPEN_NET,&open,sizeof(open));
	g_bcloseNet = false ;
    }
}
