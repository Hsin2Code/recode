/*
 * http_access_ctrl.cpp
 *
 *  Created on: 2015-1-17
 *      Author: sharp
 */
#include "http_access_ctrl.h"

#include <vector>
#include <string>
#include <pcap.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <linux/ip.h>
#include "../../common/CLocker.h"
#include "../../VCFCmdDefine.h"
#include "../../../include/MCInterface.h"

#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "../../CMyIptables.h"

extern ILocalCfginterface * g_GetlcfgInterface();

static bool spliteIp_port(std::string & src , std::string & ip , unsigned short & port) {
	unsigned int npos = src.find(":",0);
	if(npos == std::string::npos) {
		return false ;
	}

	ip = src.substr(0,npos);
	port = atoi(src.substr(npos+1,src.length() - npos - 1).c_str());
	return true ;
}

bool   CPolicyHttpAccessctrl::import_xml(const char * pxml) {
	if(pxml == NULL) {
		return false ;
	}

	CMarkup  xml ;
	if(!xml.SetDoc(pxml)) {
		return false ;
	}

	std::string  weblist ;
	std::string  httpslist ;
	if(xml.FindElem("vrvscript")) {
		xml.IntoElem();
		while(xml.FindElem("item")) {
			weblist = xml.GetAttrib("WEBList");
			m_Acmode = atoi(xml.GetAttrib("AccessMode").c_str());
			httpslist = xml.GetAttrib("HttpsList").c_str();
			m_httpsEnable = (atoi(xml.GetAttrib("HttpsAccessMode").c_str())==1);
		}
		xml.OutOfElem();
	}

	if(weblist.size()) {
		m_webList.clear();
		YCommonTool::split_new(weblist,m_webList,";");
	}
	if(httpslist.size()) {
		m_httpsList.clear();
		YCommonTool::split_new(httpslist,m_httpsList,";");
	}

	return CPolicy::import_xmlobj(xml) ;
}

void   CPolicyHttpAccessctrl::copy_to(CPolicy * pDest) {
	CPolicyHttpAccessctrl * _pDest = (CPolicyHttpAccessctrl *)pDest ;

	_pDest->m_Acmode = m_Acmode ;
	_pDest->m_webList = m_webList ;
	_pDest->m_httpsEnable = m_httpsEnable ;
	_pDest->m_httpsList = m_httpsList ;

	CPolicy::copy_to(pDest);
}
///=====================================================================================
struct  tag_IpTblrule {
	std::string  chain ;
	std::string  target ;
	std::string  opt ;
	std::string  src ;
	std::string  dest ;
};
const   char  *    g_tptblsFilename = "oldRule.txt";
static  std::vector<tag_IpTblrule>    g_vtRule ;
bool    g_bChainAdd = false ;
///=====================================================================================
///初始化
bool  http_access_ctrl_init() {
	/**
	 *  新建一个规则链条
	 */

	return true ;
}

static bool  getipfromName(std::string & name , std::vector<std::string> & ipVt) {
	struct hostent *  he = NULL ;
	struct in_addr ** addr_list;
	he = gethostbyname(name.c_str());
	if(he == NULL){
		return false ;
	}
	ipVt.clear();
	addr_list = (struct in_addr **)he->h_addr_list;
	for(int i = 0; addr_list[i] != NULL; i++) {
		ipVt.push_back(inet_ntoa(*addr_list[i]));
	}
	return true ;
}

int   crc = 0;
///
bool  http_access_ctrl_worker(CPolicy * pPolicy, void * pParam) {
	if(pPolicy->get_type() != HTTP_ACCESS_CTRL) {
		return false ;
	}

	///如果已经全局断网，后来的不再执行。
	if(g_GetlcfgInterface()->get_offlstat()) {
		return true;
	}

	CPolicyHttpAccessctrl * pAccess = (CPolicyHttpAccessctrl *)pPolicy ;

	printf("***http_access_ctrl_worker_ start\n");

	char cmd[1024] = "";
	sprintf(cmd,"iptables -F %s",MY_IPT_CHAIN_NAME4httpctrl);
	///清除掉原来的规则
	system(cmd);


	if(pAccess->get_Acmode() == 1) { ///仅允许访问的情况下， 先禁止所有的TCP, 80端口的连接
		sprintf(cmd,"iptables -I %s -p tcp --dport 80  -j  DROP",MY_IPT_CHAIN_NAME4httpctrl);
		system(cmd);
	}

	///本地通讯允许，不然消息队列的通讯会受阻
	sprintf(cmd,"iptables -I %s -p tcp -d 127.0.0.1  -j ACCEPT",MY_IPT_CHAIN_NAME4httpctrl);
	system(cmd);

	std::string  server_ip ;
	g_GetlcfgInterface()->get_lconfig(lcfg_srvip,server_ip);
	sprintf(cmd,"iptables -I %s -p tcp -d %s  -j ACCEPT",MY_IPT_CHAIN_NAME4httpctrl,server_ip.c_str());
	system(cmd);

	printf("=======================================================>\n");

	std::vector<std::string> ipVt;
	///增加新的HTTPS规则
	if(pAccess->get_httpsEnable() == 1) {
		std::string ip  = "";
		unsigned short port = 0 ;
		std::vector<std::string> & _vt = pAccess->get_httpsList();
		std::vector<std::string>::iterator iter = _vt.begin();
		while(iter != _vt.end()) {
			if(g_GetlcfgInterface()->get_offlstat()) {
				return true ;
			}
			if(spliteIp_port(*iter,ip,port)) {
				if(pAccess->get_Acmode() == 1) {
					sprintf(cmd,"iptables -I %s  -d %s -p tcp --dport %d -j ACCEPT",MY_IPT_CHAIN_NAME4httpctrl,ip.c_str(),port);
					system(cmd);
				} else {
					sprintf(cmd,"iptables -I %s  -d %s -p tcp --dport %d -j DROP",MY_IPT_CHAIN_NAME4httpctrl,ip.c_str(),port);
					system(cmd);
				}
			}
			iter++ ;
		}
	}

	{
		std::string tmp;
		std::vector<std::string> _vt  =  pAccess->get_webList();
		std::vector<std::string>::iterator iter = _vt.begin();
		while(iter != _vt.end()) {
			if(g_GetlcfgInterface()->get_offlstat()) {
				return true ;
			}
			std::string & web = *iter ;
			if(pAccess->get_Acmode() == 1) { ///只允许访问
				printf("允许访问\n");
				if(web[0] == '[') { ///启用二级域名
					tmp = web.substr(1,web.length()-2) ;
					sprintf(cmd,"iptables -I %s -p tcp --dport 80 -m string --string \"%s\" --algo bm -j ACCEPT",
							MY_IPT_CHAIN_NAME4httpctrl,tmp.c_str());
					printf("%s\n",cmd);
					system(cmd);
				} else {
					unsigned long ip = inet_addr(web.c_str());
					if(ip != INADDR_NONE) { ///纯IP格式
						sprintf(cmd,"iptables -I %s  -d %s -p tcp --dport 80 -j ACCEPT",MY_IPT_CHAIN_NAME4httpctrl,web.c_str());
						system(cmd);
					} else {
						/**
						 * 域名的话， 获取IP，全部都生效。
						 */
						if(getipfromName(web,ipVt)) {
							printf("ip ： %d\n",ipVt.size());
							/*std::vector<std::string>:: iterator iterIP = ipVt.begin() ;
							while(iterIP != ipVt.end()) {
								sprintf(cmd,"iptables -I %s  -d %s -p tcp  -j ACCEPT",MY_IPT_CHAIN_NAME4httpctrl,iterIP->c_str());
								printf("%s\n",cmd);
								iterIP++;
								system(cmd);
							}*/
							sprintf(cmd,"iptables -I %s  -d %s -p tcp  -j ACCEPT",MY_IPT_CHAIN_NAME4httpctrl,web.c_str());
							printf("%s\n",cmd);
							system(cmd);
						} else
						{
							sprintf(cmd,"iptables -I %s -p tcp --dport 80 -m string --string \"%s\" --algo bm -j ACCEPT",
									MY_IPT_CHAIN_NAME4httpctrl,web.c_str());

							system(cmd);
						}
					}
				}
			} else {
				printf("fff禁止方位\n");
				if(web[0] == '[') { ///启用二级域名
					tmp = web.substr(1,web.length()-2) ;
					sprintf(cmd,"iptables -I %s -p tcp --dport 80 -m string --string  \"%s\" --algo bm -j DROP",
							MY_IPT_CHAIN_NAME4httpctrl,tmp.c_str());
					system(cmd);
				} else {
					unsigned long ip = inet_addr(web.c_str());
					if(ip != INADDR_NONE) { ///纯IP格式
						sprintf(cmd,"iptables -I %s  -d %s -p tcp --dport 80 -j DROP",MY_IPT_CHAIN_NAME4httpctrl,web.c_str());
						system(cmd);
					} else {
						/**
						 * 域名的话， 获取IP，全部都生效。
						 */
						if(getipfromName(web,ipVt)) {
							std::vector<std::string>:: iterator iterIP = ipVt.begin() ;
							while(iterIP != ipVt.end()) {
								sprintf(cmd,"iptables -I %s  -d %s -p tcp --dport 80 -j DROP",MY_IPT_CHAIN_NAME4httpctrl,iterIP->c_str());
								iterIP++;
								system(cmd);
							}
						} else
						{
							sprintf(cmd,"iptables -I %s -p tcp --dport 80 -m string --string  \"Host:%s\" --algo bm -j DROP",
									MY_IPT_CHAIN_NAME4httpctrl,web.c_str());
							system(cmd);
						}
					}
				}
			}
			iter++ ;
		}
	}
	sprintf(cmd,"iptables -D %s -j %s",MY_IPT_CHAIN_NAME,MY_IPT_CHAIN_NAME4httpctrl);
	system(cmd);
	sprintf(cmd,"iptables -I %s -j %s",MY_IPT_CHAIN_NAME,MY_IPT_CHAIN_NAME4httpctrl);
	system(cmd);

	printf("***http_access_ctrl_worker_ finish\n");
	return true ;
}

///
void  http_access_ctrl_uninit() {
	char buffer[1204] = "";
	sprintf(buffer,"iptables -F %s",MY_IPT_CHAIN_NAME4httpctrl);
	system(buffer);
	return  ;
}
