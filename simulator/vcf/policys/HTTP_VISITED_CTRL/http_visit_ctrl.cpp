#include "http_visit_ctrl.h"

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
#include <unistd.h>
#include <linux/ip.h>
#include "../../common/CLocker.h"
#include "../../VCFCmdDefine.h"
#include "../../../include/MCInterface.h"


using namespace std;

#define MAXBYTES2CAPTURE 2048
#define STRSIZE 1024

#define  HOST_HEAD_STRING  "Host: "
#define  HOST_TAIL_STRING  "\r\n"
#define  GET_HEAD_STRING   "GET "
#define  GET_TAIL_STRING   "HTTP"
#define  GET_REFERER_HEAD  "Referer: http://"
#define  GET_REFERER_TAIL  "\r\n"
#define  CONTEXT_SIGN_HTTP  "审计访问网页"
#define  CONTEXT_SIGN_FTP   "审计访问ftp"
#define  HTML_HEAD_STRING  "<html>"
#define  HTML_TAIL_STRING  "</html>"

#define  PKT_LIST_CHAN_CNT   1024



typedef struct
{
    string hostInfo;
    string reportInfo;
} urlInfo;

struct   tag_Packetinfo {
	tag_Packetinfo * pNext ;
	unsigned short   port ;
	char hostInfo[1024];
	tag_Packetinfo() {
		memset(this,0,sizeof(tag_Packetinfo));
	}
};
//==========================================================
//网卡过滤信息结构提
struct   tag_AVisitCtrl {
	///网卡名称
	std::string         name  ;
	///网卡监控实例
	pcap_t *            pdescr ;
	///监控线程
	pthread_t           trdid ;
	///本地策略副本
	CPolicyHttpVisitctrl      *      policy;
	std::vector<urlInfo>    url_vt ;
	///日志缓存
	char   *            plogBuffer ;
	string              reportInfo;
	string              hostInfo;
	string              refererInfo;
	string              uri ;
	volatile     bool   bruning ;

	tag_AVisitCtrl() {
		name = "";
		pdescr = NULL ;
		trdid = 0 ;
		policy = NULL ;
		reportInfo.assign(2048,'\0');
		hostInfo.assign(1024,'\0');
		refererInfo.assign(1024,'\0');
		uri.assign(1024,'\0');
		bruning = false ;
		try {
			plogBuffer = new char[4096] ;
		} catch(...) {
			printf("tag_AVisitCtrl init failed \n");
		}
	}

	~tag_AVisitCtrl() {
		bruning = false ;
		if(pdescr) {
			if(trdid) {
				void * status = 0 ;
				if(trdid) {
					pthread_join(trdid,&status);
				}
				trdid = 0 ;
			}
			pcap_close(pdescr);
			pdescr = 0 ;
		}

		if(policy) {
			delete policy ;
		}

		url_vt.clear();
		if(plogBuffer) {
			delete []plogBuffer ;
			plogBuffer = NULL ;
		}
	}
};
//======================================================================================
typedef  std::map<std::string,tag_AVisitCtrl *>   CNetVisitCtrlMap ;
static   CNetVisitCtrlMap   g_acMap;
///服务器地址
static   std::string            g_server_ip;
///策略副本锁
static   YCommonTool::CLocker * g_pLocker = NULL ;
///策略副本
static   CPolicyHttpVisitctrl  *  g_pPolicyHttpvisitctrl = NULL;
///初始化标志
static   bool   g_isStartTrd = false ;
///host字段长度
static  const  unsigned char  cb_host_Hlen = strlen(HOST_HEAD_STRING);
static  const  unsigned char  cb_host_Tlen = strlen(HOST_TAIL_STRING);
///get字段长度
static  const  unsigned char  cb_get_Hlen = strlen(GET_HEAD_STRING);
static  const  unsigned char  cb_get_Tlen = strlen(GET_TAIL_STRING);
///referer字段长度
static  const  unsigned char  cb_refer_Hlen = strlen(GET_REFERER_HEAD);
static  const  unsigned char  cb_refer_Tlen = strlen(GET_REFERER_TAIL);
///HTMLtar长度
static  const  unsigned char  cb_html_Hlen = strlen(HTML_HEAD_STRING);
static  const  unsigned char  cb_html_Tlen = strlen(HTML_TAIL_STRING);
///本地日志文件名称
static  const  char  *   g_locallogName = "http_visit_ctrl.log";
//=====================================================================================
///包过滤线程函数
static  void * packet_filter(void * pParam);
///包过滤回调函数
static void    packet_filter_worker(unsigned char * ch, const struct pcap_pkthdr *header, const unsigned char *packet);
///HTTP协议处理
static void    http_packet_process(char *data, int http_len, char *dst_ip, struct tcphdr *tcpptr,tag_AVisitCtrl * pCtrl);
///HTTP协议关键字
static void    http_key_process(char *data, int http_len, char *dst_ip, struct tcphdr *tcpptr,tag_AVisitCtrl * pCtrl);
///FTP协议处理
static void    ftp_packet_process(char *data, int http_len, char *dst_ip,tag_AVisitCtrl * pCtrl);
///
static int     strJudgeQueMack(char *str, int len);
///删除斜杠
static int     removeSlash(char *str, int len);
///判断是否HTTP协议
static void    match_http(char *data, const char *head_str, unsigned char hlen, const char *tail_str,unsigned char tlen, char *buf, int total_len);
///上报日志
static bool    report_Auditlog(tag_AVisitCtrl * pCtrl,bool bisFtp = false);
///匹配关键字
static bool    match_key(tag_AVisitCtrl * pCtrl,char * data, int len);
///记录log
static bool    record_locallog(char * plog) {
	char  szTime[64] = "";
	YCommonTool::get_local_time(szTime);
	char  szlog[1024] = "";
	FILE * fp = fopen(g_locallogName,"a+");
	if(fp == NULL) {
		return false ;
	}
	sprintf(szlog,"-------------------%s---------------------\n%s",szTime,plog);
	fputs(szlog,fp);
	fclose(fp);
	return true ;
}
///是否高级策略检验通过
static   volatile    bool   g_adv_enable = true ;
static   void   advcfg_statchage(void * pParam) {
   bool * pbool = ( bool *)pParam;
   g_adv_enable = *pbool ;
}

bool    http_visit_ctrl_init() {
	printf("http_visit_ctrl_init start\n");
	///申请内存空间
	pcap_if_t *device = NULL;
	struct bpf_program filter;
	char errbuf[PCAP_ERRBUF_SIZE]= "";

	///注册策略高级设置状态改变消息
	g_adv_enable = true;
	g_GetEventNotifyinterface()->registerEvent(enNotifyer_policyAdvcfg_statChange,advcfg_statchage);

	///获取服务器地址
	std::string key = SRV_ADDRESS ;
	g_server_ip = g_GetNetEnginesinkInterface()->get_Param(key);

	///查找网卡
	if(-1 == pcap_findalldevs(&device,errbuf)) {
		g_GetlogInterface()->log_error("HTTP_ACCESS_CTRL   pcap_findalldevs error \n");
		return false ;
	}
	///没找到， 就没有执行的必要。
	if(device == NULL) {
		return false ;
	}
	///存放地址
	bpf_u_int32 netaddr = 0;
	///存放掩码
	bpf_u_int32	mask = 0;
	char buffer_log[PCAP_ERRBUF_SIZE] = "";
	char szfilter[64] = "";
	///过滤21，80端口
	sprintf(szfilter, "ip and tcp and (dst port 80 or dst port 21 or src port 80)");

	while(device) {
		///获取网卡信息
		printf("nicname = %s\n",device->name);
		if(pcap_lookupnet(device->name, &netaddr, &mask, errbuf) == -1) {
			std::string error = "HTTP_VISIT_CTRL pcap_lookupnet error #";
			error = error + errbuf ;
			g_GetlogInterface()->log_error(error.c_str());
			device = device->next ;
			continue ;
		}

		///回环地址跳过
		if(strcmp(device->name,"lo") == 0 ||
				strcmp(device->name,"any") == 0) {
			device = device->next ;
			continue ;
		}

		sprintf(buffer_log,"获取网卡信息成功 name = %s \n",device->name);
		g_GetlogInterface()->log_trace(buffer_log);
		tag_AVisitCtrl * pCtrl =NULL ;
		try {
			pCtrl = new tag_AVisitCtrl ;
		} catch(...) {
			pcap_freealldevs(device);
			return false ;
		}

		pCtrl->pdescr = pcap_open_live(device->name, MAXBYTES2CAPTURE, 0, 1, errbuf);
		if(pCtrl->pdescr == NULL) {
			sprintf(buffer_log,"打开网卡信息失败 name = %s （%s）\n",device->name,errbuf);
			g_GetlogInterface()->log_error(buffer_log);
			device = device->next ;
			delete pCtrl ;
			continue ;
		}

		///设置FILTER
		if(-1 == pcap_compile(pCtrl->pdescr, &filter, szfilter, 1, 0)) {
			sprintf(buffer_log,"设置过滤信息失败 name = %s\n",device->name);
			g_GetlogInterface()->log_error(buffer_log);
			device = device->next ;
			delete pCtrl ;
			continue ;
		}
		pcap_setfilter(pCtrl->pdescr, &filter);

		pCtrl->name = device->name ;
		///申请包存放初始化空间
		g_acMap[pCtrl->name] = pCtrl;
		device = device->next ;
	}
	///释放网卡信息内存空间
	pcap_freealldevs(device);

	if(g_pLocker == NULL) {
		try{
			g_pLocker = new YCommonTool::CLocker ;
		} catch(...) {
			http_visit_ctrl_uninit();
			return false ;
		}

	}
	g_isStartTrd = false ;
	printf("http_visit_ctrl_init finish\n");
	return  true ;
}

///执行函数
bool http_visit_ctrl_worker(CPolicy * pPolicy, void * pParam) {
	if(pPolicy->get_type() != HTTP_VISIT_CTRL) {
		return false ;
	}
	printf("http_visit_ctrl_worker start\n");
	///策略初始化
	if(g_pPolicyHttpvisitctrl == NULL) {
		g_pPolicyHttpvisitctrl = (CPolicyHttpVisitctrl *) create_policy(HTTP_VISIT_CTRL);
		if(g_pPolicyHttpvisitctrl == NULL) {
			return false ;
		}
	}

	///校验和不同
	if(pPolicy->get_crc() != g_pPolicyHttpvisitctrl->get_crc()) {
		YCommonTool::CLockHelper  helper(g_pLocker);
		///拷贝策略
		pPolicy->copy_to(g_pPolicyHttpvisitctrl);
	}

	///只有第一次调用WORKER的时候启动一次线程, 以后的WORKER运行其实就是为了获取最新的策略
	if(g_isStartTrd == false) {
		/**
		*  启动执行线程
		*/
		CNetVisitCtrlMap::iterator iter = g_acMap.begin();
		while(iter != g_acMap.end()) {
			printf("启动线程: %s\n",iter->first.c_str());
			iter->second->bruning = true ;
			int ret = pthread_create(&iter->second->trdid, NULL, packet_filter, iter->second);
			if(ret != 0) {
				delete iter->second ;
				g_acMap.erase(iter++);
			} else
				iter++ ;
		}
		g_isStartTrd =  true ;
	}

	printf("http_visit_ctrl_worker finish\n");
	return true ;
}
///策略清理函数
void http_visit_ctrl_uninit() {
	printf("http_visit_ctrl_uninit start\n");

	g_GetEventNotifyinterface()->UnregisterEvent(enNotifyer_policyAdvcfg_statChange,advcfg_statchage);
	CNetVisitCtrlMap::iterator iter = g_acMap.begin();
	while(iter != g_acMap.end()) {
		delete iter->second ;
		iter++ ;
	}
	g_isStartTrd = false ;
	g_acMap.clear();
	if(g_pPolicyHttpvisitctrl) {
		delete g_pPolicyHttpvisitctrl ;
		g_pPolicyHttpvisitctrl = NULL ;
	}
	if(g_pLocker) {
		 delete g_pLocker ;
		 g_pLocker =  NULL ;
	}
	printf("http_visit_ctrl_uninit finish\n");
}
/**
 * 包过滤函数
 * 阻塞调用
 */
void *  packet_filter(void * pParam) {
	tag_AVisitCtrl * pCtrl = (tag_AVisitCtrl *)pParam ;
	pCtrl->policy  =  new CPolicyHttpVisitctrl;

	struct pcap_pkthdr    *   pkt_header = NULL ;
	const  unsigned char  *   pkt_data   = NULL ;
	printf("packet_filter_worker \n");

	while(pCtrl->bruning) {
		///检测线程是否有变化
		if(pCtrl->policy->get_crc() != g_pPolicyHttpvisitctrl->get_crc()) {
			YCommonTool::CLockHelper  helper(g_pLocker);
			g_pPolicyHttpvisitctrl->copy_to(pCtrl->policy);
		}

		///高级策略检测
		if(!g_adv_enable) {
			///10毫秒
			usleep(10000);
			continue ;
		}

		///获取一个报文
		int ret = pcap_next_ex(pCtrl->pdescr,&pkt_header,&pkt_data) ;
		if(ret  < 0) {
			break ;
		}
		///超时
		if(ret == 0) {
			continue ;
		}
		///进行过滤
		packet_filter_worker((unsigned char *)pCtrl , pkt_header , pkt_data);
	}
	printf("packet_filter_worker——end \n");
	return 0 ;
}

void  packet_filter_worker(unsigned char * ch, ///自定义参数
		const struct pcap_pkthdr * header,     ///包头
		const unsigned char * packet)          ///包数据
{
	tag_AVisitCtrl * pCtrl = (tag_AVisitCtrl *)ch ;
	///策略发生改变，重新赋值
	if(pCtrl->policy->get_crc() != g_pPolicyHttpvisitctrl->get_crc()) {
		YCommonTool::CLockHelper  helper(g_pLocker);
		g_pPolicyHttpvisitctrl->copy_to(pCtrl->policy);
	}

	int  http_len = 0 ;
	char * data  = NULL ;
	char *tmp_dst;
	int  dst_len;
	char dst_ip[16];

	struct ether_header * eptr = NULL ;
	struct iphdr  * ipptr = NULL ;
	struct tcphdr * tcpptr = NULL ;

	eptr = (struct ether_header *)packet;

	///判断长度
	if(header->caplen != header->len) {
		return  ;
	}
	///IP判断
	ipptr = (struct iphdr *)(packet + sizeof(struct ether_header));
	if(ntohs(ipptr->tot_len) != (header->caplen - sizeof(struct ether_header)))
		return ;
	///获取TCP数据
	tcpptr=(struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));

	if(tcpptr->psh == 0x01 && tcpptr->ack == 0x01 ) {
		http_len = ntohs(ipptr->tot_len) - ((ipptr->ihl)<<2) - ((tcpptr->doff)<<2);
		tmp_dst = inet_ntoa(*(struct in_addr *)(&ipptr->daddr));
		dst_len = strlen(tmp_dst);
		if(dst_len <= 15) {
			strncpy(dst_ip, tmp_dst, dst_len);
			dst_ip[dst_len] = '\0';
		} else {
			return ;
		}

		///服务器地址跳过
		if(0 == strncmp(dst_ip, g_server_ip.c_str(), dst_len)) {
			return ;
		}

		data = (char *)(packet+sizeof(struct ether_header) + ((ipptr->ihl)<<2) + ((tcpptr->doff)<<2));

		///对关键字进行过滤
		if(ntohs(tcpptr->source) == 80) {
			//http_key_process(data, http_len, dst_ip, tcpptr,pCtrl);
		}

		switch(ntohs(tcpptr->dest)) {
			case 21: {
				ftp_packet_process(data, http_len, dst_ip,pCtrl);
				break;
			}
			case 80: {
				http_packet_process(data, http_len, dst_ip, tcpptr,pCtrl);
				break;
			}
			default:
				break;
		}
	}
}

void  http_key_process(char *data, int http_len, char *dst_ip, struct tcphdr *tcpptr,tag_AVisitCtrl * pCtrl) {
	///匹配关键字
	if(pCtrl->policy->get_Allowtip() == 1) {
		if(match_key(pCtrl,data,http_len)) {
			///提示
			char buffer[1024]="";
			tag_GuiTips * pTips = (tag_GuiTips *)buffer ;
			pTips->sign = en_TipsGUI_btnOK; ///界面标识
			pTips->defaultret = en_TipsGUI_btnOK ;
			pTips->pfunc = NULL ;
			sprintf(pTips->szTitle,"提示 ");
			   sprintf(pTips->szTips,"%s",pCtrl->policy->get_Tips().c_str());
			//g_GetSendInterface()->sendto_Imc(VCF_CMD_GUI_TIPS,buffer,sizeof(tag_GuiTips));
		}
	}

}

void  http_packet_process(char *data, int http_len, char *dst_ip, struct tcphdr *tcpptr,tag_AVisitCtrl * pCtrl )
{
	int ret = 0;
	unsigned int k = 0;

	urlInfo url;
	if(http_len > 3) {
		///GET方法
		if((*data=='G')&&(*++data=='E')&&(*++data=='T')) {
			char * pHost = const_cast<char *>(pCtrl->hostInfo.c_str());
			char * pUri = const_cast<char *>(pCtrl->uri.c_str());
			char * pRefer = const_cast<char *>(pCtrl->refererInfo.c_str());

			match_http(data, HOST_HEAD_STRING,cb_host_Hlen, HOST_TAIL_STRING,cb_host_Tlen, pHost, http_len);
			match_http(data, GET_HEAD_STRING,cb_get_Hlen, GET_TAIL_STRING,cb_get_Tlen, pUri, http_len);
			match_http(data, GET_REFERER_HEAD,cb_refer_Hlen, GET_REFERER_TAIL,cb_refer_Tlen, pRefer, http_len);

			ret = strJudgeQueMack(pUri, strlen(pUri));
			if(1 == ret) {
				return;
			}

			///去掉域名后面的数据
			removeSlash(pRefer, pCtrl->refererInfo.length());

			if(0 == pCtrl->hostInfo.length()) {
				return;
			}

			char * pReport = const_cast<char *>(pCtrl->reportInfo.c_str());
			sprintf(pReport, "%s%s", pHost, pUri);

			string &  hostInfo = pCtrl->hostInfo;
			string &  refererInfo = pCtrl->refererInfo;

			bool  bmat = false ;
			for( k=0; k < pCtrl->policy->m_urlArray.size(); k++) {
				if(string::npos != hostInfo.find(pCtrl->policy->m_urlArray[k], 0) ||
								0 == pCtrl->policy->m_urlArray[k].compare(dst_ip) ) {
					printf("***************************匹配上\n");
					bmat = true ;
					break ;
				}
			}

			if(bmat) { ///匹配上
				if(pCtrl->policy->get_Audit() == 1) { ///需要审计，报日志
					url.hostInfo = hostInfo;
					url.reportInfo = pCtrl->reportInfo;
					pCtrl->url_vt.push_back(url);
				}
			} else {
				///不审计的情况,判断referer字段，如果包含地址，也不应该审计
				bmat = false ;
				if(pCtrl->policy->get_Audit() == 0) {
					for( k=0; k < pCtrl->policy->m_urlArray.size(); k++) {
						if(string::npos != refererInfo.find(pCtrl->policy->m_urlArray[k], 0)) {
							bmat = true ;
							break ;
						}
					}
					///REFERER中也不包含， 审计
					if(!bmat) {
						url.hostInfo = hostInfo;
						url.reportInfo = pCtrl->reportInfo;
						pCtrl->url_vt.push_back(url);
					}
				}
			}
		}
	}

	report_Auditlog(pCtrl);
	return;
}

bool    report_Auditlog(tag_AVisitCtrl * pCtrl,bool bisFtp) {
	if(pCtrl->url_vt.size()==0) {
		return true ;
	}

	char szTime[21]="";
	YCommonTool::get_local_time(szTime);

	tag_Policylog * plog = (tag_Policylog *)pCtrl->plogBuffer ;
	plog->what = 1;
	plog->type = 61;
	char * pTmp = plog->log ;

	const char * pCtxSign = CONTEXT_SIGN_HTTP;
	if(bisFtp) {
		pCtxSign = CONTEXT_SIGN_FTP;
	}

	std::string user ;
	get_desk_user(user);

	for(unsigned int i = 0 ; i < pCtrl->url_vt.size(); i++) {
		sprintf(pTmp,"Body%d=time=%s<>kind=700<>policyid=%d<>policyname=%s<>host=%s<>KeyUserName=%s<>classaction=2<>riskrank=6<>context=%s: %s%s%s%s",
				i,szTime,pCtrl->policy->get_id()
				,pCtrl->policy->get_name().c_str()
				,pCtrl->url_vt[i].hostInfo.c_str(),
				user.c_str(),
				pCtxSign,pCtrl->url_vt[i].reportInfo.c_str(),STRITEM_TAG_END,"BodyCount=1",STRITEM_TAG_END);
		///上报服务器
		if(pCtrl->policy->get_Uplog() == 1) {
			report_policy_log(plog);
		}

		if(pCtrl->policy->get_rcLocal() == 1) {
			///记录到本地
			record_locallog(plog->log);
		}
	}
	pCtrl->url_vt.clear();
	return true ;
}

void ftp_packet_process(char *data, int http_len, char *dst_ip,tag_AVisitCtrl * pCtrl ) {
	unsigned int k;
	char ftp[32] = {'\0'};

	if(http_len > 5) {
		if((*data=='U')&&(*++data=='S')&&(*++data=='E')&&(*++data=='R')&&(*++data==' ')) {
			sprintf(ftp, "ftp://%s", dst_ip);
			for(k = 0; k < pCtrl->policy->m_urlArray.size(); k++) {
				if(0 == strcmp(ftp, pCtrl->policy->m_urlArray[k].c_str())) {
					if(pCtrl->policy->get_Audit() == 1) {
						report_Auditlog(pCtrl,true);
					}
				} else if(0 == pCtrl->policy->get_Audit()) {
					report_Auditlog(pCtrl,true);
				}
			}
		}
	}

	return;
}

bool match_key(tag_AVisitCtrl * pCtrl,char * data, int len) {
	int  http_offset = 0;
	char * pTemp = NULL ;
	int  key_len = 0 ;
	printf("len = %d data_len = %d data = %s \n",len,strlen(data),data);
	for(int i = 0 ; i < (int)pCtrl->policy->m_keyArray.size(); i++) {
		std::string & strkey = pCtrl->policy->m_keyArray[i];
		printf("匹配: %s\n",strkey.c_str());
		key_len = strkey.length() ;
		for(http_offset = 0 ; http_offset < len ; http_offset++ ) {
			if(data[http_offset] == '\0') {
				break;
			}

			if(data[http_offset] == strkey[0]) {
				pTemp = data + http_offset ;
				///超长,不包含
				if((http_offset + key_len) >= len ) {
					break ;
				}
				///匹配上，返回。
				if(strncmp(pTemp,strkey.c_str(),key_len) == 0) {
					return true ;
				}
			}
		}
	}

	return false ;
}

void match_http(char *data, const char *head_str,const unsigned char head_len ,
		const char *tail_str,const unsigned char tail_len , char *buf, int total_len)
{
    int  i;
    int  http_offset = 0;
    int	  val_len;
    char head_tmp[STRSIZE];
	char tail_tmp[STRSIZE];

	while((head_tmp[0] = *data) != '\0') {
        if(http_offset > total_len) {
            return;
        }

        if(head_tmp[0] == *head_str) {
            for(i=1; i<head_len; i++) {
                data++;
                head_tmp[i]= *data;
                http_offset++;
                if(head_tmp[i] != *(head_str+i))
                    break;
            }

            if(i == head_len) {
                data++;
                http_offset++;
                break;
            }
        }

        data++;
        http_offset++;
    }


    val_len = 0;
    while((tail_tmp[0] = *data) != '\0') {
        if(http_offset > total_len) {
			return;
        }

        buf[val_len++] = tail_tmp[0];
        if(tail_tmp[0] == *tail_str) {
            for(i=1; i<tail_len; i++) {
                data++;
                tail_tmp[i] = *data;

                http_offset++;
                if(tail_tmp[i] != *(tail_str+i)) {
                    val_len = 0;
                    break;
                }
            }

            if(i == tail_len) {
                buf[val_len-1] = '\0';
                break;
            }
        }

        data++;
        http_offset++;
    }
}

int strJudgeQueMack(char *str, int len)
{
    int i;
    for(i=0; i<len; i++) {
        if('?' == str[i]) {
        	return 1;
        }
    }
    return 0;
}

///去掉域名后面的东西
int removeSlash(char *str, int len)
{
    int i;
    for(i=0; i<len; i++)  {
        if('/' == str[i]) {
        	if(i != len -1) {
        		str[i+1] = '\0';
        	}
        	return i+1;
        }
    }
    return len;
}

///对关键字进行转码
extern int code_convert(const char *from_charset,const char *to_charset,char *inbuf,int inlen,char *outbuf,int & outlen);
void   CPolicyHttpVisitctrl::transkey_to_utf8() {
	char buffer[512] = "";
	int  out_len = 512 ;
	for(int i = 0 ; i < (int)m_keyArray.size() ; i++) {
		out_len = 512;
		char * p = const_cast<char *>(m_keyArray[i].c_str());
		if(!code_convert("gb2312","utf-8",p,m_keyArray[i].length(),buffer,out_len)) {

		}
		m_keyArray[i] = buffer ;
	}

	if(m_Tips.length()) {
		out_len = 512;
		char * p = const_cast<char *>(m_Tips.c_str());
		if(!code_convert("gb2312","utf-8",p,m_Tips.length(),buffer,out_len)) {
			printf("printf: trans failed\n");
		}
		m_Tips = buffer ;
	}

}

