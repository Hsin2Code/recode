
/**
 * sys_conn_monitor.cpp
 *
 *  Created on: 2015-03-12
 *  Author: liu
 *
 *
 *  该文件包含了主机连接监控策略所需的所有函数；
 *
 */

using namespace std;

#include <unistd.h>
#include <stdio.h>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <linux/sockios.h>
#include <linux/netfilter.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>
#include <fstream>
#include <pthread.h>
#include <errno.h>
#include "linux_nfnetlink_compat.h"
#include "linux_nfnetlink.h"
#include "libnfnetlink.h"
#include "libnetfilter_queue.h"
#include "nfnetlink_queue.h"
#include "sys_conn_monitor.h"
#include "../../../include/Markup.h"
#include "../../../include/MCInterface.h"
#include "../../VCFCmdDefine.h"
#include "../../vrvprotocol/VRVProtocol.hxx"
#include "../../common/Commonfunc.h"
#include "../../vrvprotocol/VrvProtocol.h"


/*本地宏定义*/
//#define dbg
#define KIND_NO_SYSCONN_MONITOR 3701 
#define INTEVAL_RPT_EVT 50

/*本地全局变量*/
pthread_t tid_conn_monitor;

struct sysConnMonitor_t g_sysConnMonitor;

/*外部函数声明*/

/*本地使用的函数声明*/
static void *sysConnMonitor_main(void *arg);
static void sysConnMonitor_log_run_info(const char *log_content);
static void sysConnMonitor_rpt_evt_to_server(string logContent);
static void sysConnMonitor_log_evt_to_file(string &logContent);
static inline string sysConnMonitor_build_log_info(int kind, connInfo_t *log_info);
static inline void sysConnMonitor_audit_evt(connInfo_t *connInfo);
static void sysConnMonitor_update_policy(CSysConnMonitor *srcObj, struct sysConnMonitor_t *dstObj);
static int sysConnMonitor_nfq_init(struct sysConnMonitor_t *obj);
static void sysConnMonitor_nfq_free(struct sysConnMonitor_t *obj);
static int sysConnMonitor_packet_watch(struct nfq_q_handle *q_queue_handle, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
static void sysConnMonitor_init_vector(string &str, vector<ipNode> &ipV);
static void sysConnMonitor_generate_useful_vector(vector<ipNode> &srcV, vector<ipNode> &ipV);
static inline int sysConnMonitor_match_ip(char *ip, int port, vector<ipNode> &ipV, int protocol);
static void sysConnMonitor_log_vector(vector<ipNode> &ipV, int type);
static void sysConnMonitor_set_iptables(void);
static void sysConnMonitor_resume_iptables(int type);
static int sysConnMonitor_rst_tcp_conn(unsigned int seq, unsigned int ack_seq,unsigned int src_ip, unsigned int dst_ip, unsigned short src_prt, unsigned short dst_prt);
static inline void sysConnMonitor_getAppProctol(int port, string &protocol);
static void sysConnMonitor_getLocalIP(char *ipAddr);

/**
 * 类的构造方法
 */
CSysConnMonitor::CSysConnMonitor()
{
    enPolicytype type = SYSTEM_CONN_MONITOR;
	set_type(type);
	sysConnMonitor_log_run_info("constructor.");
}

/**
 * 类的析构函数
 */
CSysConnMonitor::~CSysConnMonitor()
{
    sysConnMonitor_log_run_info("destroy.");
}

/**
 *父类虚函数实现：copy函数
 */
void CSysConnMonitor::copy_to(CPolicy * pDest)
{
	sysConnMonitor_log_run_info("copy_to_start.");

   	CPolicy::copy_to(pDest);

    sysConnMonitor_update_policy(this, &g_sysConnMonitor);

	sysConnMonitor_log_run_info("copy_to end.");
}

/**
 *父类虚函数实现：策略导入函数
 */
bool CSysConnMonitor::import_xml(const char *pxml)
{
    char buf_policy[512] = {0};

    sysConnMonitor_log_run_info("import_xml start.");

    if(pxml == NULL)
    {
        sysConnMonitor_log_run_info("import_xml:pxml is null.");
        return false ;
    }

    CMarkup  xml ;
    if(!xml.SetDoc(pxml))
    {
        sysConnMonitor_log_run_info("import_xml:SetDoc failed.");
        return false ;
    }

    if(xml.FindElem("vrvscript"))
    {
        xml.IntoElem();
        std::string tmp_str;

        while(xml.FindElem("item"))
        {
            /*White_List*/
            white_List.clear();
            whiteVector.clear();
            whiteVectorToUse.clear();

            tmp_str = xml.GetAttrib("White_List");
            if(0 != tmp_str.length())
            {
                white_List.assign(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "White_List:%s", white_List.c_str());
                sysConnMonitor_log_run_info(buf_policy);

                sysConnMonitor_init_vector(white_List, whiteVector);

                sysConnMonitor_generate_useful_vector(whiteVectorToUse, whiteVector);
            }

            /*Black_List*/
            black_List.clear();
            blackVector.clear();
            blackVectorToUse.clear();

            tmp_str = xml.GetAttrib("Black_List");
            if(0 != tmp_str.length())
            {
                black_List.assign(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "Black_List:%s", black_List.c_str());
                sysConnMonitor_log_run_info(buf_policy);

                sysConnMonitor_init_vector(black_List, blackVector);

                sysConnMonitor_generate_useful_vector(blackVectorToUse, blackVector);
            }

            /*UpRegionService*/
            UpRegionService.clear();

            tmp_str = xml.GetAttrib("UpRegionService");
            if(0 != tmp_str.length())
            {
                UpRegionService.assign(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "UpRegionService:%s", UpRegionService.c_str());
                sysConnMonitor_log_run_info(buf_policy);
            }

            /*WriteLocalFile*/
            WriteLocalFile.clear();

            tmp_str = xml.GetAttrib("WriteLocalFile");
            if(0 != tmp_str.length())
            {
                WriteLocalFile.assign(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "WriteLocalFile:%s", WriteLocalFile.c_str());
                sysConnMonitor_log_run_info(buf_policy);
            }

            /*AuditMode*/
            AuditMode= 0;

            tmp_str = xml.GetAttrib("AuditMode");
            if(0 != tmp_str.length())
            {
                AuditMode = atoi(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "AuditMode:%d", AuditMode);
                sysConnMonitor_log_run_info(buf_policy);
            }

            /*ControlMode*/
            ControlMode = 0;

            tmp_str = xml.GetAttrib("ControlMode");
            if(0 != tmp_str.length())
            {
                ControlMode = atoi(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "ControlMode:%d", ControlMode);
                sysConnMonitor_log_run_info(buf_policy);
            }

        }
        xml.OutOfElem();
    }

    sysConnMonitor_log_run_info("import_xml end.");
    return CPolicy::import_xmlobj(xml);
}

static void sysConnMonitor_update_policy(CSysConnMonitor *srcObj, struct sysConnMonitor_t *dstObj)
{
    char buf_policy[512] = {0};
    string serverIp;

    sysConnMonitor_log_run_info("update_policy start.");

    if(NULL == srcObj || NULL == dstObj) 
    {
        return;
    }

    dstObj->white_List.clear();
    dstObj->white_List.assign(srcObj->white_List.c_str());

    snprintf(buf_policy, sizeof(buf_policy), "g_White_List:%s", dstObj->white_List.c_str());
    sysConnMonitor_log_run_info(buf_policy);

    dstObj->black_List.clear();
    dstObj->black_List.assign(srcObj->black_List.c_str());

    snprintf(buf_policy, sizeof(buf_policy), "g_black_List:%s", dstObj->black_List.c_str());
    sysConnMonitor_log_run_info(buf_policy);

    dstObj->UpRegionService.clear();
    dstObj->UpRegionService.assign(srcObj->UpRegionService.c_str());

    dstObj->WriteLocalFile.clear();
    dstObj->WriteLocalFile.assign(srcObj->WriteLocalFile.c_str());

    dstObj->AuditMode = srcObj->AuditMode; 

    dstObj->ControlMode= srcObj->ControlMode; 

    dstObj->whiteVector.clear(); 
    dstObj->whiteVector = srcObj->whiteVector; 
    sysConnMonitor_log_vector(dstObj->whiteVector, VECTOR_WHITE);

    dstObj->whiteVectorToUse.clear(); 
    dstObj->whiteVectorToUse = srcObj->whiteVectorToUse; 
    sysConnMonitor_log_vector(dstObj->whiteVectorToUse, VECTOR_WHITE_TO_USE);

    dstObj->blackVector.clear();
    dstObj->blackVector= srcObj->blackVector; 
    sysConnMonitor_log_vector(dstObj->blackVector, VECTOR_BLACK);

    dstObj->blackVectorToUse.clear(); 
    dstObj->blackVectorToUse = srcObj->blackVectorToUse; 
    sysConnMonitor_log_vector(dstObj->blackVectorToUse, VECTOR_BLACK_TO_USE);

    snprintf(dstObj->policy_id, LEN_POLICY_ID, "%d", srcObj->get_id()); 
    snprintf(buf_policy, sizeof(buf_policy), "g_policy-id:%s", dstObj->policy_id);
    sysConnMonitor_log_run_info(buf_policy);

    snprintf(dstObj->policy_name, LEN_POLICY_NAME, "%s", srcObj->get_name().c_str()); 
    snprintf(buf_policy, sizeof(buf_policy), "g_policy-name:%s", dstObj->policy_name);
    sysConnMonitor_log_run_info(buf_policy);

    memset(dstObj->local_ip, 0, LEN_IP_ADDR + 1);
    sysConnMonitor_getLocalIP(dstObj->local_ip);
    snprintf(buf_policy, sizeof(buf_policy), "g_policy-local-ip:%s", dstObj->local_ip);
    sysConnMonitor_log_run_info(buf_policy);

    memset(dstObj->server_ip, 0, LEN_IP_ADDR + 1);
	g_GetlcfgInterface()->get_lconfig(lcfg_srvip , serverIp);
    if(0 != serverIp.length())
    {
        snprintf(dstObj->server_ip, LEN_IP_ADDR + 1, "%s", serverIp.c_str());
        sysConnMonitor_log_run_info("getting server ip ok.");
    }
    else
    {
        sysConnMonitor_log_run_info("getting server ip failed.");
    }
    snprintf(buf_policy, sizeof(buf_policy), "g_policy-server-ip:%s", dstObj->server_ip);
    sysConnMonitor_log_run_info(buf_policy);

    sysConnMonitor_log_run_info("update_policy end.");
}

/**
 * 函数名:sysConnMonitor_log_run_info()
 * 说明:该函数将运行策略信息写入log文件;
 */
static void sysConnMonitor_log_run_info(const char *log_content)
{
	char log_info[2048] = {0};

	if(NULL == log_content)
	{
		return ;
	}
	
	snprintf(log_info, sizeof(log_info), "sys_conn_monitor:%s\n", log_content);

	g_GetlogInterface()->loglog(log_info);
}

/**
 * 函数名:sys_conn_monitor_init()
 * 说明:供外部调用的init函数;
 *  	成功返回true，失败返回false；
 */
bool sys_conn_monitor_init(void)
{
    bool ret = true;
    char buf_log[512] = {0};

    sysConnMonitor_log_run_info("init start.");

    /*初始化nfq*/
    if(0 != sysConnMonitor_nfq_init(&g_sysConnMonitor))
    {
        sysConnMonitor_log_run_info("init nfq err.");
        return false;
    }

    /*创建主线程*/
    if(0 == pthread_create(&tid_conn_monitor, NULL, sysConnMonitor_main, NULL))
    {
        snprintf(buf_log, sizeof(buf_log), "init:creating thread ok.tid:%lu", tid_conn_monitor);
        sysConnMonitor_log_run_info(buf_log);
        ret = true;
    }
    else
    {
        snprintf(buf_log, sizeof(buf_log), "init:creating thread err, err-code:%d", errno);
        sysConnMonitor_log_run_info(buf_log);
        ret = false;
    }

    sysConnMonitor_set_iptables();

    sysConnMonitor_log_run_info("init end.");
    return ret;
}

/**
 * 函数名:sys_conn_monitor_worker()
 * 说明:供外部调用的worker函数;
 *  	成功返回true，失败返回false；
 */
bool sys_conn_monitor_worker(CPolicy *pPolicy, void *pParam)
{
    CSysConnMonitor *pMe = (CSysConnMonitor*)pPolicy;

    if(SYSTEM_CONN_MONITOR != pPolicy->get_type())
    {
        return false;
    }

    if(NULL == pMe)
    {
        return false;
    }
    
    return true;
}

/**
 * 函数名:sys_conn_monitor_uninit()
 * 说明:供外部调用的uninit函数,完成策略停止时的资源清理;
 */
void sys_conn_monitor_uninit(void)
{
    int ret = 0;
    char buf_log[512] = {0};

    sysConnMonitor_log_run_info("uninit start.");

    if(0 != tid_conn_monitor)
    {
        sysConnMonitor_log_run_info("uninit cancelling main thread.");
        ret = pthread_cancel(tid_conn_monitor);
        if(0 != ret) 
        {
            snprintf(buf_log, sizeof(buf_log), "uninit:failed to cancel thread.err-code:%d", errno);
            sysConnMonitor_log_run_info(buf_log);
        }
        else
        {
            sysConnMonitor_log_run_info("uninit: cancelling main thread successfully.");
        }

        ret = pthread_join(tid_conn_monitor, NULL);
        if(0 != ret) 
        {
            snprintf(buf_log, sizeof(buf_log), "uninit:failed to join thread.err-code:%d", errno);
            sysConnMonitor_log_run_info(buf_log);
        }
        else
        {
            sysConnMonitor_log_run_info("uninit: joining main thread successfully.");
        }
    }

    sysConnMonitor_nfq_free(&g_sysConnMonitor);

    sysConnMonitor_resume_iptables(IPTB_INPUT);
    sysConnMonitor_resume_iptables(IPTB_OUTPUT);

    sysConnMonitor_log_run_info("uninit end.");
}

static void sysConnMonitor_set_iptables(void)
{
    char cmd[512] = {0};

    sysConnMonitor_log_run_info("set iptables start.");

    snprintf(cmd, sizeof(cmd), "iptables -I INPUT -p tcp -j QUEUE");
    system(cmd);

    snprintf(cmd, sizeof(cmd), "iptables -I INPUT -p udp -j QUEUE");
    system(cmd);

    snprintf(cmd, sizeof(cmd), "iptables -I OUTPUT -p tcp -j QUEUE");
    system(cmd);

    snprintf(cmd, sizeof(cmd), "iptables -I OUTPUT -p udp -j QUEUE");
    system(cmd);

    sysConnMonitor_log_run_info("set iptables end.");
}

static void sysConnMonitor_resume_iptables(int type)
{
    #define MAX_IPTB_COUNT 10
    FILE *pf = NULL;
    char cmd[512] = {0};
    char rm_cmd[512] = {0};
    char buf[512] ={0};
    int i = 0;
    int iptb_rm_flg[MAX_IPTB_COUNT] = {0};
    char log_buf[512] = {0};
    const char *iptb_type[2] = {"INPUT", "OUTPUT"};

    sysConnMonitor_log_run_info("resume iptables start.");
    
    if(type <0 || 2 < type)
    {
        sysConnMonitor_log_run_info("resume iptables, type err.");
        return;
    }
    
    snprintf(log_buf, sizeof(log_buf), "resuming iptb %s.",iptb_type[type]);
    sysConnMonitor_log_run_info(log_buf);

    snprintf(cmd, sizeof(cmd), "iptables -L %s", iptb_type[type]);

    pf = popen(cmd, "r");
    if(NULL == pf)
    {
        sysConnMonitor_log_run_info("resume iptables, popen err.");
        return;
    }

    memset(iptb_rm_flg, 0, sizeof(int)*MAX_IPTB_COUNT);
    while(NULL != fgets(buf, sizeof(buf), pf)) 
    {    
        buf[strlen(buf) - 1] = '\0';  
        if(0 == strncmp("QUEUE", buf, 5))
        {
            iptb_rm_flg[i-1] = 1;
            snprintf(log_buf, sizeof(log_buf), "iptb item %d is queue.", i-1);
            sysConnMonitor_log_run_info(log_buf);
        }
        i++;
    }

    for(i = MAX_IPTB_COUNT-1; i>0; i--)
    {
        if(iptb_rm_flg[i])
        {
            snprintf(rm_cmd, sizeof(rm_cmd), "iptables -D %s %d", iptb_type[type], i);
            system(rm_cmd);
            sysConnMonitor_log_run_info(rm_cmd);
        }

    }

    pclose(pf);

    sysConnMonitor_log_run_info("resume iptables end.");
}

static int sysConnMonitor_nfq_init(struct sysConnMonitor_t *obj)
{
    char buf_log[512] = {0};
    int ret = 0;

    if(NULL == obj)
    {
        return 1;
    }

	obj->queue_handle = NULL;
	obj->q_queue_handle = NULL;

	obj->queue_handle = nfq_open();
	if(NULL == obj->queue_handle)
	{
        snprintf(buf_log, sizeof(buf_log), "init:nerfilter queue open failed, err-code:%d", errno);
        sysConnMonitor_log_run_info(buf_log);
		return 1;
	}

	ret = nfq_unbind_pf(obj->queue_handle, AF_INET);
	if(ret < 0)
	{
        snprintf(buf_log, sizeof(buf_log), "init:nfq unbind_pf failed, err-code:%d", errno);
        sysConnMonitor_log_run_info(buf_log);
        sysConnMonitor_nfq_free(obj);
		return 1;
	}

	ret = nfq_bind_pf(obj->queue_handle, AF_INET);
	if(ret < 0)
	{
        snprintf(buf_log, sizeof(buf_log), "init:nfq bind_pf failed, err-code:%d", errno);
        sysConnMonitor_log_run_info(buf_log);
        sysConnMonitor_nfq_free(obj);
		return 1;
	}	

	obj->q_queue_handle = nfq_create_queue(obj->queue_handle, 0, sysConnMonitor_packet_watch, NULL);
	if(NULL == obj->q_queue_handle)
	{
        snprintf(buf_log, sizeof(buf_log), "init:creating netfilter queue failed, err-code:%d", errno);
        sysConnMonitor_log_run_info(buf_log);
        sysConnMonitor_nfq_free(obj);
		return 1;
	}

	ret = nfq_set_mode(obj->q_queue_handle, NFQNL_COPY_PACKET, 0xffff);
	if(ret < 0)
	{
        snprintf(buf_log, sizeof(buf_log), "init:nfq_set_mode failed, err-code:%d", errno);
        sysConnMonitor_log_run_info(buf_log);
        sysConnMonitor_nfq_free(obj);
		return 1;
	}

	obj->nfq_fd = nfq_fd(obj->queue_handle);
    snprintf(buf_log, sizeof(buf_log), "nfq init:nfq_fd:%d", obj->nfq_fd);
    sysConnMonitor_log_run_info(buf_log);

    return 0;

}

static void sysConnMonitor_nfq_free(struct sysConnMonitor_t *obj)
{
    sysConnMonitor_log_run_info("nfq free start.");

    if(NULL == obj)
    {
        return;
    }

    if(NULL != obj->q_queue_handle)
    {
        nfq_destroy_queue(obj->q_queue_handle);
        obj->q_queue_handle = NULL;
    }

    if(NULL != obj->queue_handle)
    {
        nfq_unbind_pf(obj->queue_handle, AF_INET);
        nfq_close(obj->queue_handle);
        obj->queue_handle = NULL;
    }
	
    sysConnMonitor_log_run_info("nfq free end.");
}

static void * sysConnMonitor_main(void *arg)
{
    int ret = 0;
    int rec_len = 0;
    char buf[4096] = {0};

    while(1)
    {
        usleep(1000);
        rec_len = recv(g_sysConnMonitor.nfq_fd, buf, sizeof(buf), 0);
        if(rec_len <= 0)
        {
            continue;
        }

        ret = nfq_handle_packet(g_sysConnMonitor.queue_handle, buf, rec_len);	
        if(ret != 0)
        {
            sysConnMonitor_log_run_info("main thread:nfq_handle_packet fail.");
        }
    }

    return NULL;
}

static inline string sysConnMonitor_build_log_info(int kind, connInfo_t *log_info)
{
    std::string audit_time;
    char str_audit_time[256]= {0};
	YCommonTool::get_local_time(str_audit_time);
    audit_time.assign(str_audit_time);
    string packtInfo;
    string str_srcIp;
    string str_dstIp;
    string str_port;
    string str_protocol;
    string str_appProtocol;

    char ch_action[8] = { '\0' };
    snprintf(ch_action, sizeof(ch_action), "%d", General_Behavior);
    char ch_risk[8] = { '\0' };
    snprintf(ch_risk, sizeof(ch_risk), "%d", Event_Message);
    char ContextChar[2048]= {0};

    if(NULL == log_info)
    {
        return "";
    }

    if(0 == strcmp(log_info->context, "黑名单") || 0 == strcmp(log_info->context, "非黑非白名单"))
    {
        snprintf(ch_action, sizeof(ch_action), "%d", Illegal_Behavior);
        snprintf(ch_risk, sizeof(ch_risk), "%d", Event_Critical);
    }

    std::string SysUserName;
    get_desk_user(SysUserName);
    if("" == SysUserName)
    {
        SysUserName.assign("root");
    }
    
    str_srcIp.assign(log_info->srcIp);
    str_dstIp.assign(log_info->dstIp);
    str_port.assign(log_info->port);
    str_protocol.assign(log_info->protocol);
    str_appProtocol.assign(log_info->applyProctol);;

    packtInfo += "<>host=<>Proctol=" + str_protocol;
    packtInfo += "<>ApplyProctol=" + str_appProtocol + "<>Programe=";
    packtInfo += "<>SrcIp=" + str_srcIp + "<>DestIp=" + str_dstIp;
    packtInfo += "<>Port=" + str_port;
    packtInfo += "<>time=" + audit_time;

    sprintf(ContextChar, "time=%s<>kind=%d<>policyid=%s<>policyname=%s%s<>context=%s<>pkid=<>pkiuser=<>pkiunit=<>KeyUserName=%s<>classaction=%s<>riskrank=%s",
         audit_time.c_str(), kind, g_sysConnMonitor.policy_id, g_sysConnMonitor.policy_name,
         packtInfo.c_str(), log_info->context, SysUserName.c_str(), ch_action, ch_risk);

    std::string audit_context;
    audit_context.assign(ContextChar);

    std::string audit_info;
    audit_info += audit_context;

	sysConnMonitor_log_run_info(audit_info.c_str());

	sysConnMonitor_log_run_info("build report info end.");

    return audit_info;
}

static void sysConnMonitor_rpt_evt_to_server(string logContent)
{
	tag_Policylog * plog = NULL;
	int ret = 0;
	char buf_run_info[128] = {0};

	/*审计信息上报服务器*/
	plog = (tag_Policylog *)malloc(sizeof(tag_Policylog) + logContent.length() + 1);
	if(NULL == plog)
	{
		sysConnMonitor_log_run_info("rpt to server:malloc err.");
		return ;
	}

	memset(plog, 0, sizeof(tag_Policylog) + logContent.length() + 1);
	plog->type = AGENT_RPTAUDITLOG;
	plog->what = 1;
	strncpy(plog->log, logContent.c_str(), logContent.length());

	ret = report_policy_log(plog, 0);
	snprintf(buf_run_info, sizeof(buf_run_info), "rpt to server ret:%d", ret);
	sysConnMonitor_log_run_info(buf_run_info);

	free(plog);
}

static int sysConnMonitor_packet_watch(struct nfq_q_handle *q_queue_handle, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    int id = 0;
    int data_len = 0;
    char dst[LEN_IP_ADDR + 1] = {0};
    char srcIp[LEN_IP_ADDR + 1] = {0};
    connInfo_t connInfo;

    unsigned char *play_data = NULL;
    unsigned int dst_len = 0;

    string processName;
    string appProctocol;
	
    struct iphdr *iph = NULL;
    struct tcphdr *tcph= NULL;
    struct udphdr *udph  = NULL;
    struct nfqnl_msg_packet_hdr *ph = NULL;
    
    ph = nfq_get_msg_packet_hdr(nfa);
    if(NULL != ph)
    {
        id = ntohl(ph->packet_id);
    }
	
    data_len = nfq_get_payload(nfa, &play_data);
    if(data_len <= 0)
    {
        return nfq_set_verdict(q_queue_handle, id, NF_ACCEPT, 0, NULL);
    }

    iph = (struct iphdr *)play_data;

    dst_len = strlen(inet_ntoa(*(struct in_addr *)(&iph->daddr)));

    if(dst_len <= LEN_IP_ADDR)
    {
        strncpy(dst, inet_ntoa(*(struct in_addr *)(&iph->daddr)), dst_len);
        dst[dst_len] = '\0';
    }
    else
    {			
        return nfq_set_verdict(q_queue_handle, id, NF_ACCEPT, 0, NULL);
    }

    strncpy(srcIp,	inet_ntoa(*(struct in_addr *)(&iph->saddr)), LEN_IP_ADDR);
    if(0 == strlen(srcIp))
    {
        return nfq_set_verdict(q_queue_handle, id, NF_ACCEPT, 0, NULL);
    }

#ifdef dbg
    printf("--------------%s(0x%x)-->%s(0x%x)\n", srcIp, iph->saddr, dst, iph->daddr);
    printf("-------------local-ip-%s(0x%x) serverip:%s(0x%x)\n",
          g_sysConnMonitor.local_ip, inet_addr(g_sysConnMonitor.local_ip),
          g_sysConnMonitor.server_ip, inet_addr(g_sysConnMonitor.server_ip));
#endif

    /*和本机无关的数据包不做检查*/
    if(iph->saddr != inet_addr(g_sysConnMonitor.local_ip) &&
       iph->daddr != inet_addr(g_sysConnMonitor.local_ip) 
      )
    {
        return nfq_set_verdict(q_queue_handle, id, NF_ACCEPT, 0, NULL);
    }

    /*目的地为本机的数据包不做检查*/
    if(iph->daddr == inet_addr(g_sysConnMonitor.local_ip))
    {
        return nfq_set_verdict(q_queue_handle, id, NF_ACCEPT, 0, NULL);
    }

    /*和服务器通信的数据包不做检查*/
    if(iph->saddr == inet_addr(g_sysConnMonitor.server_ip) ||
       iph->daddr == inet_addr(g_sysConnMonitor.server_ip)
      )
    {
        return nfq_set_verdict(q_queue_handle, id, NF_ACCEPT, 0, NULL);
    }
    
    memset(&connInfo, 0, sizeof(connInfo_t));
    strncpy(connInfo.srcIp, srcIp, LEN_IP_ADDR);
    strncpy(connInfo.dstIp, dst, LEN_IP_ADDR);

    switch(iph->protocol)
    {
        case IPPROTO_TCP:
        {
            tcph = (struct tcphdr *)(play_data + (iph->ihl)*4);

#ifdef dbg
			processName = getProcessName(ntohs(tcph->source));
			printf("processName is %s\n", processName.c_str());
#endif
            /*whitelist*/
            if(sysConnMonitor_match_ip(dst, ntohs(tcph->dest), g_sysConnMonitor.whiteVectorToUse, 1) &&
              (g_sysConnMonitor.ControlMode & 1))
            {				
                if(g_sysConnMonitor.AuditMode & 1)
                {
                    appProctocol.clear();
                    sysConnMonitor_getAppProctol(htons(tcph->dest), appProctocol);

                    strncpy(connInfo.protocol, "tcp", LEN_CONN_INFO_ITEM);
                    snprintf(connInfo.port, LEN_CONN_INFO_ITEM, "%d", ntohs(tcph->dest));
                    strncpy(connInfo.context, "白名单", LEN_CONN_INFO_ITEM/2);
                    strncpy(connInfo.applyProctol, appProctocol.c_str(), LEN_CONN_INFO_ITEM);

                    sysConnMonitor_audit_evt(&connInfo);
                    }
            }
            else 
            if(sysConnMonitor_match_ip(dst, ntohs(tcph->dest),g_sysConnMonitor.blackVectorToUse, 1) && 
              (g_sysConnMonitor.ControlMode & 2))
            {
                sysConnMonitor_rst_tcp_conn(tcph->seq, tcph->ack_seq, iph->daddr, iph->saddr, tcph->dest, tcph->source);

                if(g_sysConnMonitor.AuditMode & 2)
                {
                    appProctocol.clear();
                    sysConnMonitor_getAppProctol(htons(tcph->dest), appProctocol);

                    strncpy(connInfo.protocol, "tcp", LEN_CONN_INFO_ITEM);
                    snprintf(connInfo.port, LEN_CONN_INFO_ITEM, "%d", ntohs(tcph->dest));
                    strncpy(connInfo.context, "黑名单", LEN_CONN_INFO_ITEM/2);
                    strncpy(connInfo.applyProctol, appProctocol.c_str(), LEN_CONN_INFO_ITEM);

                    sysConnMonitor_audit_evt(&connInfo);
                }
							
                return nfq_set_verdict(q_queue_handle, id, NF_DROP, 0, NULL);
            }
            else if(0 != (g_sysConnMonitor.ControlMode&4))
            {
                static int tcp_count = 0;

                /*审计非黑非白记录*/
                if(g_sysConnMonitor.AuditMode & 4)
                {
                    tcp_count ++;
                    if(INTEVAL_RPT_EVT <= tcp_count)
                    {
                        tcp_count = 0;
                        appProctocol.clear();
                        sysConnMonitor_getAppProctol(htons(tcph->dest), appProctocol);

                        strncpy(connInfo.protocol, "tcp", LEN_CONN_INFO_ITEM);
                        snprintf(connInfo.port, LEN_CONN_INFO_ITEM, "%d", ntohs(tcph->dest));
                        strncpy(connInfo.context, "非黑非白名单", LEN_CONN_INFO_ITEM/2);
                        strncpy(connInfo.applyProctol, appProctocol.c_str(), LEN_CONN_INFO_ITEM);

                        sysConnMonitor_audit_evt(&connInfo);
                    }
                }

                /*拒绝非黑非白记录*/
                if(g_sysConnMonitor.AuditMode & 8)
                {
                    return nfq_set_verdict(q_queue_handle, id, NF_DROP, 0, NULL);
                }
            }

            break;
        }
        case IPPROTO_UDP:
        {
            udph = (struct udphdr *)(play_data + (iph->ihl)*4);

            if(sysConnMonitor_match_ip(dst, ntohs(udph->dest), g_sysConnMonitor.whiteVectorToUse, 2) &&
              (g_sysConnMonitor.ControlMode & 1))
            {				
                /*udp白名单*/
                if(g_sysConnMonitor.AuditMode & 1)
                {
                    appProctocol.clear();
                    sysConnMonitor_getAppProctol(htons(udph->dest), appProctocol);

                    strncpy(connInfo.protocol, "udp", LEN_CONN_INFO_ITEM);
                    snprintf(connInfo.port, LEN_CONN_INFO_ITEM, "%d", ntohs(udph->dest));
                    strncpy(connInfo.context, "白名单", LEN_CONN_INFO_ITEM/2);
                    strncpy(connInfo.applyProctol, appProctocol.c_str(), LEN_CONN_INFO_ITEM);

                    sysConnMonitor_audit_evt(&connInfo);
               }
							
            }
            else
            if(sysConnMonitor_match_ip(dst, ntohs(udph->dest),g_sysConnMonitor.blackVectorToUse, 2) && 
              (g_sysConnMonitor.ControlMode & 2))
            {
                /*udp黑名单*/
                if(g_sysConnMonitor.AuditMode & 2)
                {
                    appProctocol.clear();
                    sysConnMonitor_getAppProctol(htons(udph->dest), appProctocol);

                    strncpy(connInfo.protocol, "udp", LEN_CONN_INFO_ITEM);
                    snprintf(connInfo.port, LEN_CONN_INFO_ITEM, "%d", ntohs(udph->dest));
                    strncpy(connInfo.context, "黑名单", LEN_CONN_INFO_ITEM/2);
                    strncpy(connInfo.applyProctol, appProctocol.c_str(), LEN_CONN_INFO_ITEM);

                    sysConnMonitor_audit_evt(&connInfo);
               }
							
               return nfq_set_verdict(q_queue_handle, id, NF_DROP, 0, NULL);
            }
            else if(0 != (g_sysConnMonitor.ControlMode&4))
            {
                static int udp_count = 0;

                /*审计udp非黑非白名单*/
                if(g_sysConnMonitor.AuditMode & 4)
                {
                    udp_count ++;
                    if(INTEVAL_RPT_EVT <= udp_count)
                    {
                        udp_count = 0;
                        appProctocol.clear();
                        sysConnMonitor_getAppProctol(htons(udph->dest), appProctocol);

                        strncpy(connInfo.protocol, "udp", LEN_CONN_INFO_ITEM);
                        snprintf(connInfo.port, LEN_CONN_INFO_ITEM, "%d", ntohs(udph->dest));
                        strncpy(connInfo.context, "非黑非白名单", LEN_CONN_INFO_ITEM/2);
                        strncpy(connInfo.applyProctol, appProctocol.c_str(), LEN_CONN_INFO_ITEM);

                        sysConnMonitor_audit_evt(&connInfo);
                    }
                }

                /*拒绝非黑非白记录*/
                if(g_sysConnMonitor.AuditMode & 8)
                {
                    return nfq_set_verdict(q_queue_handle, id, NF_DROP, 0, NULL);
                }
            }
						
            break;
        }
        default:
            break;
    }
	
    return nfq_set_verdict(q_queue_handle, id, NF_ACCEPT, 0, NULL);
}

static void split(char str[], const char *delim, vector<string> &strV)
{
    if(NULL== str || NULL == delim)
    {
        perror("para pointer is null!\n");
    }

    char *p = NULL;
    p = strtok(str, delim);
    while(p)
    {
        string s(p);
        strV.push_back(s);
        p = strtok(NULL, delim);
    }
}

static void sysConnMonitor_init_vector(string &str, vector<ipNode> &ipV)
{
    unsigned int i = 0;

    vector<string> strV;
    char * arr = new char[str.length()+1];
    strcpy(arr, str.c_str());
    split(arr, ";", strV);
    delete [] arr;

    vector<string> str2V;
    for(i=0; i<strV.size(); i++)
    {
        char *strTemp = new char[strV[i].length()+1];
        strcpy(strTemp, strV[i].c_str());
        split(strTemp, ",", str2V);
        delete [] strTemp;
    }

    for(i = 0; i<str2V.size(); i = i + 4)
    {

        ipNode ip;
		
        ip.proctol = atoi(str2V[i].c_str());
        ip.srcIpRange = str2V[i+1];
        ip.dstIpRange = str2V[i+2];
        ip.dstportRange = str2V[i+3];

        ipV.push_back(ip);
    }
}

static unsigned long int ipToValue(char *ip)
{
    unsigned long int value = 0;
    struct in_addr addr = {0};
    int result = 0;
    char buf_log[512] = {0};
    
    if(NULL == ip)
    {
        sysConnMonitor_log_run_info("ipToValue:null ptr.");
        return 0;
    }

    result = inet_aton(ip, &addr);
    if(0 == result)
    {
        snprintf(buf_log, sizeof(buf_log), "ipToValue err,ip:%s", ip);
        sysConnMonitor_log_run_info(buf_log);
    }
    else
	{
        memcpy(&value, &addr.s_addr, 4);
    }
    
    return value;
}

static int localIpIsInRange(char *ip, string &ipRange)
{
    unsigned long int ipValue = 0;
    unsigned long int startValue = 0;
    unsigned long int endValue = 0;
    int ret = 0;
    
    if(NULL == ip)
    {
        sysConnMonitor_log_run_info("localIpIsInRange:null ptr.");
        return ret;
    }

    char *ptemp = new char[ipRange.length()+1];
    strcpy(ptemp, ipRange.c_str());

    char start[1024] = {0};
    char end[1024] = {0};
    char *p = NULL;
    p = strtok(ptemp, "-");
    if(NULL != p)
    {
        strcpy(start, p);
    }
	
    p = strtok(NULL, "-");
    if(NULL != p)
    {
        strcpy(end, p);
    }
    else
	{
        strcpy(end, start);
    }

	ipValue = ntohl(ipToValue(ip));
    startValue = ntohl(ipToValue(start));
    endValue = ntohl(ipToValue(end));

    delete [] ptemp;
    if(startValue > endValue)
    {
        int temp = startValue;
        startValue = endValue;
        endValue = temp;
    }
    if((ipValue >= startValue) && (ipValue <= endValue))
    {
        ret = 1;
    }

    return ret;
}

static void sysConnMonitor_getLocalIP(char *ipAddr)
{
	using namespace YCommonTool;
	std::list<std::string> niclist;
	std::string  ip;

    if(NULL == ipAddr)
    {
        return;
    }

	get_Nicinfo(niclist);

	std::list<std::string>::iterator  iter = niclist.begin();

	while(iter != niclist.end())
	{
		ip =  get_ip(*iter);
        if(0 != ip.length())
        {
		    strncpy(ipAddr, ip.c_str(), LEN_IP_ADDR);
            break;
        }

		iter++ ;
	}
}

static void sysConnMonitor_generate_useful_vector(vector<ipNode> &srcV, vector<ipNode> &ipV)
{
    char ip[LEN_IP_ADDR + 1] = {0};
    char buf_log[512] = {0};
    unsigned int i = 0;

    sysConnMonitor_getLocalIP(ip);
    
    snprintf(buf_log, sizeof(buf_log), "localip:%s", ip);
    sysConnMonitor_log_run_info(buf_log);
	
    for(i=0; i<ipV.size(); i++)
    {
        if(localIpIsInRange(ip, ipV[i].srcIpRange))
        {
            srcV.push_back(ipV[i]);
        }
        if(0 == ipV[i].srcIpRange.compare("0.0.0.0"))
        {
            srcV.push_back(ipV[i]);
        }
    }
}

static inline int sysConnMonitor_match_port(int port, string &portRange)
{
    char *ptemp = new char[portRange.length()+1];
    strcpy(ptemp, portRange.c_str());

    char start[100] = {0};
    char end[100] = {0};
    char *p = NULL;

    p = strtok(ptemp,"-");
    if(NULL != p)
    {
        strcpy(start, p);
    }
    p = strtok(NULL, "-");
    if(NULL != p)
    {
        strcpy(end, p);
    }
    else
    {
        strcpy(end, start);
    }
    delete [] ptemp;
    int startValue = atoi(start);
    int endValue = atoi(end);
    if(startValue > endValue)
    {
        int temp = startValue;
        startValue = endValue;
        endValue = temp;
    }
    if(port >= startValue && port <= endValue)
    {
        return  1;
    }

    return 0;
}

static inline int sysConnMonitor_match_ip(char *ip, int port, vector<ipNode> &ipV, int protocol)
{
    unsigned int i = 0;
	
    for(i = 0; i<ipV.size(); i++)
    {
        if(ipV[i].proctol == protocol)
        {
            if(0 == ipV[i].dstIpRange.compare("0.0.0.0") &&  sysConnMonitor_match_port(port, ipV[i].dstportRange))
            {
                return 1;
            }

            if(localIpIsInRange(ip, ipV[i].dstIpRange) && sysConnMonitor_match_port(port, ipV[i].dstportRange))
            {
                return 1;
            }
        }
    }

	return 0;
}

static void sysConnMonitor_log_evt_to_file(string &logContent)
{
    fstream fs;
    fs.open("SysConnMonitor.txt", fstream::out | fstream::app);
    fs<<logContent;
    fs.close();
}

static void sysConnMonitor_log_vector(vector<ipNode> &ipV, int type)
{
    unsigned int i = 0;
    char log_buf[2048] = {0};
    char str_idx[10] = {0};
    const char *p_type[2]= {"tcp", "udp"};
    const char *vector_type[4]= {"white-vec",
                           "white-vec-to-use",
                           "black-vec",
                           "black-vec-to-use"
                          };

    snprintf(log_buf, sizeof(log_buf), "%s:", vector_type[type]);

    for(i = 0; i<ipV.size(); i++)
    {
        snprintf(str_idx, sizeof(str_idx), "%d:%s:", i, p_type[ipV[i].proctol - 1]);
        strncat(log_buf, str_idx, sizeof(log_buf) - strlen(log_buf));

        strncat(log_buf, ipV[i].srcIpRange.c_str(), sizeof(log_buf) - strlen(log_buf));
        strncat(log_buf, "->", sizeof(log_buf) - strlen(log_buf));
        strncat(log_buf, ipV[i].dstIpRange.c_str(), sizeof(log_buf) - strlen(log_buf));
        strncat(log_buf, " p:", sizeof(log_buf) - strlen(log_buf));
        strncat(log_buf, ipV[i].srcportRange.c_str(), sizeof(log_buf) - strlen(log_buf));
        strncat(log_buf, ":", sizeof(log_buf) - strlen(log_buf));
        strncat(log_buf, ipV[i].dstportRange.c_str(), sizeof(log_buf) - strlen(log_buf));
        strncat(log_buf, "\n", sizeof(log_buf) - strlen(log_buf));
    }
    
    sysConnMonitor_log_run_info(log_buf);
}

static unsigned short in_cksum(unsigned short *addr,int len)
{
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *(u_char *)(&answer) = *(u_char *)w ;
        sum += answer;
    }

    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return(answer);
}

static int sysConnMonitor_rst_tcp_conn(unsigned int seq, unsigned int ack_seq,unsigned int src_ip, unsigned int dst_ip, unsigned short src_prt, unsigned short dst_prt)
{
    int one=1;

    int rawsocket=0;

    char packet[ sizeof(struct tcphdr) + sizeof(struct iphdr) +1 ] = {0};

    struct iphdr *ipheader = (struct iphdr *)packet;

    struct tcphdr *tcpheader = (struct tcphdr *) (packet + sizeof(struct iphdr));

    tcp_phdr_t pseudohdr;

    char tcpcsumblock[ sizeof(tcp_phdr_t) + 20 ] = {0};

    struct sockaddr_in dstaddr;

    memset(&packet, 0, sizeof(packet));
    memset(&dstaddr, 0, sizeof(dstaddr));
	
    dstaddr.sin_family = AF_INET;
    dstaddr.sin_port = dst_prt;
    dstaddr.sin_addr.s_addr = dst_ip;

    if ( (rawsocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
    {
        perror("TCP_RST_send():socket()");
        return -1;
    }

    if( setsockopt(rawsocket, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        perror("TCP_RST_send():setsockopt()");
        return -1;
    }

    ipheader->ihl = 5;
    ipheader->version = 4;
    ipheader->tos = 0;
    ipheader->tot_len = htons( sizeof (struct iphdr) + sizeof (struct tcphdr) );
    ipheader->frag_off = 0;
    ipheader->ttl = 64;
    ipheader->protocol = 6;
    ipheader->check = 0;
    ipheader->id = htons( 0xabcd );
    ipheader->saddr = src_ip;
    ipheader->daddr = dst_ip;

    tcpheader->seq = 0;
    //tcpheader->seq = ack_seq;
    tcpheader->ack_seq = ntohl(htonl(seq) + 1);    
    tcpheader->res1 = 0;
    tcpheader->doff = 5;
	tcpheader->rst = 1;
	//tcpheader->syn = 1;
	tcpheader->ack = 1;
	
    tcpheader->window = 0;

	tcpheader->urg_ptr = 0;
    tcpheader->source = src_prt;
    tcpheader->dest = dst_prt;
    tcpheader->check=0;

    pseudohdr.src = ipheader->saddr;
    pseudohdr.dst = ipheader->daddr;
    pseudohdr.zero = 0;
    pseudohdr.protocol = ipheader->protocol;
    pseudohdr.tcplen = htons( sizeof(struct tcphdr) );
    
    memcpy(tcpcsumblock, &pseudohdr, sizeof(tcp_phdr_t));
    memcpy(tcpcsumblock+sizeof(tcp_phdr_t),tcpheader, sizeof(struct tcphdr));
    
    tcpheader->check = in_cksum((unsigned short *)(tcpcsumblock), sizeof(tcpcsumblock));
       
    if ( sendto(rawsocket, packet, ntohs(ipheader->tot_len), 0,
                (struct sockaddr *) &dstaddr, sizeof (dstaddr)) < 0)
    {
        return -1;
    }

    close(rawsocket);
    return 0;
}

static inline void sysConnMonitor_getAppProctol(int port, string &protocol)
{
    char ch_port[16] = {0};
    sprintf(ch_port,"%d",port);
    string str(ch_port);
    string str_cmd = "cat /etc/services|grep " + str + "|awk '{print $1}'";
    FILE *fp = NULL;

    fp = popen(str_cmd.c_str(),"r");
    if(NULL != fp)
    {
        char ch_tmp[32] = {0};
        fgets(ch_tmp,31,fp);
        if(NULL != strstr(ch_tmp,"#"))
        {
            memset(ch_tmp, 0, sizeof(ch_tmp));
            fgets(ch_tmp,31,fp);
        }

        if(0 != strcmp(ch_tmp,""))
        {
            char buf[32] = {0};
            sscanf(ch_tmp,"%[^\n]",buf);
            protocol.assign(buf);
        }
        else
        {
            protocol = "未知协议类型";
        }
    }
    pclose(fp);
    return;
}

static inline void sysConnMonitor_audit_evt(connInfo_t *connInfo)
{
    string logContent;

    logContent.clear();
    logContent = sysConnMonitor_build_log_info(KIND_NO_SYSCONN_MONITOR, connInfo);

    if(0 == g_sysConnMonitor.UpRegionService.compare("1"))
    {
        sysConnMonitor_rpt_evt_to_server(logContent);
    }

    if(0 == g_sysConnMonitor.WriteLocalFile.compare("1"))
    {
        logContent += STRITEM_TAG_END; 
        sysConnMonitor_log_evt_to_file(logContent);
    }
}

