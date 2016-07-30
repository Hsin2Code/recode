
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include "../../vrvprotocol/VRVProtocol.hxx"
#include "../../vrvprotocol/VRVProtocolEx.hxx"
#include "../../common/Commonfunc.h"
#include "../../vrcport_tool.h"
#include "../../VCFCmdDefine.h"
#include "../../../include/MCInterface.h"
#include "connect_gateway_affirm.h"

using namespace std;

#define LEN_IP_ADDR 15
#define LEN_GW_POLICY_ITEM 32
#define MAX_NUM_GATEWAY 10
#define LEN_REG_INFO_ITEM 64 

struct ip_addr_t
{
    char addr[LEN_IP_ADDR + 1];
};

struct gw_policy_t
{
    char rpt_interval[LEN_GW_POLICY_ITEM + 1];/*认证包发送间隔*/
    char id_mode[LEN_GW_POLICY_ITEM + 1];/*认证模式*/
    char def_user_name[LEN_GW_POLICY_ITEM + 1];/*默认的用户名*/
    char def_user_pw[LEN_GW_POLICY_ITEM + 1];/*默认用户名的密码*/
    int flg_use_def_login;/*启用默认用户登录标志*/
    int flg_show_tray_icon;/*显示托盘标志*/
    int num_gw;/*网关数目*/
    struct ip_addr_t gw_ip[MAX_NUM_GATEWAY];/*用于存储网关ip*/
};

struct edpClt_reg_info_t
{
    char sid[LEN_REG_INFO_ITEM + 1];/*本机id*/
    char nicname[LEN_REG_INFO_ITEM +1];
    char ip[LEN_IP_ADDR + 1];/*本机和edpServer通信的ip地址*/
    char mac[LEN_REG_INFO_ITEM + 1];/*本机的mac地址*/
    char dev_name[LEN_REG_INFO_ITEM + 1];/*本机名称*/
    char reg_user[LEN_REG_INFO_ITEM + 1];/*注册时填写的用户信息*/
    char srv_ip[LEN_IP_ADDR + 1];/*edpServer ip*/
    int reboot;/*标记是首次注册发送的注册信息(2),还是重启后发送的注册信息(1)*/
    char reg_dep[LEN_REG_INFO_ITEM + 1];/*注册时填写的部门信息*/
    char tel[LEN_REG_INFO_ITEM + 1];/*注册时填写的电话信息*/
};

#define CONN_GATEWAY_AFFIRM_WDIR "./gateway_cfg_dat/"
#define CONN_GATEWAY_AFFIRM_CIGPATH "./gateway_cfg_dat/connect_gateway_affirm.cfg"
#define CONN_GATEWAY_AFFIRM_REGISTER "./gateway_cfg_dat/connect_gateway_affirm_register.cfg"
#define CONN_GATEWAY_AFFIRM_CLIENT_NAME "edpNclt"

//extern int code_convert(const char *from_charset,const char *to_charset,char *inbuf,int inlen,char *outbuf,int & outlen);

static unsigned int old_crcvalue;
static CConnectGatewayAffirm *g_pConnectGatewayAffirm=NULL;

static void connect_gateway_affirm_log_info(const char *log_content);

vector<string> asplit(string str, string pattern)
{
    string::size_type pos;
    vector<string> result;

    str+=pattern;
    unsigned int size=str.size();
    for(unsigned int i=0; i<size; i++)
    {
        pos=str.find(pattern,i);
        if(pos<size)
        {
            string s=str.substr(i,pos-i);
            result.push_back(s);
            i=pos+pattern.size()-1;
        }
    }
    return result;
}

int nclt_detect_process(char * process_name)
{
    char buf[512]={0};
    char ps[128]={0};

    sprintf(ps, "pgrep %s", process_name);
    FILE *fp = popen(ps, "r");
    if(NULL == fp) 
    {
        return -1;
    }
    int i = 0 ;
    while(fgets(buf, sizeof(buf) - 1, fp)) 
    {
        i++ ;
    }
    pclose(fp);

    return i ;
}

int read_gateway_config()
{
    return 0;
}

int write_gateway_config()
{
    FILE *fp=NULL;
    int rnt_wr=0;
    vector<string> vec_ipaddr;
    char log_buf[128] = {0};

    connect_gateway_affirm_log_info("write gw-cfg starting...");

    fp=fopen(CONN_GATEWAY_AFFIRM_CIGPATH,"wb");
    if(fp == NULL)
    {
        snprintf(log_buf, sizeof(log_buf), "open %s err,code:%d", CONN_GATEWAY_AFFIRM_CIGPATH, errno);
        connect_gateway_affirm_log_info(log_buf);
        return -1;
    }

    struct gw_policy_t stGwpolicy;
    memset(&stGwpolicy,0,sizeof(struct gw_policy_t));
    strcpy(stGwpolicy.rpt_interval,g_pConnectGatewayAffirm->IntervalTime.c_str());

    snprintf(log_buf, sizeof(log_buf), "gw-ip: %s", g_pConnectGatewayAffirm->GatewayIP.c_str());
    connect_gateway_affirm_log_info(log_buf);

    vec_ipaddr=asplit(g_pConnectGatewayAffirm->GatewayIP,";");
    stGwpolicy.num_gw = vec_ipaddr.size() - 1;
    int loop_num = (stGwpolicy.num_gw>MAX_NUM_GATEWAY? MAX_NUM_GATEWAY:stGwpolicy.num_gw);
    snprintf(log_buf, sizeof(log_buf), "gw-num: %d", stGwpolicy.num_gw);
    connect_gateway_affirm_log_info(log_buf);

    for(int i=0; i< loop_num ; i++)
    {
        strcpy(stGwpolicy.gw_ip[i].addr, vec_ipaddr[i].c_str());
    }
    strcpy(stGwpolicy.id_mode,g_pConnectGatewayAffirm->IdentifyMode.c_str());
    stGwpolicy.flg_use_def_login=atoi(g_pConnectGatewayAffirm->UseDefaultUserLogin.c_str());
    strcpy(stGwpolicy.def_user_name,g_pConnectGatewayAffirm->DefaultUser1Name.c_str());
    strcpy(stGwpolicy.def_user_pw,g_pConnectGatewayAffirm->DefaultUser1Pass.c_str());
    stGwpolicy.flg_show_tray_icon=atoi(g_pConnectGatewayAffirm->ShowTrayIcon.c_str());
    rnt_wr=fwrite(&stGwpolicy,sizeof(struct gw_policy_t),1,fp);
    if(rnt_wr != 1)
    {
        snprintf(log_buf, sizeof(log_buf), "write %s err,code:%d", CONN_GATEWAY_AFFIRM_CIGPATH, errno);
        connect_gateway_affirm_log_info(log_buf);
        fclose(fp);
	    return -1;
    }
    fclose(fp);
    connect_gateway_affirm_log_info("write gw-cfg succ.");

    return 0;
}

void cleanup_configfile()
{
    char cmd_buf[128] = {0};
    char log_buf[128] = {0};

    if( -1 != access(CONN_GATEWAY_AFFIRM_CIGPATH,F_OK))
    {
        if(0 != unlink(CONN_GATEWAY_AFFIRM_CIGPATH))
        {
            snprintf(log_buf, sizeof(log_buf), "removing old policy file:%s, err", CONN_GATEWAY_AFFIRM_CIGPATH);
            connect_gateway_affirm_log_info(log_buf);
        }
        else
        {
            snprintf(log_buf, sizeof(log_buf), "removing old policy file:%s ok", CONN_GATEWAY_AFFIRM_CIGPATH);
            connect_gateway_affirm_log_info(log_buf);
        }
    }
}

void cleanup_registerfile()
{
    char cmd_buf[128] = {0};
    char log_buf[128] = {0};
    int ret = 0;

    if( -1 != access(CONN_GATEWAY_AFFIRM_REGISTER,F_OK))
    {
        ret = unlink(CONN_GATEWAY_AFFIRM_REGISTER);

        snprintf(log_buf, sizeof(log_buf), "removing reginfo file:%s,ret:%d", cmd_buf, ret);
        connect_gateway_affirm_log_info(log_buf);
    }
}

void setonlyworkpwd()
{
    char cmd[128] = {0};
    char log_buf[128] = {0};
    int ret = 0;

    if(access(CONN_GATEWAY_AFFIRM_WDIR,0))
    {
        mkdir(CONN_GATEWAY_AFFIRM_WDIR,0777);        

        snprintf(cmd, sizeof(cmd), "chmod 777 %s", CONN_GATEWAY_AFFIRM_WDIR);
        ret = system(cmd);

        snprintf(log_buf, sizeof(log_buf), "%s not exist, created with ret:%d.", CONN_GATEWAY_AFFIRM_WDIR, ret);
        connect_gateway_affirm_log_info(log_buf);
    }
    else
    {
        snprintf(log_buf, sizeof(log_buf), "%s already exist.", CONN_GATEWAY_AFFIRM_WDIR);
        connect_gateway_affirm_log_info(log_buf);
    }
}

bool connect_gateway_affirm_init() 
{
    struct edpClt_reg_info_t stRegInfos;
    string nclt_sid;
    string nclt_ip;
    string nclt_mac;
    string nclt_devname;
    string nclt_regusr;
    int edp_reboot = 2;
    string nclt_regdep;
    string nclt_regtel;
    string regui_str;
    string nclt_regnic;
    vector<string> vecregui;
    char log_buf[128] = {0};

    connect_gateway_affirm_log_info("init starting.");

    old_crcvalue = 0;

    setonlyworkpwd();

    memset(&stRegInfos, 0, sizeof(struct edpClt_reg_info_t));

    g_GetlcfgInterface()->get_lconfig(lcfg_devid,nclt_sid);
    strncpy(stRegInfos.sid,nclt_sid.c_str(),LEN_REG_INFO_ITEM);
    snprintf(log_buf, sizeof(log_buf), "sid:%s", stRegInfos.sid);
    connect_gateway_affirm_log_info(log_buf);

    g_GetlcfgInterface()->get_lconfig(lcfg_regip,nclt_ip);
    strncpy(stRegInfos.ip, nclt_ip.c_str(), LEN_IP_ADDR);
    snprintf(log_buf, sizeof(log_buf), "ip:%s", stRegInfos.ip);
    connect_gateway_affirm_log_info(log_buf);

    g_GetlcfgInterface()->get_lconfig(lcfg_regmac,nclt_mac);
    strncpy(stRegInfos.mac,nclt_mac.c_str(),LEN_REG_INFO_ITEM);
    snprintf(log_buf, sizeof(log_buf), "mac:%s", stRegInfos.mac);
    connect_gateway_affirm_log_info(log_buf);

    g_GetlcfgInterface()->get_lconfig(lcfg_regnic,nclt_regnic);
    strncpy(stRegInfos.nicname, nclt_regnic.c_str(),LEN_REG_INFO_ITEM);
    snprintf(log_buf, sizeof(log_buf), "ifname:%s", stRegInfos.nicname);
    connect_gateway_affirm_log_info(log_buf);

    g_GetlcfgInterface()->get_lconfig(lcfg_srvip,nclt_ip);
    strncpy(stRegInfos.srv_ip, nclt_ip.c_str(), LEN_IP_ADDR);
    snprintf(log_buf, sizeof(log_buf), "srvip:%s", stRegInfos.srv_ip);
    connect_gateway_affirm_log_info(log_buf);

    stRegInfos.reboot = edp_reboot;

    g_GetlcfgInterface()->get_lconfig(lcfg_reguiStr,regui_str);
    cout<<"@@@@@@@@@@@@@@@@@@@@@@@@get regui infos : "<< regui_str <<endl;
    vecregui = asplit(regui_str,STRITEM_TAG_END);
    cout<<"vecregui[1]: "<<vecregui[1]<<endl;
    vector<string> vecstr_tmp1 = asplit(vecregui[1],"=");
    nclt_regusr = vecstr_tmp1[1];
    strcpy(stRegInfos.reg_user,nclt_regusr.c_str());
    snprintf(log_buf, sizeof(log_buf), "reg_user:%s", stRegInfos.reg_user);
    connect_gateway_affirm_log_info(log_buf);

    cout<<"nclt_regusr: "<<nclt_regusr<<endl;
    cout<<"vecregui[7]: "<<vecregui[7]<<endl;
    vector<string> vecstr_tmp2 = asplit(vecregui[7],"=");
    nclt_regdep = vecstr_tmp2[1];
    strcpy(stRegInfos.reg_dep,nclt_regdep.c_str());
    cout<<"nclt_regdep: "<<nclt_regdep<<endl;
    cout<<"vecregui[9]: "<<vecregui[9]<<endl;
    vector<string> vecstr_tmp3 = asplit(vecregui[9],"=");
    nclt_regtel = vecstr_tmp3[1];
    strcpy(stRegInfos.tel,nclt_regtel.c_str());
    cout<<"nclt_regtel: "<<nclt_regtel<<endl;

    char computer_name[64] = {0};
    if(gethostname(computer_name,sizeof(computer_name)) != 0)
    {
        snprintf(log_buf, sizeof(log_buf), "init:gethostname err,code:%d", errno);
        connect_gateway_affirm_log_info(log_buf);
        return false;
    }
    
    strcpy(stRegInfos.dev_name, computer_name);
    snprintf(log_buf, sizeof(log_buf), "dev_name:%s", stRegInfos.dev_name);
    connect_gateway_affirm_log_info(log_buf);

    FILE *fp=NULL;
    int rnt_wr2=0;

    fp=fopen(CONN_GATEWAY_AFFIRM_REGISTER,"wb");
    if(fp == NULL)
    {
        snprintf(log_buf, sizeof(log_buf), "init:open file err,code:%d", errno);
        connect_gateway_affirm_log_info(log_buf);
        return false;
    }

    rnt_wr2 = fwrite(&stRegInfos, sizeof(struct edpClt_reg_info_t), 1, fp);
    if(rnt_wr2 != 1)
    {
        snprintf(log_buf, sizeof(log_buf), "init:write call err,code:%d", errno);
        connect_gateway_affirm_log_info(log_buf);
        fclose(fp);
	    return false;
    }
    fclose(fp);

    connect_gateway_affirm_log_info("init end.");

    return  true ;
}

bool connect_gateway_affirm_worker(CPolicy * pPolicy, void * pParam) 
{
    int ret = 0;
    char log_buf[128] = {0};
    char cmd[128] = {0};
    struct stat f_info;
    
    if(pPolicy->get_type() != CONNECT_GATEWAY_AFFIRM) 
    {
        connect_gateway_affirm_log_info("worker:policy type invalid.");
        return false ;
    }

    g_pConnectGatewayAffirm = (CConnectGatewayAffirm *)pPolicy;
 
    if(old_crcvalue != g_pConnectGatewayAffirm->get_crc())
    {
        connect_gateway_affirm_log_info("worker:policy changed,refreshing plicy file.");
        cleanup_configfile();
        write_gateway_config();

        ///save policy crc
        old_crcvalue = g_pConnectGatewayAffirm->get_crc();
    }

    int netclt_exit = 0;
    netclt_exit = nclt_detect_process((char *)CONN_GATEWAY_AFFIRM_CLIENT_NAME);
    if(netclt_exit == 0)
    {
        connect_gateway_affirm_log_info("worker:edpNclt not running, starting up...");
        ret = lstat(CONN_GATEWAY_AFFIRM_CLIENT_NAME, &f_info);
        if(0 != ret)
        {
            connect_gateway_affirm_log_info("worker:edpNclt not exist");
            return true;
        }

        /*chmod*/
        snprintf(cmd, sizeof(cmd), "chmod +x %s", CONN_GATEWAY_AFFIRM_CLIENT_NAME);
        ret = system(cmd);
        snprintf(log_buf, sizeof(log_buf), "worker:chmod for edpNclt with ret:%d", ret);
        connect_gateway_affirm_log_info(log_buf);
    
        /*startup edpNclt*/
        snprintf(cmd, sizeof(cmd), "./%s &", CONN_GATEWAY_AFFIRM_CLIENT_NAME);
        ret = system(cmd);
        snprintf(log_buf, sizeof(log_buf), "worker:edpNclt not running, started with ret:%d", ret);
        connect_gateway_affirm_log_info(log_buf);
    }

    return true;
}

void connect_gateway_affirm_uninit() 
{
    connect_gateway_affirm_log_info("uninit starting...");

    cleanup_configfile();
    cleanup_registerfile();
    old_crcvalue = 0;

    connect_gateway_affirm_log_info("uninit end.");
    return;
}

static void connect_gateway_affirm_log_info(const char *log_content)
{
	char log_info[2048] = {0};

	if(NULL == log_content)
	{
		return ;
	}
	
	snprintf(log_info, sizeof(log_info), "gw_acces:%s\n", log_content);

	g_GetlogInterface()->loglog(log_info);
}
