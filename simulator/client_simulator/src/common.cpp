#include <iostream>
#include <sys/socket.h>
#include "common.h"

std::string g_server_ip = "";
std::string g_dev_id = "";
int g_server_port = -1;
std::string g_mac_addr = "";
std::string g_self_ipaddr = "";
std::string g_gw_ip = "";
int g_run_times;

int g_log_interval = 0;
int g_policy_interval = 0;
int g_sfd_flag = 0;
int g_upload_log_times = 1;


void test() {
    std::cout << "test function " << std::endl;
}
//获取本地时间
void get_local_time(char strtime[])
{
    time_t timep;
    struct tm *p;
    time(&timep);
    p = localtime(&timep);
    sprintf(strtime, "%d-%02d-%02d %02d:%02d:%02d", (1900 + p->tm_year), (1 + p->tm_mon), p->tm_mday, p->tm_hour,
                    p->tm_min, p->tm_sec);
}


static bool Get_Network_Info(net_info *n_info)
{
    std::string x = "x.x.x.x";
    if(n_info != NULL) {
        strncpy(n_info->gateway, x.c_str(), x.length());
        strncpy(n_info->ip, x.c_str(), x.length());
        strncpy(n_info->mac, x.c_str(), x.length());
        strncpy(n_info->sub_mask, x.c_str(), x.length());
        strncpy(n_info->eth_name, x.c_str(), x.length());
        return true;
    }
    return false;
}


int      get_logHeader(char * buffer ,
		    std::string  &  regip,  ///注册IP
		    std::string  &  regmac, ///注册MAC
		    std::string  &  id,
		    std::string  &  sysuser)     ///ID
{
	net_info net;
	memset(&net,0,sizeof(net));
	Get_Network_Info(&net);
	char computer_name[256] = "fake_computer_name";
	std::string  iprpt  = regmac + "|"  + regip+"|" + net.sub_mask +"|"+net.gateway+"*84C9B2A7E124|"+ "8.8.8.8.8" + "#";

	sprintf(buffer,
			"SysUserName=%s%s"\
			"KeyUserName=%s%s"\
			"MACAddress0=%s%s"\
			"IPAddress0=%s%s"\
			"MACCount=1%sIPCount=1%s"\
			"IPReport=%s%s"\
			"ComputerName=%s%s"\
			"DeviceIdentify=%s%s"\
			"LogonOnUserName=%s%s"\
			"LangId=%s%s",
			sysuser.c_str(),STRITEM_TAG_END,
			sysuser.c_str(),STRITEM_TAG_END,
			regmac.c_str(),STRITEM_TAG_END,
			regip.c_str(),STRITEM_TAG_END,
			STRITEM_TAG_END,STRITEM_TAG_END,
			iprpt.c_str(),STRITEM_TAG_END,
			computer_name,STRITEM_TAG_END,
			id.c_str(),STRITEM_TAG_END,
			sysuser.c_str(),STRITEM_TAG_END,
			"zh-cn.UTF-8",STRITEM_TAG_END);
	return strlen(buffer) ;
}


int code_convert(const char *from_charset,const char *to_charset,char *inbuf,int inlen,char *outbuf,int & outlen)
{
    (void)(from_charset);
    (void)(to_charset);
    outlen = inlen;
    strcpy(outbuf,inbuf);
    return 1;
}

