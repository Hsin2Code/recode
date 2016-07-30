/*
 * vrcport_tool.cpp
 *
 *  Created on: 2015-1-4
 *      Author: sharp
 */

#include "vrcport_tool.h"
#include "common/Commonfunc.h"
using namespace YCommonTool ;
#include "../include/cli_config.h"
#include "VCFCmdDefine.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <net/route.h>

#ifndef __APPLE__
#include <linux/sockios.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <errno.h>
#include <limits.h>


///获取本地配置接口哦
extern ILocalCfginterface * g_GetlcfgInterface();
extern ILocalogInterface * g_GetlogInterface();
extern void get_desk_user(std::string &usrlist);
#define BUFSIZE 2048

struct route_info
{
    char ifName[IF_NAMESIZE];
    u_int gateWay;
    u_int srcAddr;
    u_int dstAddr;
};

bool Get_Worked_Eth_Name(int fd,char *eth)
{
    //char* ether_Name;
    struct ifreq *ifreq;
    struct ifconf ifconf;
    unsigned char buf[512];
    //init ifconf
    ifconf.ifc_len = 512;
    ifconf.ifc_buf = (char *)buf;

    //get ethernet name
    if(0 > ioctl(fd,SIOCGIFCONF,&ifconf)) {
        close(fd);
        return false ;
    }
    ifreq = (struct ifreq*)buf;
    int i = 0;
    for(i = (ifconf.ifc_len/sizeof(struct ifreq)); i>0; i--) {
        if(0 != strcmp("lo",ifreq->ifr_name)  && 0 != strcmp("virbr0", ifreq->ifr_name))
        {
            strncpy(eth,ifreq->ifr_name,16);
        }
        ifreq++;
    }
    return true ;
}

bool Get_IP(int fd,char* p_IP,char* eth,int len)
{
    struct ifreq* ifreq;
    char *p = NULL;
    ifreq = (struct ifreq*)malloc(sizeof(struct ifreq));
    memset(ifreq,0,sizeof(struct ifreq));
    strncpy(ifreq->ifr_name,eth,len+1);
    if(0 > ioctl(fd,SIOCGIFADDR,ifreq)) {
    	free(ifreq);
    	close(fd);
        return false ;
    }

    p = inet_ntoa(((struct sockaddr_in*)&(ifreq->ifr_addr))->sin_addr);
    strncpy(p_IP,p,strlen(p)+1);
    free(ifreq);
    return true ;
}

#ifndef __APPLE__
bool Get_MAC(int fd,char* p_MAC,char* Ether_Name,int len)
{
    const char *eth;
    eth = Ether_Name;
    struct ifreq *ifreq;
    ifreq = (struct ifreq *)malloc(sizeof(struct ifreq));
    memset(ifreq,0,sizeof(struct ifreq));
    strncpy(ifreq->ifr_name,Ether_Name,len);
    //get mac info
    if(0 > ioctl(fd,SIOCGIFHWADDR,ifreq)) {
    	close(fd);
    	free(ifreq);
    	return false ;
    }
    int i;
    for(i=0; i<6; i++) {
        sprintf(p_MAC+2*i,"%02x",(unsigned char)(ifreq)->ifr_hwaddr.sa_data[i]);
    }
    free(ifreq);
    return true ;
}

#endif

/*same as linux*/
bool Get_Sub_Mask(int fd,char *submask,char *eth_name,int len) {
    struct ifreq *ifreq;
    char *p = NULL;

    ifreq = (struct ifreq *)malloc(sizeof(struct ifreq));
    memset(ifreq,0,sizeof(struct ifreq));
    strncpy(ifreq->ifr_name,eth_name,len);
    if(ioctl(fd,SIOCGIFNETMASK,ifreq) < 0) {
        free(ifreq);
        return false ;
    }
    p = inet_ntoa(((struct sockaddr_in*)&(ifreq->ifr_addr))->sin_addr);
    strncpy(submask,p,strlen(p)+1);
    free(ifreq);
    ifreq = NULL;
    return true ;
}

int Get_Gateway(char * pNic,char *gateway)
{
	std::string nic = pNic ;
	std::string gate = YCommonTool::get_gatWay(nic);
	strcpy(gateway,gate.c_str());
    return 0;
}

bool Get_Network_Info(net_info *n_info)
{
    int fd;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(0 > fd) {
       char szError[128]="";
       sprintf(szError,"SOCK_DGRAM error %d",errno);
       g_GetlogInterface()->log_error(szError);
       return false ;
    }

    char sz[32];
    sprintf(sz,"fd = %d  name = %s",fd,n_info->eth_name);
    g_GetlogInterface()->log_error(sz);

    if(!Get_Sub_Mask(fd,n_info->sub_mask,n_info->eth_name,16)) {
    	close(fd);
    	char szbuffer[128]="";
    	sprintf(szbuffer,"Get_Sub_Mask error %d",errno);
    	g_GetlogInterface()->log_error(szbuffer);
    	return false ;
    }

    Get_Gateway(n_info->eth_name,n_info->gateway);

    close(fd);
    return true ;
}

static int str_reverse_and_dealph(const char *src_buf, int src_len, char *dst_buf, int dst_len)
{
    int i = src_len - 1;
    int j = 0;
    char buf[512] = {0};

    if(NULL == src_buf || NULL == dst_buf || 0 == src_len || 0 == dst_len)
    {
        return -1;
    }

    snprintf(buf, sizeof(buf), "%s", src_buf);

    while(0 < i && j < dst_len)
    {
        if(buf[i] >='A' && buf[i] <= 'Z')
        {
           buf[i] -= 'A' -'1';
        }

        if(buf[i] >='a' && buf[i] <= 'z')
        {
            buf[i] -= 'a' -'1';
        }
        dst_buf[j] = buf[i];
        i --;
        j ++;
    }

    dst_buf[dst_len] = '\0';

    return 0;
}

int get_device_indetify(char *buf,int bufsize,string & strmac)
{
    #define MAC_LEN 12
    char mac_buf[MAC_LEN + 1] = {0};
//    char sid_buf_ten[10 + 1] = {0};
    char sid_buf_nine[9 + 1] = {0};
//    unsigned long int test_ul = 0;

    if(NULL == buf)
    {
        return 0;
    }

    snprintf(mac_buf, sizeof(mac_buf), "%s", strmac.c_str());

    (void)str_reverse_and_dealph(mac_buf, strlen(mac_buf), sid_buf_nine, sizeof(sid_buf_nine) - 1);

    snprintf(buf, bufsize, "%s", sid_buf_nine);
//以下代码在 32 位服务器会出问题，对devid的 算法要进行改进。
/*    (void)str_reverse_and_dealph(mac_buf, strlen(mac_buf), sid_buf_ten, sizeof(sid_buf_ten) - 1);

    test_ul = strtoul(sid_buf_ten, NULL, 0);
    if(ULONG_MAX != test_ul)
    {
        snprintf(buf, bufsize, "%s", sid_buf_ten);
    }
    else
    {
        (void)str_reverse_and_dealph(mac_buf, strlen(mac_buf), sid_buf_nine, sizeof(sid_buf_nine) - 1);
        snprintf(buf, bufsize, "%s", sid_buf_nine);
    }
*/
    return 1;
}

int  Judge_User_Login(char *user_name)
{
    FILE *fp;
    char buf[256];
    //char name_tmp[64] = {0};
    char tty_tmp[64];
    char reg_tmp[64];
    char free_tmp[64];
    fp = popen("who","r");
    if(NULL != fp)
    {
        while(fgets(buf,255,fp))
        {
            sscanf(buf,"%s %s %s %s",user_name,tty_tmp,reg_tmp,free_tmp);
#if 1
            if(0 == strncmp(tty_tmp,"tty1",4))
            {
                break;
            }
#endif
        }
        if(0 == strcmp("",user_name)) {
            pclose(fp);
            return 0;
        }
        pclose(fp);
    }

    return 1 ;
}

int get_loginUser_info(char *buf,int bufsize)
{
    if((buf == NULL)||(bufsize <=0))
    {
        return -1;
    }
    *buf = '\0';

    char usrname[128]={0};
    Judge_User_Login(usrname);
    if(0 == strcmp("",usrname)) {
    	strcpy(buf,"root");
    } else {
    	strcpy(buf,usrname);
    }
    return 0;
}

string getLangId()
{
    char *_pl = getenv("LANG");
    if(_pl == NULL) {
        return "zh_CN.UTF-8";
    }
    return _pl;
}

int  get_pkt_app_info(string  & info,string & nicName,string  & regip,
		string  & retmac) {

d	info = info + "MACAddress0="+retmac+STRITEM_TAG_END;
	info = info + "IPAddress0="+regip+STRITEM_TAG_END;
	info = info + "MACCount=1\r\nIPCount=1"+STRITEM_TAG_END;

	net_info n_info;
	memset(&n_info,0,sizeof(net_info));
	strcpy(n_info.mac,retmac.c_str());
	strcpy(n_info.ip,regip.c_str());
	strcpy(n_info.eth_name,nicName.c_str());

	char szlog[128]="";
	sprintf(szlog,"mac=%s,ip=%s,nic=%s",n_info.mac,n_info.ip,n_info.eth_name);
	g_GetlogInterface()->log_error(szlog);

	if(!Get_Network_Info(&n_info)) {
		printf("Get_Network_Info error\r\n");
		return 0 ;
	}

	info = info +"IPReport="+retmac+"|"+n_info.ip+"|"+n_info.sub_mask+
	                    "|"+n_info.gateway+"*"+"84C9B2A7E124|8.8.8.8,8.8.4.4#" + STRITEM_TAG_END;

	char value[1024]={0};

	memset(value,'\0',sizeof(value));
	get_device_indetify(value,1024,retmac);
	info = info +"DeviceIdentify="+value+STRITEM_TAG_END;

    std::string _ulist;
    get_desk_user(_ulist);
	info = info + "SysUserName=" + _ulist + STRITEM_TAG_END;
	info = info + "LogonOnUserName=" + _ulist + STRITEM_TAG_END;
	info = info + "LangId=" + getLangId() + STRITEM_TAG_END;

	info = info +"ActiveIPAddress="+regip+STRITEM_TAG_END;

	return 1 ;
}

void  trimstring(string & str) {
	if(str[str.length()-1] == '\n') {
		str.erase(str.length()-1);
	}
	if(str[str.length()-1] == '\r') {
		str.erase(str.length()-1);
	}
}

#define POLICY_COUNT_TAG "_COUNT="

std::string  get_tag_val(string & src,string & tag , int & max) {
	int npos = src.find(tag,max);
	if(npos== (int)string::npos) {
		return "" ;
	}
	int npos1 = src.find(".",npos);
	if(npos1 == (int)string::npos) {
		return "";
	}
	if(npos1 > max) {
		max = npos1 ;
	}
	///后面有两个看不见的字符，所以+2
	std::string ret = src.substr(npos + tag.length() + 1,npos1 - (npos + tag.length()+strlen(STRITEM_TAG_END)));
	trimstring(ret);
	return ret;
}

bool    get_PolicyContent(int i, std::string  & src , string & xml , int & startpos) {
	string tag = "P_CONTENT" ;
	char sz[20] = "";
	sprintf(sz,"%d",i);
	tag = tag + sz ;
	size_t  npos = src.find(tag,startpos);
	if(npos == string::npos) {
		return false ;
	}
	size_t  npos1 = src.find(POLICY_END_TAG,npos);
	if(npos1 == string::npos) {
		return false ;
	}
	if((int)npos1 > startpos) {
		startpos = npos1 ;
	}
	xml = src.substr(npos+tag.length()+1,npos1+strlen(POLICY_END_TAG) -(npos+tag.length()+1));
	trimstring(xml);
	return true ;
}

int    get_policylist_fromGeneral(std::string & general ,
                                  std::vector<tag_vrv_policyGen> & _array)
{
    ///先获取数量
    int  cnt_tag_len = strlen(POLICY_COUNT_TAG);
    int npos = general.find(POLICY_COUNT_TAG,0);
    if(npos == (int)string::npos) {
        printf("get_policylist_fromGeneral failed 1\n");
        return 0 ;
    }
    int npos1 = general.find(".",npos);
    if(npos1 == (int)string::npos) {
        printf("get_policylist_fromGeneral failed 2\n");
        return 0 ;
    }

    string  strcount = general.substr(npos + cnt_tag_len,npos1-npos-1);
    int count = atoi(strcount.c_str());

    string  id_tag , func_tag , crc_tag , flg_tag ;
    string  id,      func ,     crc ,     flg ;
    char    sz[32] = "" ;
    string  tmp ;
    int max_idx = 0 ;
    tag_vrv_policyGen item;
    for(int i = 0 ; i < count ; i++) {
        sprintf(sz,"%d",i);
        tmp = sz ;
        id_tag = "_ID" + tmp ;
        id = get_tag_val(general,id_tag,max_idx);
        if(id.length() == 0)  {
            break ;
        }
        //printf("id_Tag = %s , val = %s\n",id_tag.c_str(),id.c_str());
        item.id = atoi(id.c_str());


        func_tag = "_FUNC" + tmp;
        func = get_tag_val(general,func_tag,max_idx);
        if(func.length()==0) {
            break ;
        }
        //printf("func_tag = %s , val = %s\n",func_tag.c_str(),func.c_str());
        item.func = func ;

        crc_tag = "_CRC" + tmp ;
        crc = get_tag_val(general,crc_tag,max_idx);
        if(crc.length()==0) {
            break ;
        }

        item.crc =(unsigned int)strtoul(crc.c_str(),NULL,10);

        flg_tag = "_FLG" + tmp ;

        flg = get_tag_val(general,flg_tag,max_idx);
        if(flg.length()==0) {
            break;
        }
        //printf("flg_tag = %s , val = %s\n",flg_tag.c_str(),flg.c_str());
        item.flg = atoi(flg.c_str());
        bool  bexsit = false ;
        for(int j = 0 ; j < (int)_array.size() ; j++) {
            if(item.func == _array[j].func) {
                if(item.flg > _array[j].flg) {
                    _array[j] = item ;
                    bexsit = true ;
                    break ;
                }
            }
        }
        if(!bexsit) {
            _array.push_back(item);
        }
    }

    return _array.size() ;
}

///策略概况过滤
void       filter_PolicyGen(std::map<unsigned int , int> & crcmap ///老的策略CRCMAP
                            ,std::map<unsigned int , int> & crcmapEx ///老的策略CRCMAP
                            ,std::vector<tag_vrv_policyGen>  &  addArray ///传入获取的概况，输出需要下载的策略
                            ,std::vector<unsigned int> & delArray ///删除策略的CRC列表
                            ,std::vector<unsigned int> & unApplyArray ) ///取消应用的策略列表
{
    std::map<unsigned int , int> newmap;
    ///先过滤掉不许要动的部分
    std::vector<tag_vrv_policyGen>::iterator  iterGen = addArray.begin();
    while(iterGen != addArray.end()) {
        std::map<unsigned int , int>::iterator iterCrc = crcmap.find(iterGen->crc);
        newmap[iterGen->type] = 0 ;
        ///CRC相同， 肯定同一条策略，所以不用下载
        if(iterCrc != crcmap.end()) {
            iterGen = addArray.erase(iterGen);
            crcmap.erase(iterCrc);
            continue ;
        }
        iterGen++ ;
    }

    ///过滤掉需要停止的
    std::map<unsigned int , int>::iterator iterCrc = crcmap.begin();
    bool bexsit = false ;
    while(iterCrc != crcmap.end()) {
        iterGen = addArray.begin();
        bexsit =  false ;
        while(iterGen != addArray.end()) {
            if(iterGen->crc == iterCrc->first) {
                bexsit = true ;
                break ;
            }
            iterGen++ ;
        }
        if(!bexsit) {
            ///获取此CRC的type
            std::map<unsigned int , int>::iterator find = crcmapEx.find(iterCrc->first);
            if(find != crcmapEx.end()) {
                ///在新的TYPE里面查找
                if(newmap.find(find->second) != newmap.end()) {
                    ///再寻找一下ID
                    iterGen = addArray.begin();
                    bexsit = false ;
                    while(iterGen != addArray.end()) {
                        if(iterGen->id == iterCrc->second) {
                            bexsit = true ;
                        }
                        iterGen++;
                    }
                    if(!bexsit)
                        delArray.push_back(iterCrc->first);
                } else {
                    unApplyArray.push_back(iterCrc->first);
                }
            } else {
                unApplyArray.push_back(iterCrc->first);
            }
        }
        iterCrc++ ;
    }
}

static string getdns() {
    FILE *fp;
    const char *buf = "/etc/resolv.conf";
    char str[128] = "\0";
    string dns;
    fp = fopen(buf,"r");
    if(fp == NULL) {
        return "";
    }
    char *p;
    if(fp != NULL) {
        while(fgets(str,128,fp)) {
            p  = strstr(str,"nameserver");
            if(p != NULL) {
                if(*(p + strlen(p) -1) == '\n') {
                    *(p + strlen(p) -1) = 0 ;
                }
                dns = dns + (p+strlen("nameserver "))+",";
            }
        }
    }
    fclose(fp);
    return dns;
}

bool     getVal_fromTarget(char * pval,const char * pTar , const char * pSrc,int maxlen) {
	if(pSrc == NULL || pTar == NULL) return false ;
	char  target[64] = "";
	int nlen = strlen(pTar) ;
	nlen = (nlen > 31 ? 31 : nlen) ;
	strncpy(target,pTar, nlen);
	target[nlen++] = '=';
	const char * pTmp = strstr(pSrc, target);
	if(pTmp == NULL) {
		return false ;
	}
	const char * pTmp1 = strstr(pTmp+nlen, STRITEM_TAG_END);
	if(pTmp1 == NULL) {
		return false ;
	}
	int tmp = nlen ;
	nlen = ((pTmp1-(pTmp+nlen)) > maxlen ? maxlen : (pTmp1-(pTmp+nlen)));
	strncpy(pval,pTmp+tmp,nlen);
	return true ;
}

int      get_logHeader(char * buffer ,
                       std::string  &  regip,  ///注册IP
                       std::string  &  regmac, ///注册MAC
                       std::string  &  id,
                       std::string  &  sysuser)     ///ID
{
    net_info net;
    memset(&net,0,sizeof(net));
    std::string nic ;
    g_GetlcfgInterface()->get_lconfig(lcfg_regnic,nic);
    strcpy(net.eth_name,nic.c_str());
    Get_Network_Info(&net);

    char computer_name[256];
    gethostname(computer_name,256);
    std::string  iprpt  = regmac + "|"  + regip+"|" + net.sub_mask +"|"+net.gateway+"*84C9B2A7E124|"+ getdns() + "#";

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
            getLangId().c_str(),STRITEM_TAG_END);
    return strlen(buffer) ;
}
