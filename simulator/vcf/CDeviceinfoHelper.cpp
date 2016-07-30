/*
 * CDeviceinfoHelper.cpp
 *
 *  Created on: 2015-1-28
 *      Author: sharp
 */

#include "CDeviceinfoHelper.h"
#include <ctype.h>
#include <string>
#include <list>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include "ldbdefine.h"
#include "../include/cli_config.h"
#include "VCFCmdDefine.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include "common/Commonfunc.h"
#include <sys/ioctl.h>
#include <termios.h>
#ifndef __APPLE__
#include <linux/hdreg.h>
#include <linux/sockios.h>
#include <scsi/sg.h>
#else
#include <net/if_dl.h>
#include <net/ethernet.h>
#endif



#define SPEED_10        10
#define SPEED_100       100
#define SPEED_1000      1000
#define SPEED_2500      2500
#define SPEED_10000     10000

#ifndef SIOCETHTOOL
#define SIOCETHTOOL     0x8946
#endif
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif


/* CMDs currently supported */
#define ETHTOOL_GSET        0x00000001 /* Get settings. */
#define ETHTOOL_SSET        0x00000002 /* Set settings. */

/* hack, so we may include kernel's ethtool.h */
//typedef unsigned long long __u64;
typedef __uint32_t __u32;       /* ditto */
typedef __uint16_t __u16;       /* ditto */
typedef __uint8_t __u8;         /* ditto */

struct ethtool_cmd {
        __u32   cmd;
        __u32   supported;      /* Features this interface supports */
        __u32   advertising;    /* Features this interface advertises */
        __u16   speed;          /* The forced speed, 10Mb, 100Mb, gigabit */
        __u8    duplex;         /* Duplex, half or full */
        __u8    port;           /* Which connector port */
        __u8    phy_address;
        __u8    transceiver;    /* Which transceiver to use */
        __u8    autoneg;        /* Enable or disable autonegotiation */
        __u32   maxtxpkt;       /* Tx pkts before generating tx int */
        __u32   maxrxpkt;       /* Rx pkts before generating rx int */
        __u32   reserved[4];
};

///获取本地配置接口
extern ILocalCfginterface * g_GetlcfgInterface();

static void trimEnter(char * pStr) {
	int len = strlen(pStr);
	if(len == 0) {
		return ;
	}
	if(*(pStr+len-1) == '\n') {
		*(pStr+len-1) = 0 ;
	}
}

//return NULL is failed
char * info_search(const char *cmd, char *name, char * result, int length)
{
    FILE *pfp = NULL;

    pfp = popen(cmd, "r");
    if (pfp == NULL)  {
        return NULL;
    }

    fgets(result, length, pfp);
    char *index = NULL;
    index = strstr(result, name);
    if (index == NULL) {
        pclose(pfp);
        return NULL;
    }

    char * pval =  index + strlen(name) + 1;
    while (isspace(*pval) || *pval == ':') {
    	pval++ ;
    }
    pclose(pfp);
    return pval;
}

#ifdef __APPLE__
const unsigned int BUFFER_SIZE = 1024;
/* 获取CPU名称命令 */
const char * CPU_NAME_CMD = "sysctl -n machdep.cpu.brand_string";
/* 获取cpu ID*/
const char * CPU_ID_CMD = "sysctl -n hw.cpufamily";
/* 获取CPU 频率 */
const char * CPU_HZ_CMD = "sysctl -n hw.cpufrequency";
/* 获取主机名 */
const char * HOSTNAME_CMD = "hostname";
/* 获取操作系统版本 */
const char * OS_TYPE_CMD = "sysctl -n kern.version";
/* 获取语言环境 */
const char * SYS_DEFAULTLANG_CMD = "echo $LANG";
/* 获取主板名 */
const char * BASEBOARD_NAME_CMD = "system_profiler SPHardwareDataType | grep \"Boot ROM Version\" ";
/* 获取主板时间 */
const char * BASEBOARD_TIME_CMD = "sysctl -n kern.boottime";
/* 获取内存总量 */
const char * MEM_TOTAL_CMD = "sysctl -n hw.memsize";
/* 内存使用情况 */
const char * MEM_SPACE_CMD = "top -l 1 | grep PhysMem";
/* 获取显卡信息 */
const char * MONITOR_INFO_CMD = "system_profiler SPDisplaysDataType | grep \"Chipset Model\" ";
/* 获取磁盘名称 */
const char * DISK_NAME_CMD = "df | grep /dev/disk | awk '{print $1}' ";
/* 获取磁盘信息 */
const char * DISK_INFO_CMD = "system_profiler SPStorageDataType ";
/* 获取硬盘使用情况 */
const char * DISK_SPACE_CMD = "df -k | grep /";
/* 获取网卡名称 */
const char * ETH_NAME_CMD = "system_profiler SPEthernetDataType -xml";
/* audio设备 */
const char * AUDIT_INFO_CMD = "system_profiler SPCameraDataType | grep \"Model ID\"";

const char * USB_INFO_CMD = "system_profiler SPUSBDataType";


static int exe_cmd_hd(const char * cmd, char *buf, int bufsize) {
    FILE *fp = popen(cmd, "r");
    if(NULL == fp) {
	fprintf(stderr, "[popen] %s", strerror(errno));
	return false;
    }
    fgets(buf, bufsize, fp);
    pclose(fp);
    return true;
}

#endif


///获取CPU型号
static  int get_cpu_name(char *buf,int bufsize) {
#ifndef __APPLE__
    char buff[512]={0};
    char cmd[512]={0};
    char *index = NULL;
    FILE *fp=NULL;

#ifdef HW_X86
    snprintf(cmd,512,"grep -E 'model name|cpu model' /proc/cpuinfo");
    fp = popen(cmd,"r");
    if(NULL ==fp) {
        return 0;
    }
    fgets(buff,sizeof(buff)-1,fp);
    if(NULL != (index=strstr(buff,":")))  {
    	sscanf(index+1,"%[^\n]",buf);
    }
    pclose(fp);
#endif

#ifdef HW_LONGXIN
	snprintf(cmd,512,"grep -E 'model name|cpu model' /proc/cpuinfo");
    fp = popen(cmd,"r");
    if(NULL ==fp) {
        return 0;
    }
    fgets(buff,sizeof(buff)-1,fp);
    if(NULL != (index=strstr(buff,":")))  {
    	sscanf(index+1,"%[^\n]",buf);
    }
    pclose(fp);
#endif

#ifdef HW_ARM64
	sprintf(cmd,"cat /proc/cpuinfo");
	fp = popen(cmd,"r");
	if(NULL ==fp) {
		return 0 ;
	}
	int len = 0 ;
	fgets(buff,sizeof(buff)-1,fp) ;
	if(NULL != (index=strstr(buff,":")))  {
    	sscanf(index+1,"%[^\n]",buf);
    }
	pclose(fp);

#endif
    return 1;
#else // APPLE_HERE get_cpu_name
    return exe_cmd_hd(CPU_NAME_CMD, buf, bufsize);
#endif
}
///获取CPUID
static int get_cpu_id(char *buf,int bufsize) {
#ifndef __APPLE__

#ifdef HW_X86
	char cmd[512]={0};
	char name[10] = "ID";
	char result[512]="";
	int  length=512;
    memset(result,0,length);

    snprintf(cmd,512,"dmidecode -t processor |grep '%s'",name);
    char * pVal = info_search(cmd,name,result,length);
    if(pVal)
    	memcpy(buf,pVal,strlen(pVal)+1);
#endif

#ifdef HW_LONGXIN

#endif


#ifdef HW_ARM64
	char *index = NULL;
    FILE *fp=NULL;
 	char buff[512]={0};
    char cmd[512]={0};

	sprintf(cmd,"cat /proc/cpuinfo");
	fp = popen(cmd,"r");
	if(NULL ==fp) {
		return 0 ;
	}
	int len = 0 ;
	while(fgets(buff,sizeof(buff)-1,fp)) {
		if(strncmp("Hardware",buff,8) == 0) {
			if(NULL != (index=strstr(buff,":")))  {
    			sscanf(index+1,"%[^\n]",buf);
    		}
			break ;
		}
		memset(buff,0,sizeof(buff));
	}
	pclose(fp);
#endif
    return 1;
#else  //APPLE_HERE
    return exe_cmd_hd(CPU_ID_CMD, buf, bufsize);
#endif

}
///获取CPU频率
static int get_cpu_hz(char *buf,int bufsize) {
#ifndef __APPLE__

#ifdef HW_X86
	char cmd[512]={0};
	char name[10] = "cpu MHz";
	char result[512]="";
	int  length=512;
	memset(result,0,length);
    snprintf(cmd,512,"cat /proc/cpuinfo |grep '%s'",name);
    char * pVal = info_search(cmd,name,result,length);
    if(pVal)
    	memcpy(buf,pVal,strlen(pVal)+1);
#endif

#ifdef  HW_LONGXIN
#endif

#ifdef  HW_ARM64
#endif

    return 1;
#else  //APPLE_HERE
    char szline[BUFFER_SIZE];
    if(true != exe_cmd_hd(CPU_HZ_CMD, szline, BUFFER_SIZE)) {
        return false;
    }
    snprintf(buf, bufsize, "%0.2fG", atof(szline)/1000/1000/1000);
    return true;
#endif
}
///获取主机名
static int get_sys_hostname(char *buf,int bufsize) {
	char   cmd[512]={0};
	FILE * pfp  = popen("hostname", "r");
	if (pfp == NULL) {
	    return 0;
    }
	fgets(cmd,512,pfp);
	strcpy(buf,cmd);
	pclose(pfp);
	return 1;
}


///获取操作系统版本
int get_os_type(char *buf,int bufsize,bool hasR = true) {

#ifndef __APPLE__
	//发行版本
	FILE *fp=NULL;
	char  szline[512] = "";
	fp = popen("cat /etc/issue","r");
	if(fp == NULL) {
		return 0 ;
	}

	fgets(szline,511,fp);

	if(strlen(szline)==0) {
		pclose(fp);
		return 0 ;
	}
	pclose(fp);
	if(!hasR) {
		return 1;
	}

	int index = 0 ;
	while(szline[index] != '\n' &&
			szline[index] != '\0') {
		index++;
	}
	szline[index] = '\0';
	trimEnter(szline);
	sprintf(buf,"%s",szline);
	trimEnter(buf);
	//系统类型
	fp = popen("uname -o","r");
	if(fp == NULL) {
		return 0 ;
	}
	memset(szline,0,511);
	if(fgets(szline,511,fp) == NULL){
		pclose(fp);
		return 0;
	}
	trimEnter(szline);
	sprintf(buf + strlen(buf)," %s ",szline);
	trimEnter(buf);
	pclose(fp);

	fp = popen("uname -r","r");
	if(fp == NULL) {
			return 0;
	}
	memset(szline,0,511);
	if(fgets(szline,511,fp) == NULL){
		pclose(fp);
		return 0;
	}
	pclose(fp);

	trimEnter(szline);
	trimEnter(buf);
	sprintf(buf + strlen(buf)," (%s) ",szline);
	trimEnter(buf);
	return 1;
#else //APPLE_HERE
    if(!hasR) {
        return true;
    }
    return exe_cmd_hd(OS_TYPE_CMD, buf, bufsize);
#endif
}

static int get_sys_defaultLang(char *buf,int bufsize) {
	FILE *fp=NULL;

	char  szline[512] = "";
	fp = popen("echo $LANG","r");
	if(fp == NULL) {
		return 0 ;
	}

	fgets(szline,511,fp);
	pclose(fp);

	if(NULL != strstr(szline,"zh")) {
	    strcpy(buf,"CHINESE");
	} else if(NULL != strstr(szline,"en")) {
	    strcpy(buf,"ENGLISH");
	} else {
	    strcpy(buf,"UNKNOWN");
	}
	return 1;
}
///获取SDA接口的磁盘名称
static int get_disk_name(std::list<std::string> & diskArray, const char * disktype ) {
#ifndef __APPLE__
	char szcmd[128] = "";
#ifdef  HW_X86
	sprintf(szcmd,"df|grep /dev/%s|awk '{print $1}'",disktype);
#endif

#ifdef HW_LONGXIN
	sprintf(szcmd,"df|grep /dev/%s|awk '{print $1}'",disktype);
#endif

#ifdef  HW_ARM64
	sprintf(szcmd,"fdisk -l|grep /dev/%s|awk '{print $1}'",disktype);
#endif
	FILE *fp =popen(szcmd,"r");
    if(NULL == fp) {
        return -1;
    }
    char szLine[256] = "";
    std::string  name ;
    bool  bexsit = false ;
    while(fgets(szLine,255,fp)) {
    	bexsit  =  false ;
    	std::list<std::string>::iterator iter = diskArray.begin();
    	while(iter != diskArray.end()) {
    		if(szLine == *iter) {
    			bexsit = true ;
    			break ;
    		}
    		iter++ ;
    	}
    	trimEnter(szLine);
    	if(!bexsit)
    		diskArray.push_back(szLine);
    	memset(szLine,0,sizeof(szLine));
    }
    pclose(fp);
    return diskArray.size();

#else //APPLE_HERE
    FILE * fp = popen(DISK_NAME_CMD, "r");
    if(NULL == fp) {
        return false;
    }
    char szline[BUFFER_SIZE] = {0};
    diskArray.clear();
    while(fgets(szline, BUFFER_SIZE, fp)) {
        trimEnter(szline);
        diskArray.push_back(szline);
        memset(szline, 0, BUFFER_SIZE);
    }
    pclose(fp);
    return true;
#endif

}
///获取磁盘类型
static int get_diskType_info(const char * name,char *buf,int bufsize) {
#ifndef __APPLE__

#ifdef HW_X86
    if((buf == NULL)||(bufsize <= 0)) {
        return 0;
    }
    *buf='\0';

    char value[1024]= {0};
    char cmd[256] = {0};
    char *index = NULL;
    sprintf(cmd,"smartctl -i %s",name);
    FILE *fp =popen(cmd,"r");
    if(NULL == fp) {
        return -1;
    }
    while(fgets(value,bufsize-1,fp)) {
        if(NULL!=(index =strstr(value,"Device Model:") )) {
            sscanf(index+strlen("Device Model:"), "%s", buf);
            break;
        }
    }
	pclose(fp);
#endif
#ifdef HW_LONGXIN
#endif

#ifdef HW_ARM64
#endif
    return 0;
#else //APPLE_HERE
    FILE * fp = popen(DISK_INFO_CMD, "r");
    if(NULL == fp) {
        return false;
    }
    int flag = false;
    char *tmp = NULL;
    char szline[BUFFER_SIZE];
    while(fgets(szline, BUFFER_SIZE, fp)) {
        if(strstr(szline, name)) {
            flag = true;
        }
        if(flag) {
            tmp = strstr(szline, "Device Name:");
            if(tmp != NULL) {
                strcpy(buf, tmp + strlen("Device Name:"));
                break;
            }
        }
    }
    pclose(fp);
    if(tmp == NULL) {
        return false;
    }
    return true;
#endif

}



///获取磁盘ID
static int get_disk_id(char * name ,char *buf,int bufsize) {
#ifndef __APPLE__

#ifdef HW_X86
    char value[1024]= {0};
    char cmd[256] = {0};
    char *index = NULL;

    sprintf(cmd,"smartctl -i %s",name);
    FILE *fp =popen(cmd,"r");
    if(NULL == fp) {
        return -1;
    }

    while(fgets(value,bufsize-1,fp)) {
        if(NULL!=(index =strstr(value,"Serial Number:") )) {
            sscanf(index+strlen("Serial Number:"), "%s", buf);
            break;
        }
    }

    pclose(fp);
#endif

#ifdef HW_LONGXIN
#endif

#ifdef HW_ARM64
    int fd;
    struct hd_driveid hid;
    fd = open (name, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    if (ioctl (fd, HDIO_GET_IDENTITY, &hid) < 0) {
		close (fd);
        return -1;
    }
    close (fd);
    sprintf(buf,"%s", hid.serial_no);
#endif
    return 0;

#else //APPLE_HERE
    FILE * fp = popen(DISK_INFO_CMD, "r");
    if(NULL == fp) {
        return false;
    }
    int flag = false;
    char *tmp = NULL;
    char szline[BUFFER_SIZE];
    while(fgets(szline, BUFFER_SIZE, fp)) {
        if(strstr(szline, name)) {
            flag = true;
        }
        if(flag) {
            tmp = strstr(szline, "Volume UUID:");
            if(tmp != NULL) {
                strcpy(buf, tmp + strlen("Volume UUID:"));
                break;
            }
        }
    }
    pclose(fp);
    if(tmp == NULL) {
        return false;
    }
    return true;
#endif
}
///获取光驱
static int   get_cdrom_desc(char * szbuf,int bufsize) {
#ifndef __APPLE__
#ifdef HW_X86
	char result[512] = {0};
	char name[512] ={0};
	char *index = NULL;
	FILE *fp = popen("cdrecord --devices|grep dev", "r");
	if (fp == NULL) {
		return -1;
	}

	while(fgets(result, sizeof(result), fp)) {
		if(NULL!=(index = strstr(result,":"))) {
			sscanf(index+1,"%[^\n]",name);
			strcat(szbuf,name);
			strcat(szbuf,";");
		}
		memset(result,'\0',sizeof(result));
	}

	//复制数据
	int len = strlen(szbuf);
	*(szbuf+len-2) = '\0';

	pclose(fp);
#endif
	return 0;
#else //APPLE_HERE
    sprintf(szbuf, "%s", "--");
    return true;
#endif

}

///获取主板名
static int get_baseboard_name(char *buf,int bufsize)
{
#ifndef __APPLE__
#ifdef HW_LONGXIN
	char result[512] = {0};
	char *index = NULL;
	FILE *fp = popen("cat /proc/boardinfo|grep 'Board name'", "r");

	if (fp == NULL) {
	    return -1;
	}
	fgets(result, sizeof(result), fp);
	if(NULL!=(index = strstr(result,":"))) {
	    strcpy(buf,index+1);
    }

	int len = strlen(buf);
	*(buf+len-1) = '\0';

	pclose(fp);
#endif

#ifdef HW_ARM64
	char result[512] = {0};
	char *index = NULL;
	FILE *fp = popen("cat /proc/boardinfo|grep 'Board name'", "r");

	if (fp == NULL) {
	    return -1;
	}
	fgets(result, sizeof(result), fp);
	if(NULL!=(index = strstr(result,":"))) {
	    strcpy(buf,index+1);
    }

	int len = strlen(buf);
	*(buf+len-1) = '\0';

	pclose(fp);
#endif 

#ifdef HW_X86
    char cmd[128]= {0};
    char name[32]= {0};
    char szResult[512] = "";
    int  length=512;

    memset(szResult,0,512);

    snprintf(name,32,"%s","Product Name");
    snprintf(cmd,128,"dmidecode -t baseboard |grep '%s'",name);
    char * pVal =  info_search(cmd,name,szResult,length);
    if(pVal)
      strcpy(buf,pVal);
#endif
	return 0;

#else //APPLE_HERE
    char szline[BUFFER_SIZE] = {0};
    if(true != exe_cmd_hd(BASEBOARD_NAME_CMD, szline, BUFFER_SIZE)) {
        return false;
    }
    char *index = strchr(szline, ':');
    if(index == NULL) {
        return false;
    }
    strcpy(buf, index + 1);
    trimEnter(buf);
    return true;

#endif

}

///获取主板时间
static int get_baseboard_time(char *buf,int bufsize) {
#ifndef __APPLE__

#ifdef HW_LONGXIN
	char result[512] = {0};
	char *index = NULL;
	FILE *fp = popen("cat /proc/boardinfo|grep Date", "r");
	if (fp == NULL) {
	    return -1;
	}
	//send bios time
	fgets(result, sizeof(result), fp);
	if(NULL!=(index = strstr(result,":"))) {
	    strcpy(buf,index+1);
    }

	int len = strlen(buf);
	*(buf+len-1) = '\0';
	pclose(fp);
#endif

#ifdef HW_ARM64
	char result[512] = {0};
	char *index = NULL;
	FILE *fp = popen("cat /proc/boardinfo|grep Date", "r");
	if (fp == NULL) {
	    return -1;
	}
	//send bios time
	fgets(result, sizeof(result), fp);
	if(NULL!=(index = strstr(result,":"))) {
	    strcpy(buf,index+1);
    }

	int len = strlen(buf);
	*(buf+len-1) = '\0';
	pclose(fp);
#endif

#ifdef HW_X86
    char cmd[128]= {0};
    char name[32]= {0};
    char szResult[512] = "";

    snprintf(name,32,"%s","Release Date");
    snprintf(cmd,128,"dmidecode -t bios | grep '%s'",name);
    char * pVal = info_search(cmd,name,szResult,512);
     if(pVal)
	strcpy(buf,pVal);
#endif

#else //APPLE_HERE

#endif
	return 0;
}

///获取主板制造商
static int get_baseboard_manufacturer(char *buf,int bufsize) {
#ifndef __APPLE__

#ifdef HW_LONGXIN
	char result[512] = {0};
	char *index = NULL;
	FILE *fp = popen("cat /proc/boardinfo|grep Manufacturer", "r");
	if (fp == NULL) {
	    return -1;
	}
	fgets(result, sizeof(result), fp);
	if(NULL!=(index = strstr(result,":"))) {
	    strcpy(buf,index+1);
    }
	pclose(fp);
	int len = strlen(buf);
	*(buf+len-1) = '\0';
#endif

#ifdef HW_ARM64
	char result[512] = {0};
	char *index = NULL;
	FILE *fp = popen("cat /proc/boardinfo|grep Manufacturer", "r");
	if (fp == NULL) {
	    return -1;
	}
	fgets(result, sizeof(result), fp);
	if(NULL!=(index = strstr(result,":"))) {
	    strcpy(buf,index+1);
    }
	pclose(fp);
	int len = strlen(buf);
	*(buf+len-1) = '\0';
#endif

#ifdef HW_X86
    char cmd[128]= {0};
    char name[32]= {0};
    char szResult[512] = "";

    memset(szResult,0,512);
    snprintf(name,32,"%s","Manufacturer");
    snprintf(cmd,128,"dmidecode -t baseboard |grep '%s'",name);
    char * pVal = info_search(cmd,name,szResult,512);
    if(pVal)
    	strcpy(buf,pVal);
#endif

#else //APPLE_HERE

#endif
	return 0;
}

///获取内存总量
static int get_mem_total(char *buf,int bufsize) {
#ifndef __APPLE__
	char memtotal[32] = {0};
	char result[512] = {0};
	char *index = NULL;
	FILE *fp = popen("cat /proc/meminfo|grep MemTotal", "r");
	if (fp == NULL) {
	    return -1;
    }
	fgets(result, sizeof(result), fp);
	if(NULL!=(index = strstr(result,":"))) {
		sscanf(index+1,"%s",memtotal);
    }
	pclose(fp);
    sprintf(buf,"容量：%ldM",atol(memtotal)/1024);
    return 0;
#else //APPLE_HERE
    char szline[BUFFER_SIZE] = {0};
    if(true != exe_cmd_hd(MEM_TOTAL_CMD, szline, BUFFER_SIZE)) {
        return false;
    }
    sprintf(buf, "容量: %ldM", atol(szline)/(1024*1024));
    trimEnter(buf);
    return true;
#endif

}

///获取显卡
static int get_monitor_info(char *buf,int bufsize) {
#ifndef __APPLE__
	char cmd[128]= {0};
	char name[32]= {0};
	char szResult[512] = "";

	snprintf(name,32,"%s","VGA compatible controller");
	snprintf(cmd,128,"lspci |grep '%s'",name);
	char * pVal = info_search(cmd,name,szResult,512);
        if(pVal)
		strcpy(buf,pVal);
	return 0 ;
#else  //APPLE_HERE
    char szline[BUFFER_SIZE] = {0};
    if(true != exe_cmd_hd(MONITOR_INFO_CMD, szline, BUFFER_SIZE)) {
        return false;
    }
    char *index = strchr(szline, ':');
    if(index == NULL) {
        return false;
    }
    strcpy(buf, index + 1);
    return true;
#endif

}


#ifdef __APPLE__
static int get_keymouse_info(const char *cmd, const char *genre, char *buf, int bufsize)
{
    char szline[BUFFER_SIZE] = {0};
    char temp[BUFFER_SIZE] = {0};
    FILE * fp = popen(cmd, "r");
    if(fp == NULL) {
	return false;
    }
    char * tmp = NULL;
    int product_door = true, vendor_door = true;
    while(fgets(szline, BUFFER_SIZE, fp)) {
	if(NULL != strstr(szline, genre)) {
	    char *mark = strrchr(szline, ':');
	    if(*(mark + 1) != '\n') {
	        continue;
	    }
	    *mark = '\n';
	    strcat(buf, "(  ");
	    tmp = szline;
	    while(*tmp++ == ' ');
	    sprintf(temp,"Name: %s| ", --tmp);
	    strcat(buf, temp);
	    while(fgets(szline, BUFFER_SIZE, fp)) {
		if((tmp = strstr(szline, "Product ID:")) != NULL && product_door) {
		    sprintf(temp, "Product ID:%s| ", tmp + strlen("Product ID:"));
		    strcat(buf, temp);
		    product_door = false;
		}
		if((tmp = strstr(szline, "Vendor ID:")) != NULL && vendor_door) {
		    sprintf(temp, "Vendor ID:%s| ", tmp + strlen("Product ID:"));
		    strcat(buf, temp);
		    vendor_door = false;
		}
	    }
	    tmp = strrchr(buf, '|');
	    if(tmp != NULL)
	        *tmp = ' ';
	    strcat(buf,")  ");
	    pclose(fp);
	    return true;
	}
    }
    pclose(fp);
    return false;
}
#endif


///键盘
static int get_keyboard_name(char *buf,int bufsize) {
#ifndef __APPLE__
    char cmd[128]= {0};
    char name[32]= {0};
    char szResult[256] = "";

    snprintf(name,32,"%s","Name");
    snprintf(cmd,128,"cat /proc/bus/input/devices | grep eyboard");//龙芯、x86文件名称区别
    char * pVal = info_search(cmd,name,szResult,256);
     if(pVal) {
         strcpy(buf,pVal);
     }

    return 0;
#else //APPLE_HERE

    memset(buf, 0, bufsize);
    get_keymouse_info("system_profiler SPBluetoothDataType", "Keyboard", buf, bufsize);
    get_keymouse_info("system_profiler SPSPIDataType", "Keyboard", buf, bufsize);
    get_keymouse_info("system_profiler SPUSBDataType", "Keyboard", buf, bufsize);

    char * tmp = buf;
    while(*tmp != '\0') {
        if(*tmp == '\n') {
            *tmp = ' ';
        }
        tmp++;
    }
    if(strlen(buf) == 0) {
        strcpy(buf, "--");
        return false;
    } else {
        return true;
    }
#endif
}

///声音，视频控制器
static int get_audio_info(char *buf,int bufsize) {
#ifndef __APPLE__
	char result[512] = {0};
	char *index = NULL;
#ifdef HW_LONGXIN
	FILE *fp = popen("lspci|grep 'Audio device:'", "r");
	if (fp == NULL) {
	    return -1;
	}
	fgets(result, sizeof(result), fp);
	if(NULL!=(index = strstr(result,"Audio device:"))) {
	    strcpy(buf,index+strlen("Audio device:"));
	}
#else
	FILE *fp = popen("lspci|grep 'audio controller:'", "r");
	if (fp == NULL) {
	    return -1;
	}
	fgets(result, sizeof(result), fp);
	if(NULL!=(index = strstr(result,"audio controller:"))) {
	    strcpy(buf,index+strlen("audio controller:"));
	}
#endif
	int len = strlen(buf);
	*(buf+len-1) = '\0';

	pclose(fp);
	return 0;
#else //APPLE_HERE
    char szline[BUFFER_SIZE] = {0};
    if(true != exe_cmd_hd(AUDIT_INFO_CMD, szline, BUFFER_SIZE)) {
        return false;
    }
    char *index = strchr(szline, ':');
    if(index == NULL) {
        sprintf(buf, "%s", "--");
        return false;
    }
    strcpy(buf, index + 1);
    return true;
#endif

}

static int get_mouse_name(char *buf,int bufsize) {
#ifndef __APPLE__
    char cmd[128] = {0};
    char name[32] = {0};
    char szLine[128] = "";

    snprintf(name,32,"%s","Name");
    snprintf(cmd,128,"cat /proc/bus/input/devices | grep Mouse");
    FILE * fp = popen(cmd, "r");
    if(fp == NULL) {
    	return -1 ;
    }
    const char * pKey = "N: Name=";
    int  key_len = strlen(pKey);
    int  buf_len = strlen(buf);
    while(fgets(szLine,128,fp)) {
    	char * pVal = strstr(szLine,pKey);
    	pVal = pVal + key_len;
    	trimEnter(pVal);
    	buf_len = strlen(buf);
    	strcpy(buf + buf_len,pVal);
    }
    pclose(fp);
    return 0;
#else  //APPLE_HERE
    memset(buf, 0, bufsize);
    get_keymouse_info("system_profiler SPBluetoothDataType", "Mouse", buf, bufsize);
    get_keymouse_info("system_profiler SPSPIDataType", "Mouse", buf, bufsize);
    get_keymouse_info("system_profiler SPUSBDataType", "Mouse", buf, bufsize);
    char * tmp = buf;
    while(*tmp != '\0') {
        if(*tmp == '\n') {
            *tmp = ' ';
        }
        tmp++;
    }
    if(strlen(buf) == 0) {
        strcpy(buf, "--");
        return false;
    }else {
        return true;
    }
#endif

}

static int get_eth_name(char *buf,int bufsize) {
#ifndef __APPLE__
	char cmd[128]={0};
	char name[32]={0};
	char szResult[256] = "";

    snprintf(name,32,"%s","Ethernet controller");
    snprintf(cmd,128,"lspci |grep '%s'",name);
    char * pVal = info_search(cmd,name,szResult,256);
    if(pVal) {
        strcpy(buf,pVal);
    }
    return 0;
#else //APPLE_HERE
    strcpy(buf, "--");
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if( sockfd < 0) {
        perror("Create socket failed!");
        return false;
    }
    char szline[BUFFER_SIZE] = {0};
    char buffer[BUFFER_SIZE] = {0};
    struct ifconf ifc;
    ifc.ifc_len = BUFFER_SIZE;
    ifc.ifc_ifcu.ifcu_buf = buffer;
    
    if( ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
        perror("ioctl err!");
        return false;
    }
    /* 定义并初始化接下来要使用的变量 */
    memset(buf, 0, bufsize);
    char * ptr = buffer,* cptr = NULL,lastname[IFNAMSIZ] = {0},mac[80] = {0};
    
    while(ptr < buffer + ifc.ifc_len) {
        struct ifreq * ifr = (struct ifreq *)ptr;
        int len = sizeof(struct sockaddr) > ifr->ifr_addr.sa_len ? sizeof(struct sockaddr) : ifr->ifr_addr.sa_len;
        ptr += sizeof(ifr->ifr_name) + len; /* for next one in buffer */
        /* 获取网卡的MAC地址 */
        if(ifr->ifr_addr.sa_family == AF_LINK) {
            struct sockaddr_dl *sdl = (struct sockaddr_dl *)&ifr->ifr_addr;
            int a,b,c,d,e,f;
            strcpy(mac, (char *)ether_ntoa((const struct ether_addr *)LLADDR(sdl)));
            sscanf(mac, "%x:%x:%x:%x:%x:%x", &a, &b, &c, &d, &e, &f);
            if((a | b | c | d | e | f) == 0)
                continue;
        }
        if((cptr = (char *)strchr(ifr->ifr_name, ':')) != NULL)
            *cptr = 0;  /* replace colon will null */
        if(strncmp(lastname, ifr->ifr_name, IFNAMSIZ) == 0)
            continue;   /* already processed this interface */
        memcpy(lastname, ifr->ifr_name, IFNAMSIZ);
        
        struct ifreq ifrcopy = *ifr;
        ioctl(sockfd, SIOCGIFFLAGS, &ifrcopy);
        
        if(ifrcopy.ifr_flags & IFF_LOOPBACK)
            continue;   /* 跳过回环地址 */
        
        sprintf(szline,"%s (%s)| ", ifr->ifr_name, mac);
        strcat(buf, szline);
    }
    close(sockfd);
    char * tmp = strrchr(buf, '|');
    if(tmp == NULL) {
        strcpy(buf, "--");
        return false;
    }else {
        *tmp = '\n';
        return true;
    }
#endif
}

void print_hwconf_info(char *buffer,const char *name,char * resultbuf,int resultbuf_size) {
#ifndef __APPLE__
    char *index=NULL;
    char *result=NULL;
    char  lineinfo[256]= {0};

    char *begin=lineinfo;
    int len=0;
    //AUDIO
    index=buffer;
    result=strstr(index,name);
    if(result==NULL)  {
        fprintf(stdout,"no %s\n",name);
        return ;
    }
    index=result;
    result=strstr(index,"desc:");
    result+=strlen("desc:");
    sscanf(result,"%[^\n]",lineinfo);

    //去除首尾的引号
    begin=lineinfo;
    while(*begin == ' ' || *begin == '"')  {
        begin++;
    }
    snprintf(resultbuf,resultbuf_size,"%s",begin);
    len = strlen(resultbuf);
    *(resultbuf+len-1) = '\0';

#else //APPLE_HERE

#endif
    return ;
}

static int get_floppy_info(char *buf,int bufsize) {
#ifndef __APPLE__
    void *ret=NULL;
    struct stat sb;
    int fd=-1;

    char filepath[]="/etc/sysconfig/hwconf";
    fd=open(filepath,O_RDONLY);
    if(fd==-1) {
      return 0;
    }
    fstat(fd,&sb);
    ret=mmap(NULL,sb.st_size,PROT_READ,MAP_PRIVATE,fd,0);

    //TODO:
    print_hwconf_info((char *)ret,"FLOPPY",buf,256);

    if(ret!=NULL)
    {
        if(munmap(ret,sb.st_size)!=0)
            fprintf(stdout,"%s\n",strerror(errno));
    }

    close(fd);
    return 1;
#else
     sprintf(buf, "%s", "--");
     return true;
#endif
}

static int get_slot_info(char *buf,int bufsize) {
#ifndef __APPLE__
    int fd=-1;
    char fileName[]="tempFile-XXXXXX";

    buf[0] = '\0';

    fd=mkstemp(fileName);

    close(fd);

    //we'll write the result to file
    char cmd[128]= {0};
    snprintf(cmd,sizeof(cmd),"dmidecode -t slot >%s",fileName);
    system(cmd);

    fd=open(fileName,O_RDONLY);
    struct stat sb;
    char *buffer;
    if(fd==-1) {
        goto _end_;
    }
    fstat(fd,&sb);
    buffer=(char *)mmap(NULL,sb.st_size,PROT_READ,MAP_PRIVATE,fd,0);
    if(buffer==MAP_FAILED) {
        close(fd);
        goto _end_;
    }

    char *index;
    char line[128];
    index=strstr(buffer,"Designation");
    while(index!=NULL) {
        index+=strlen("Designation:");
        sscanf(index,"%[^\n]",line);
        strncat(buf,line,bufsize);

        strncat(buf," ",bufsize);

        index=strstr(index,"Type");

        sscanf(index,"%[^\n]",line);
        strncat(buf,line,bufsize);

        strncat(buf," ",bufsize);

        index=strstr(index,"Current Usage");

        sscanf(index,"%[^\n]",line);
        strncat(buf,line,bufsize);

        strncat(buf,";",bufsize);
        index=strstr(index,"Designation");
    }

    //now end the file map
    if(munmap(buffer,sb.st_size)==-1) {
        fprintf(stdout,"munmap error: %s\n",strerror(errno));
    }
    close(fd);
_end_:
    unlink(fileName);

    //去掉最后的回车符
    int len = strlen(buf);
    *(buf+len-1) = '\0';
    return 0;
#else //APPLE_HERE
     sprintf(buf, "%s", "--");
     return true;
#endif

}

///获取USB信息
static int get_usb_info(char *buf,int bufsize) {
#ifndef __APPLE__
	char cmd[128]={0};
	char name[32]={0};
	char szResult[256] = "";

    snprintf(name,32,"%s","USB Controller");
    snprintf(cmd,128,"lspci |grep '%s'",name);
    FILE  * fd = popen(cmd,"r");
    if(fd == NULL) {
    	return -1;
    }

    char * index = NULL;
    while(NULL!=fgets(szResult,256,fd)) {
    	if(NULL!=(index=strstr(szResult,name))) {
			sscanf(index+strlen(name)+1,"%s",szResult);
			sprintf(buf + strlen(buf),"\"%s\";",szResult);
			break;
		}
    }
    pclose(fd);
    return 0;
#else

    char * tmp = NULL;
    memset(buf, 0, bufsize);
    if(true != exe_cmd_hd("system_profiler SPUSBDataType | grep -E \"USB {0,9}.{0,9} Bus\"", buf, bufsize)) {
        strcpy(buf, "--");
        return false;
    }
    tmp = strstr(buf, "USB");
    strcpy(buf, tmp);
    strcat(buf, "( ");
    FILE * fp = popen(USB_INFO_CMD, "r");
    char szline[BUFFER_SIZE] = {0};
    char temp[BUFFER_SIZE] = {0};

    while(fgets(szline, BUFFER_SIZE, fp)) {
        if(NULL != (tmp = strstr(szline, "Host Controller Driver:"))) {
            sprintf(temp, "主控制驱动器:%s| ", tmp + strlen("Host Controller Driver:"));
            strcat(buf, temp);
        }
        if(NULL != (tmp = strstr(szline, "PCI Device ID:"))) {
            sprintf(temp, "设备ID:%s| ", tmp + strlen("PCI Device ID:"));
            strcat(buf, temp);
        }
        if(NULL != (tmp = strstr(szline, "PCI Revision ID:"))) {
            sprintf(temp, "版本ID:%s| ", tmp + strlen("PCI Revision ID:"));
            strcat(buf, temp);
        }
        if(NULL != (tmp = strstr(szline, "PCI Vendor ID:"))) {
            sprintf(temp, "供应商ID:%s", tmp + strlen("PCI Vendor ID:"));
            strcat(buf, temp);
        }
    }
    pclose(fp);
    strcat(buf, ")");
    tmp = buf;
    while(*tmp != '\0') {
        if(*tmp == '\n') {
            *tmp = ' ';
        }
        tmp++;
    }
    return true;
#endif
}

static int get_eth_speedfromname(const char * nicname,char * pspeed) {
#ifndef __APPLE__
	struct ifreq ifr;
	int fd;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, nicname);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		return -1;
	}

	int err;
	struct ethtool_cmd ep;

	ep.cmd = ETHTOOL_GSET;
	ifr.ifr_data = (caddr_t)&ep;
	err = ioctl(fd, SIOCETHTOOL, &ifr);
	if (err != 0) { // 如果出错退出;
		return -1;
	}

	switch (ep.speed) {
	case SPEED_10:
		sprintf(pspeed,"10Mb/s");
		break;
	case SPEED_100:
		sprintf(pspeed,"100Mb/s");
		break;
	case SPEED_1000:
		sprintf(pspeed,"1000Mb/s");
		break;
	case SPEED_2500:
		sprintf(pspeed,"2500Mb/s");
		break;
	case SPEED_10000:
		sprintf(pspeed,"10000Mb/s");
		break;
	default:
		sprintf(pspeed,"UnKown");
		break;
	};

#else //APPLE_HERE

#endif
	return 0 ;
}

///获取网卡速率
static int get_eth_speed(char *buf,int bufsize) {
#ifndef __APPLE__
	char val[128]="";

    std::list<std::string>      niclst;
    YCommonTool::get_Nicinfo(niclst) ;

    std::list<std::string>::iterator iter = niclst.begin();
    while(iter != niclst.end()) {
    	if(get_eth_speedfromname(iter->c_str(),val) == 0) {
    		sprintf(buf + strlen(buf),"%s: %s ;",iter->c_str(),val);
    	}
    	iter++ ;
    }
    return 0;
#else //APPLE_HERE
     sprintf(buf, "%s", "--");
     return true;
#endif
}

static int str_to_num(char *strNum) {
    char *head;
    head = strNum;
    while (isdigit(*head)) {
        head++;
    }
    *head = 0;
    return atoi(strNum);
}

///获取内存使用情况
static int get_mem_space(char *buf,int bufsize) {
#ifndef __APPLE__
    char cmd[128]= {0};
    char name[32]= {0};
    char szResult[256] = "";
    char szTemp[128] = "";

    snprintf(name,32,"%s","MemTotal");
    snprintf(cmd,128,"cat /proc/meminfo |grep '%s'",name);
    char * pVal = info_search(cmd,name,szResult,256);

    //初始化返回字符串
    *buf = '\0';
    trimEnter(pVal);
    //赋值
    snprintf(szTemp,128,"%s:%s;","内存总数",pVal);
    strncat(buf,szTemp,strlen(szTemp)+1);

    //record MemTotal
    int memTotal=0;
    memTotal=str_to_num(pVal);
    if(memTotal == 0) {
    	return -1;
    }

    snprintf(name,32,"%s","MemFree");
    snprintf(cmd,128,"cat /proc/meminfo |grep '%s'",name);
    memset(szResult,0,strlen(szResult));
    pVal = info_search(cmd,name,szResult,256);
    if(pVal) {
        trimEnter(pVal);
        snprintf(szTemp,128,"%s:%s;","内存可用数",pVal);
        strncat(buf,szTemp,strlen(szTemp)+1);
    }
    int memFree=0;
    memFree=str_to_num(pVal);

	snprintf(szResult,256,"%d%%",(100*(memTotal-memFree))/memTotal);
	snprintf(szTemp,128,"%s:%s","内存使用率",szResult);
	strncat(buf,szTemp,strlen(szTemp)+1);
	return 0;
#else  //APPLE_HERE
    return exe_cmd_hd(MEM_SPACE_CMD, buf, bufsize);
#endif

}

static int get_disk_space(char *buf,int bufsize) {
#ifndef __APPLE__
    //A.获取磁盘使用信息
    char  buffer[1024];
    FILE *fp=NULL;

    char  device[1024];
    float size;
    float used;
    float free;

    char temp[1024];
    *buf = '\0';

    fp=popen("df -P|grep /","r");

    while(fgets(buffer,1024,fp) != NULL) {
        sscanf(buffer,"%s %f %f %f",device,&size,&used,&free);
        snprintf(temp,sizeof(temp),"%s 总容量：%.2fG 使用容量：%.2fG 剩余容量：%.2fG;",device,size/1024/1024,used/1024/1024,free/1024/1024);
        strncat(buf,temp,bufsize);
    }

    pclose(fp);

    int len = strlen(buf);
    *(buf+len-1) = '\0';

    return 0;

#else  //APPLE_HERE
    FILE * fp = popen(DISK_SPACE_CMD, "r");
    if(fp == NULL) {
        return false;
    }
    char buffer[BUFFER_SIZE];
    char temp[BUFFER_SIZE];
    char device[128];
    float size;
    float used;
    float free;

    while(fgets(buffer,1024,fp) != NULL) {
        sscanf(buffer,"%s %f %f %f",device,&size,&used,&free);
        snprintf(temp,sizeof(temp),"%s 总容量：%.2fG 使用容量：%.2fG 剩余容量：%.2fG;",device,size/1024/1024,used/1024/1024,free/1024/1024);
        strncat(buf,temp,bufsize);
        bufsize -= strlen(temp);
    }
    pclose(fp);
    return true;
#endif

}



CDeviceinfoHelper::CDeviceinfoHelper() {


}

CDeviceinfoHelper::~CDeviceinfoHelper() {

}

std::string & CDeviceinfoHelper::getAssetVal(int type) {
	CDeviceInfoMap::iterator iter = m_devmap.find(type) ;
	if(iter != m_devmap.end()) {
		return iter->second ;
	}
	char  buffer[1024] = "" ;
	switch(type) {
	case asset_cpu:{
			get_cpu_name(buffer,1024);
			m_devmap[type] = buffer ;
			return  m_devmap[type];
		}
	}
	return m_strFront;
}

bool   CDeviceinfoHelper::getfrot() {
	m_strFront = "";
	char  buffer[1024] = "" ;

	get_cpu_id(buffer,1024);
	trimEnter(buffer);
	m_strFront = m_strFront +"ProcessorSerialNumber="+buffer+STRITEM_TAG_END;
	m_strFront = m_strFront +"ProcessorNameString="+getAssetVal(asset_cpu)+STRITEM_TAG_END;

	memset(buffer,'\0',sizeof(buffer));
	get_cpu_hz(buffer,1024);
	trimEnter(buffer);
	m_strFront = m_strFront +"MHZ="+buffer+"MHZ" + STRITEM_TAG_END;

	memset(buffer,'\0',sizeof(buffer));
	gethostname(buffer,256);
	m_strFront = m_strFront +"ComputerName="+buffer+STRITEM_TAG_END;

	m_strFront = m_strFront +"WindowVersion=--"+STRITEM_TAG_END;

	memset(buffer,'\0',sizeof(buffer));
	get_os_type(buffer,1024);
	trimEnter(buffer);
	m_strFront = m_strFront +"BuildNumber="+buffer+STRITEM_TAG_END;

	m_strFront = m_strFront +"WindowsServicePack=--" + STRITEM_TAG_END;

	memset(buffer,'\0',sizeof(buffer));
	get_sys_defaultLang(buffer,1024);
	m_strFront = m_strFront +"SystemDefaultLang="+buffer+STRITEM_TAG_END;

	m_strFront = m_strFront +"IEVersion=--" + STRITEM_TAG_END;

	std::string tmp ;
	g_GetlcfgInterface()->get_lconfig(lcfg_regip,tmp);
	m_strFront = m_strFront +"ADAPTER0IPAddress0="+tmp+STRITEM_TAG_END;
	m_strFront = m_strFront +"ADAPTER0IPAddressCount=1"  + STRITEM_TAG_END;

	g_GetlcfgInterface()->get_lconfig(lcfg_regmac,tmp);
	m_strFront = m_strFront +"ADAPTER0MACAddress="+tmp+STRITEM_TAG_END;
	m_strFront = m_strFront +"AdapterCount=1"  + STRITEM_TAG_END;

	return true ;
}

bool   CDeviceinfoHelper::init() {
	m_devmap.clear();

	/**
	 * 先获取磁盘信息
	 */

	char  buffer[1024] = "" ;
	std::string         desc ;
	std::list<std::string>  diskArray;
	get_disk_name(diskArray, "sd"); ///STAT硬盘
	
	//get_disk_name(diskArray, "hd"); ///IDE硬盘
	if(diskArray.size() == 0) {
		get_disk_name(diskArray, "root");
		if(diskArray.size() == 0) {
			return false ;
		}
	}

		
	std::list<std::string>::iterator iter = diskArray.begin();
	while(iter != diskArray.end()) {
		memset(buffer,0,sizeof(buffer));
		get_diskType_info(iter->c_str(),buffer,1024);
		desc = desc + (*iter + ": " + buffer + "|");
		iter++ ;
	}
	m_devmap[asset_hd] = desc ;

	///光驱
	memset(buffer,0,strlen(buffer));
	get_cdrom_desc(buffer,1024);
	trimEnter(buffer);
	m_devmap[asset_cd] = buffer ;

	///处理器
	memset(buffer,0,strlen(buffer));
	get_cpu_name(buffer,1024);
	trimEnter(buffer);
	m_devmap[asset_cpu] = buffer ;

	///主板
	memset(buffer,0,strlen(buffer));
	get_baseboard_name(buffer,1024);
	trimEnter(buffer);
	m_devmap[asset_mbd] = buffer ;

	///内存
	memset(buffer,0,strlen(buffer));
	get_mem_total(buffer,1024);
	trimEnter(buffer);
	m_devmap[asset_mem] = buffer ;

	///显卡
	memset(buffer,0,strlen(buffer));
	get_monitor_info(buffer,1024);
	trimEnter(buffer);
	m_devmap[asset_vc] = buffer ;

	///键盘
	memset(buffer,0,strlen(buffer));
	get_keyboard_name(buffer,1024);
	trimEnter(buffer);
	m_devmap[asset_kb] = buffer ;

	///鼠标
	memset(buffer,0,strlen(buffer));
	get_mouse_name(buffer,1024);
	trimEnter(buffer);
	m_devmap[asset_mouse] = buffer ;

	///声音
	memset(buffer,0,strlen(buffer));
	get_audio_info(buffer,1024);
	trimEnter(buffer);
	m_devmap[asset_svctl] = buffer ;

	///网卡
	memset(buffer,0,strlen(buffer));
	get_eth_name(buffer,1024);
	trimEnter(buffer);
	m_devmap[asset_nic] = buffer ;

	///软盘驱动器
	memset(buffer,0,strlen(buffer));
	get_floppy_info(buffer,1024);
	trimEnter(buffer);
	m_devmap[asset_fd] = buffer ;

	///系统插槽
	memset(buffer,0,strlen(buffer));
	get_slot_info(buffer,1024);
	trimEnter(buffer);
	m_devmap[asset_slot] = buffer ;

	///USB接口
	memset(buffer,0,strlen(buffer));
	get_usb_info(buffer,1024);
	trimEnter(buffer);
	m_devmap[asset_usb] = buffer ;

	///网卡速率
	memset(buffer,0,strlen(buffer));
	get_eth_speed(buffer,1024);
	trimEnter(buffer);
	m_devmap[asset_nic_speed] = buffer ;

	///内存使用情况
	memset(buffer,0,strlen(buffer));
	get_mem_space(buffer,1024);
	trimEnter(buffer);
	m_devmap[asset_mem_used] = buffer ;

	///硬盘使用情况
	memset(buffer,0,strlen(buffer));
	get_disk_space(buffer,1024);
	trimEnter(buffer);
	m_devmap[asset_hd_used] = buffer ;

	getfrot();

	return true ;
}


void  CDeviceinfoHelper::check(CDeviceInfoMap & oldmap,
			CDeviceInfoMap & addmap ,
			CDeviceInfoMap & delmap ,
			CDeviceInfoMap & modifymap) {
	/**
	 * 查找新加的和修改的。
	 */
	CDeviceInfoMap::iterator  iter = m_devmap.begin();
	while(iter != m_devmap.end()) {
		CDeviceInfoMap::iterator iterold = oldmap.find(iter->first);
		if(iterold != oldmap.end()) { ///找见了
		    if(iterold->first != asset_mem_used){
		        if(iter->second != iterold->second) { ///修改
		            modifymap[iter->first] = iter->second ;
		        }
		    }
		    oldmap.erase(iterold);
			iter++;
			//m_devmap.erase(iter++);
			continue ;
		} else { ///没找见，新加的。
			addmap[iter->first] =iter->second;
		}
		iter++ ;
	}

	/**
	 * 查找删除的
	 */
	iter = oldmap.begin() ;
	while(iter != oldmap.end()) {
		CDeviceInfoMap::iterator iterNew = m_devmap.find(iter->first);
		if(iterNew == m_devmap.end()) {
			delmap[iter->first] = iter->second ;
		}
		iter++ ;
	}
}
