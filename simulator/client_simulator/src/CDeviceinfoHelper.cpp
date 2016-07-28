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
#include "cli_config.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <linux/hdreg.h>
#include <scsi/sg.h>

#ifndef SIOCETHTOOL
#define SIOCETHTOOL     0x8946
#endif
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif




static void trimEnter(char * pStr) {
	int len = strlen(pStr);
	if(len == 0) {
		return ;
	}
	if(*(pStr+len-1) == '\n') {
		*(pStr+len-1) = 0 ;
	}
}

///获取CPU型号
static  int get_cpu_name(char *buf,int bufsize) {
    (void)(bufsize);
    strcpy(buf, "INTEL+LONGXIN+SW");
    return 1;
}
///获取CPUID
static int get_cpu_id(char *buf,int bufsize) {
    (void)(bufsize);
    strcpy(buf, "FAKE-CPU-ID:xxxxxxxx");
    return 0;
}
///获取CPU频率
static int get_cpu_hz(char *buf,int bufsize) {
    (void)(bufsize);
    strcpy(buf, "3000000");
    return 0;
}
#if 0
///获取主机名
static int get_sys_hostname(char *buf,int bufsize) {
    (void)(bufsize);
    strcpy(buf, "fake_host_name");
	return 0;
}
#endif

///获取操作系统版本
int get_os_type(char *buf,int bufsize,bool hasR = true) {
    (void)(bufsize);
    strcpy(buf, "os_linux_fake_type");
	return 1;
}

static int get_sys_defaultLang(char *buf,int bufsize) {
    (void)(bufsize);
    strcpy(buf,"CHINESE");
	return 1;
}


///获取内存总量
static int get_mem_total(char *buf,int bufsize) {
    (void)(bufsize);
    strcpy(buf, "10000MB");
    return 0;
}

///获取显卡
static int get_monitor_info(char *buf,int bufsize) {
    (void)(bufsize);
    strcpy(buf,"VGA compatible controller");
	return 0 ;
}

///键盘
static int get_keyboard_name(char *buf,int bufsize) {
    (void)(bufsize);
    strcpy(buf,"Keyboard");
    return 0;
}

///声音，视频控制器
static int get_audio_info(char *buf,int bufsize) {
    (void)(bufsize);
    strcpy(buf,"Audio Device");
	return 0;
}

static int get_mouse_name(char *buf,int bufsize) {
    (void)(bufsize);
    strcpy(buf,"Mouse");
    return 0;
}

static int get_eth_name(char *buf,int bufsize) {
    (void)(bufsize);
    strcpy(buf,"Ethernet controller");
    return 0;
}

static int get_floppy_info(char *buf,int bufsize) {
    (void)(bufsize);
    strcpy(buf,"FLOPPY");
    return 1;
}

static int get_slot_info(char *buf,int bufsize) {
    (void)(bufsize);
    strcpy(buf,"PCI SLOT");
    return 0;
}

///获取USB信息
static int get_usb_info(char *buf,int bufsize) {
    (void)(bufsize);
    strcpy(buf,"USB Controller");
    return 0;
}

///获取网卡速率
static int get_eth_speed(char *buf,int bufsize) {
    (void)(bufsize);
    strcpy(buf,"1000");
    return 0;
}

#if 0
static int str_to_num(char *strNum) {
    char *head;
    head = strNum;
    while (isdigit(*head)) {
        head++;
    }
    *head = 0;
    return atoi(strNum);
}
#endif

///获取内存使用情况
static int get_mem_space(char *buf,int bufsize) {
    (void)(bufsize);
    char szTemp[128] = "";

    snprintf(szTemp,128,"%s:%s;","内存总数", "1024M");
    strncat(buf,szTemp,strlen(szTemp)+1);

    snprintf(szTemp,128,"%s:%s;","内存可用数","512M");
    strncat(buf,szTemp,strlen(szTemp)+1);

	snprintf(szTemp,128,"%s:%s","内存使用率","50");
	strncat(buf,szTemp,strlen(szTemp)+1);
	return 0;
}

static int get_disk_space(char *buf,int bufsize) {

    char temp[1024] = {0};

    snprintf(temp,sizeof(temp),"%s 总容量：%.2fG 使用容量：%.2fG 剩余容量：%.2fG;",
            "device",500.0,250.0,250.0);
    strncat(buf,temp,strlen(temp));

    int len = strlen(buf);
    *(buf+len-1) = '\0';

    return 0;
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
    tmp = "x.x.x.x";
	m_strFront = m_strFront +"ADAPTER0IPAddress0="+tmp+STRITEM_TAG_END;
	m_strFront = m_strFront +"ADAPTER0IPAddressCount=1"  + STRITEM_TAG_END;

    tmp = "xx:xx:xx:xx:xx:xx";
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
	m_devmap[asset_hd] = "sda fake disk_info";

	///光驱
	m_devmap[asset_cd] = "fake_cd_rom" ;

	///处理器
	memset(buffer,0,strlen(buffer));
	get_cpu_name(buffer,1024);
	m_devmap[asset_cpu] = buffer ;

	///主板
	m_devmap[asset_mbd] = "main_board" ;

	///内存
	memset(buffer,0,strlen(buffer));
	get_mem_total(buffer,1024);
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
	m_devmap[asset_svctl] = buffer ;

	///网卡
	memset(buffer,0,strlen(buffer));
	get_eth_name(buffer,1024);
	trimEnter(buffer);
	m_devmap[asset_nic] = buffer ;

	///软盘驱动器
	memset(buffer,0,strlen(buffer));
	get_floppy_info(buffer,1024);
	m_devmap[asset_fd] = buffer ;

	///系统插槽
	memset(buffer,0,strlen(buffer));
	get_slot_info(buffer,1024);
	m_devmap[asset_slot] = buffer ;

	///USB接口
	memset(buffer,0,strlen(buffer));
	get_usb_info(buffer,1024);
	m_devmap[asset_usb] = buffer ;

	///网卡速率
	memset(buffer,0,strlen(buffer));
	get_eth_speed(buffer,1024);
	m_devmap[asset_nic_speed] = buffer ;

	///内存使用情况
	memset(buffer,0,strlen(buffer));
	get_mem_space(buffer,1024);
	m_devmap[asset_mem_used] = buffer ;

	///硬盘使用情况
	memset(buffer,0,strlen(buffer));
	get_disk_space(buffer,1024);
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
