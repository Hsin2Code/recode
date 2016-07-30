/*
 * main.cpp
 *
 *  Created on: 2014-11-24
 *      Author: sharp
 */
#include <stdlib.h>
#include <stdio.h>
#include "CYApp.h"
#include "common/CYlog.h"
#include "CVCFApp.h"
#include "../include/Markup.h"
#include  <sys/file.h>
#include "../include/Netko.h"
/*#include "../include/unlink.h"*/
#include "CEdpApp.h"

#include "ldbdefine.h"

dbDatabase      m_db;
int  bufffer[1024]={0};
using namespace std;


CEdpApp  *  g_pApp  = 0;

std::string   strxml = "<?xml version=\"1.0\" encoding=\"utf-8\"?> <vrvscript><item>2</item><item>3</item></vrvscript>";

bool  import_xml(const char * pxml) {
	if(pxml == NULL) {
		return false ;
	}

	CMarkup  xml ;
	if(!xml.SetDoc(pxml)) {
		return false ;
	}

	if(xml.FindElem("vrvscript")) {
		xml.IntoElem();
		while(xml.FindElem("item")) {
			std::string tmp = xml.GetData();
			printf("itemval = %s\n",tmp.c_str());
		}
		xml.OutOfElem();
	}
	return true ;
}

void sig_handle(int signo) ;



/**
 * 记录启动日志
 */
void  record_startlog() {
	char strtime[128]={0};
	char filename[128]={0};
	time_t timep;
	struct tm *p;
	time(&timep);
	p = localtime(&timep);
	snprintf(filename, sizeof(filename)-1,"%d-%02d-%02d.log", (1900 + p->tm_year),
			(1 + p->tm_mon), p->tm_mday);
	snprintf(strtime, sizeof(strtime)-1,"%d-%02d-%02d %02d:%02d:%02d", (1900 + p->tm_year),
			(1 + p->tm_mon), p->tm_mday, p->tm_hour, p->tm_min,p->tm_sec);
	FILE *fp = fopen("start_log","a+");
	if(NULL == fp) {
		return ;
	}
	fprintf(fp,"[%s] is starting pid=%d\n",strtime,getpid());
	fclose(fp);
}

int detect_process(char * process_name)
{
    char buf[512]={0};
    char ps[128]={0};
    sprintf(ps, "pgrep %s", process_name);
    FILE *fp = popen(ps, "r");
    if(NULL == fp) {
        return -1;
    }
    int i = 0 ;
    while(fgets(buf, sizeof(buf) - 1, fp)) {
    	i++ ;
    }
    pclose(fp);

    return i ;
}



bool  check_lock() {
	/**
	 * 启动数大于2个
	 */
	if(detect_process(EDP_SVRAPP_NAME)>1) {
		return false ;
	}

    extern void checkWatchV();
    checkWatchV();
	return true;
}
#include <stdint.h>
#include "vrvprotocol/VRVProtocol.hxx"

int  main() {
	///注册信号处理函数
	signal(SIGINT,sig_handle);
	signal(SIGQUIT,sig_handle);
	///不能被挂起
	signal(SIGSTOP,sig_handle);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, sig_handle);
	//signal(SIGTERM)

	/*todo replace as read and write*/

    /*
	system("echo \"/opt/edp_vrv/lib/libunlink.so\" > /etc/ld.so.preload");
	system("ldconfig");
	set_fake_flag(1);
    */
	if(!check_lock()) {
		printf("程序已经启动\n");
		return 0 ;
	}

	CEdpApp  g_app ;
	record_startlog();
	g_pApp = &g_app;

	g_app.exec() ;
	

	///卸载网络内核模块
#if 0
#ifdef HW_X86
	if(0 == access("/sys/module/EdoNetko", 0)) {
		char cmd[32]="";
		sprintf(cmd,"rmmod %s",EDP_NETKO);
		system(cmd);
	}
#endif
#endif
	printf("app quit\n");
	return 0 ;
}


void sig_handle(int signo) {
	if(signo == SIGINT
			|| signo == SIGQUIT || signo == SIGTERM) {
        /*2 == CLIENT_STOP*/
        extern void report_status_to_server(int client);
        report_status_to_server(2);
		if(g_pApp) {
			///恢复网络
			if(g_GetlcfgInterface()->get_offlstat()) {
				if(!g_pApp->get_AlawaysOffline()) {
					g_pApp->openNet();
				}
			}
			g_pApp->quit();
		}
	}
}


///获取发送接口指针
IVCFAppSendinterface * g_GetSendInterface() {
	return static_cast<IVCFAppSendinterface *>(g_pApp);
}

///获取日志指针
ILocalogInterface * g_GetlogInterface() {
	return static_cast<ILocalogInterface *>(g_pApp);
}

///获取网络回调指针
INetEngineSinkinterface * g_GetNetEnginesinkInterface() {
	return static_cast<INetEngineSinkinterface *>(g_pApp);
}

///获取本地配置接口
ILocalCfginterface * g_GetlcfgInterface() {	
	return static_cast<ILocalCfginterface *>(g_pApp);
}

///获取改变消息接口
IEventNotifyInterface * g_GetEventNotifyinterface() {
	return static_cast<IEventNotifyInterface *>(g_pApp);
}

