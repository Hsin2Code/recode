/**
 * CYApp.cpp
 *
 *  Created on: 2014-11-26
 *      Author: sharp
 */

#include "CYApp.h"
#include <string.h>
#include "common/CLocker.h"
#include "common/Commonfunc.h"
#include <stdlib.h>
#include <iostream>

#ifndef __APPLE__
#include <sys/sysinfo.h>
#else
#include <libgen.h>
#endif

int CYApp::tag_timerinfo::gtimerId = 1 ;

///最小的定时器执行间隔，10毫秒
static const  int  timer_min_interval = 10;

void * cyapp_timer(void * pparam) {
	CYApp * pApp = (CYApp *)pparam ;
	return pApp->cyapp_timer_helper();
}

bool cyapp_msgwork_helper(unsigned short cmd , PVOID buffer , int len , void * param,unsigned int id) {
	CYApp * pApp = (CYApp *)param;
	return pApp->msg_proc(cmd,buffer,len,id);
}

bool cyapp_timermsg_helper(unsigned short cmd , PVOID buffer , int len , void * param,unsigned int id) {
	CYApp * pApp = (CYApp *)param;
	return pApp->timer_proc(cmd,buffer,len,id);
}

void CYApp::yapp_construction() {
	m_strModulePath = get_AppabspathAndName(m_strModuleName);
	m_nMainChannel = -1;
	m_nTimerChannel = -1;
	m_timtrd = 0 ;
	m_pTimerLock = new YCommonTool::CLocker ;
	srand(YCommonTool::get_Timesec());
	m_nUsercnt = 0 ;
	memset(m_userTimer,-1,sizeof(m_userTimer));
}
CYApp::CYApp(int argc, char ** argv,int ntrd) : IMsgdispatcher(ntrd){
	if(argc) {
		for(int i = 0 ; i < argc ; i++) {
			char * pCmd = *(argv+i);
			std::string strcmd = pCmd ;
			m_argList.push_back(strcmd);
		}
	}
	yapp_construction();
}

CYApp::CYApp(int ntrd) :IMsgdispatcher(ntrd) {
	yapp_construction();
}

CYApp::~CYApp() {

}

std::string   CYApp::get_AppabspathAndName(std::string & name) {
    char absolute_path[4096]= "";
    /*if we don't use proc then linux same as osx*/
    int cnt = 0;
    char app_name[256] = "";
#ifndef __APPLE__
    /**
     * 获取当前程序绝对路径
     */
    cnt = readlink("/proc/self/exe", absolute_path, 4096);
    if (cnt < 0 || cnt >= 4096) {
        return "";
    }
#else
    (void)getcwd(absolute_path, sizeof(absolute_path) - 1);
    const char *pg_name = getprogname();
    strcat(absolute_path, "/");
    strcat(absolute_path, pg_name);
    cnt = strlen(absolute_path);
#endif
    /**
     * 获取当前目录绝对路径，即去掉程序名
     */
    int i;
    for (i = cnt; i >=0; --i) {
        if (absolute_path[i] == '/') {
            strcpy(app_name,&(absolute_path[i+1]));
            absolute_path[i+1] = '\0';
            break;
        }
    }
    name = app_name ;
    std::cout << " appen  nn n n" << name << std::endl;
    return absolute_path;
}



bool  CYApp::InitInstances()
{
	/**
	 * 启动后不能再调用
	 * */

	if(m_nMainChannel>=0) return true ;

	sigemptyset(&m_runset);
	sigaddset(&m_runset,SIGUSR2);
	pthread_sigmask(SIG_BLOCK, &m_runset , NULL);
	/**
	 * 注册主消息处理线程
	 */
	char szChannel[100] = "";
	sprintf(szChannel,"%p",this);
	m_nMainChannel = registerDispatcher(szChannel
				,cyapp_msgwork_helper
				,1,this);
	if(m_nMainChannel < 0) {
		return false ;
	}
	sprintf(szChannel,"%p_timer!",this);
	m_nTimerChannel =  registerDispatcher(szChannel
			,cyapp_timermsg_helper
			,1,this);
	if(m_nTimerChannel < 0) {
		return false ;
	}

	/**
	 * 启动定时器线程
	 */
	m_btimerRuning = true ;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	int policy = 0 ;
	int rc = 0 ;
	pthread_attr_getschedpolicy( &attr, &policy );
	struct   sched_param   param;
	switch(policy) {
	case SCHED_FIFO:
		 param.sched_priority  = sched_get_priority_max(policy);
		 printf("SCHED_FIFO pri = %d\n",param.sched_priority);
		 pthread_attr_setschedparam(&attr,   &param);
		 rc = pthread_create(&m_timtrd,&attr,cyapp_timer,(void *)this);
	     break;

	case SCHED_RR:
		 param.sched_priority = sched_get_priority_max(policy);
		 printf("SCHED_RR pri = %d\n",param.sched_priority);
		 pthread_attr_setschedparam(&attr,   &param);
		 rc = pthread_create(&m_timtrd,&attr,cyapp_timer,(void *)this);
	     break;

	case SCHED_OTHER:
		 printf("SCHED_OTHER \n");
		 rc = pthread_create(&m_timtrd,NULL,cyapp_timer,(void *)this);
	     break;
	}
	pthread_attr_destroy(&attr);
	if(rc != 0) {
		return false ;
	}

	return true ;
}

int  CYApp::ExitInstances(int extid) {

	/**
	 * 关闭所有通道
	 */
	printf("CYApp::ExitInstances\n");
	stopDispatcher();

	if(m_nMainChannel != -1) {
		m_nMainChannel = -1 ;
	}
	if(m_nTimerChannel != -1) {
		m_nTimerChannel = -1 ;
	}
	printf("CYApp::ExitInstances1\n");
	return extid;
}

int   CYApp::exec() {
	if(!InitInstances()) {
		return ExitInstances(-1);
	}

	/**
	 *  等待信号
	 */
	int sig = 0 ;
	int ret = sigwait(&m_runset,&sig);

	if(ret < 0) {
		printf("sigwait ret error ret = %d\n",ret);
	}

	return ExitInstances(0) ;
}

void  CYApp::quit() {
   /**
    * 发送消息
    */

	if(m_nMainChannel != -1) {
	   sendtoDispatcher(m_nMainChannel,YAPP_CMD_QUIT) ;
    }

}

void  *  CYApp::cyapp_timer_helper() {
	using  namespace  YCommonTool ;

	int sleep_inerval = timer_min_interval * 1000;
	int index = 0 ;
	time_t tm = YCommonTool::get_Startpmsec();

	while(m_btimerRuning) {
		tm = YCommonTool::get_Startpmsec();
		for(index = 0 ; index < m_nUsercnt ; index++) {
			tag_timerinfo & info = m_timerArray[m_userTimer[index]];
			if(info.buse == 1) { ///启用
				if(tm - info.lastexec >= info.interval) {
					sendtoDispatcher(m_nTimerChannel,YAPP_CMD_TIMER,(void *)(&(info.id)),sizeof(info.id),0,false,false);
					if(!info.bloop) {
						info.buse = 0 ;
					}
					info.lastexec = tm ;
				}
			}
		}
		///10豪秒
		usleep(sleep_inerval);
	}

	return (void *) 0 ;
}


bool  CYApp::timer_proc(unsigned short cmd , PVOID buffer, int len,unsigned int id) {
	if(YAPP_CMD_TIMER == cmd) {
		int * pID = (int *)buffer ;
		return timer_proc(*pID);
	}
	return true ;
}

bool  CYApp::msg_proc(unsigned short cmd , PVOID buffer, int len,unsigned int id) {
	switch(cmd) {
		case YAPP_CMD_QUIT: { ///app退出
			/**
			 * 定时器退出
			 */
			m_btimerRuning = false ;
			void *status = 0;
			pthread_join(m_timtrd,&status);
			if(m_nTimerChannel != -1) {
				stopDispatcher(m_nTimerChannel) ;
				m_nTimerChannel = -1 ;
			}
			kill(getpid(),SIGUSR2);
			return true ;
		}
	}

	return true ;
}

bool CYApp::timer_Isloop(int id) {
	if(id >= max_timer_cnt
			|| id < 0) {
		return false ;
	}
	if(m_timerArray[id].buse) {
		return false ;
	}
	return m_timerArray[id].bloop;
}

int  CYApp::set_Timer(unsigned  int interval , void * pParam,bool bloop)
{
	if(m_nMainChannel< 0
			|| m_btimerRuning == false ) return -1 ;

	///寻找没有使用的定时器
	int index = 0 ;
	for(index = 0 ; index < max_timer_cnt ; index++) {
		if(m_timerArray[index].buse == 0) {
			m_timerArray[index].buse = 1 ;
			break ;
		}
	}
	if(index >= max_timer_cnt) {
		return -1 ;
	}

	tag_timerinfo & info  = m_timerArray[index];
	info.id = index ;
	if(interval == 0) {
		interval = 1 ;
	}
	info.interval = interval  ; ///
	info.pparam   = pParam  ;
	info.lastexec = YCommonTool::get_Startpmsec()  ;
	info.bloop    = bloop ;

	///给使用的数组赋值

	int usrcnt = 0 ;
	for(index = 0 ; index < max_timer_cnt ; index++) {
		if(m_timerArray[index].buse) {
			m_userTimer[usrcnt++] = index ;
		}
	}

	m_nUsercnt = usrcnt ;
	return info.id ;
}

void  *  CYApp::kill_timer(int id) {

	using  namespace  YCommonTool ;
	void * pparam = (void *)0 ;
	if(id < 0 || id >= max_timer_cnt) {
		return pparam ;
	}

	m_timerArray[id].buse = 0 ;
	int usrcnt = 0 ;
	for(int index = 0 ; index < max_timer_cnt ; index++) {
		if(m_timerArray[index].buse) {
			m_userTimer[usrcnt++] = index ;
		}
	}
	m_nUsercnt = usrcnt ;
	return m_timerArray[id].pparam ;
}

const void *  CYApp::getTimerParam(int id)  {
	 using namespace YCommonTool ;

	 if(id < 0 || id >= max_timer_cnt) {
	 	return 0 ;
	 }

	 return m_timerArray[id].pparam ;
}

bool CYApp::sendmsg(int id ,
			unsigned short cmd ,
			PVOID pData,
			int len) {
	return sendtoDispatcher(id,cmd,pData,len,0,true);
}

bool CYApp::postmsg(int id,
		    unsigned short cmd ,
		    PVOID pData ,
		    int len,int sendid) {
	return sendtoDispatcher(id ,cmd , pData , len , sendid , false );
}
