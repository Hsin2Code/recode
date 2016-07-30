/*
 * CIMCSrv.cpp
 *
 *  Created on: 2014-12-2
 *      Author: sharp
 */

#include "CIMCSrv.h"
#include "include/zmq/zmq.h"
#include "string.h"
#include <unistd.h>
#include "common/Commonfunc.h"
#include "common/CLocker.h"
#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <exception>
#include <stdint.h>
#include "VCFCmdDefine.h"

extern ILocalogInterface * g_GetlogInterface();

static  unsigned  int startport = 17690 ;
using namespace YCommonTool;

struct tag_callCli {
	///进程调用临时ID
	int    callid ;
	CIMCSrv * pSrv ;
};

void *  pIMCSrv_worker(void * pSrv) {
	CIMCSrv * _pSrv = (CIMCSrv *)pSrv ;
	_pSrv->Running() ;
	return  0 ;
}
void *  pIMCSrv_callCli(void * pCall) {
	tag_callCli * _pCall = (tag_callCli *)pCall ;
	_pCall->pSrv->cli_running(_pCall->callid);
	delete _pCall ;

	return 0 ;
}

///获取服务器地址
static  bool   set_EdpSAddr(const char * pAddr) {
	FILE * fp = fopen(TRAY_ADDR,"w");
	if(fp == NULL) {
		return false ;
	}
	fputs(pAddr,fp);
	fclose(fp);
	return true ;
}

CIMCSrv::CIMCSrv() {
	m_trdid = 0 ;
	m_brunning = false ;
	m_pSrv = 0 ;
	m_pSink = NULL ;
	m_pPub = NULL ;
	m_nidIndex = rand()  ;
	try {
		m_pMaplock = new CLocker ;
	} catch(std::exception & e) {
		
	}
}
CIMCSrv::~CIMCSrv() {
	close();
	if(m_pMaplock) {
		delete (CLocker *)m_pMaplock ;
		m_pMaplock =  0 ;
	}
}

bool  CIMCSrv::Create(const char * pname , IMCSrvsinkinterface * pSink) {
	if(m_pSrv) {
		return false ;
	}
	if(strlen(pname) > 32) {
		printf("CIMCSrv::Create name too long!\n");
		return false ;
	}
	/**
	 * 启动问答服务器
	 **/
	char buffer[64]  = "";
	m_pSrv =  zmq_socket(pSink->get_Ctx(),ZMQ_REP);
	m_pSink = pSink   ;
bind_again1:
	sprintf(buffer,"tcp://127.0.0.1:%d",startport++);
	m_strname = buffer ;
	int rc = zmq_bind(m_pSrv,buffer);
	if(rc < 0)  {
		goto bind_again1;
	}

	/**
	 * 启动广播服务器
	 */
	//m_strPubName = m_strname  + "-pub";
	m_pPub = zmq_socket(pSink->get_Ctx(),ZMQ_PUB);
bind_again2:
	sprintf(buffer,"tcp://127.0.0.1:%d",startport++);
	m_strPubName = buffer;
	rc = zmq_bind(m_pPub,m_strPubName.c_str());
	if(rc < 0)  {
		goto bind_again2 ;
	}

	///记录服务器地址到文件
	set_EdpSAddr(m_strname.c_str());

	///启动线程
	m_brunning = true ;
	rc = pthread_create(&m_trdid,NULL,pIMCSrv_worker,(void *)this);
	if(rc != 0) {
		return false  ;
	}
	return true  ;
}

bool   CIMCSrv::call_Exit(int id) {
	char * p = const_cast<char *>("name is id , exit please!");
	return pub_msg(id,MC_CMD_S2C_QUIT,p,strlen(p));
}

bool   CIMCSrv::isTray(int id) {
	CLockHelper helper((CLocker *)m_pMaplock);
	std::map<int,tag_Cli>::iterator  iter = m_cliMap.find(id);
	if(iter != m_cliMap.end()) {
		return iter->second.bTray;
	}
	return false;
}

bool   CIMCSrv::hasTray() {
	CLockHelper helper((CLocker *)m_pMaplock);
	std::map<int,tag_Cli>::iterator iter = m_cliMap.begin();
	while(iter != m_cliMap.end()) {
		if(iter->second.bTray) {
			return true ;
		}
		iter++ ;
	}
	return false ;
}

bool   CIMCSrv::pub_msg_4tray(unsigned short cmd, void * pdata, int len) {
	if(m_pPub) {
		CLockHelper helper((CLocker *)m_pMaplock);
		std::map<int,tag_Cli>::iterator iter = m_cliMap.begin();
		while(iter != m_cliMap.end()) {
			if(!pub_msg(iter->second.id,cmd,pdata,len)) {
				return false ;
			}
			iter++ ;
		}
	}
	return true ;
}

bool   CIMCSrv::pub_msg(int id,unsigned short cmd,void * pdata, int len) {
	if(m_pPub) {
		zmq_msg_t msg_t ;
		zmq_msg_init_size(&msg_t,sizeof(tag_MCMsg) + len);
		tag_MCMsg * pmsg = (tag_MCMsg *)zmq_msg_data(&msg_t);
		pmsg->cmd = cmd;
		pmsg->id =  id ;
		pmsg->pid = getpid();
		memcpy(pmsg->data,pdata,len);
		pmsg->len = len;
		int rc = zmq_msg_send(&msg_t,m_pPub, 0);
		if(rc == -1) {
			return false ;
		}
		zmq_msg_close(&msg_t);
		return true ;
	}
	return false ;
}

void   CIMCSrv::close() {
	/*先通知客户端退出*/
	if(m_pPub) {
		const char * p = "i'm quit , follow me please!";
		pub_msg(0,MC_CMD_S2C_QUIT,(void*)p, strlen(p));
		zmq_close(m_pPub);
		m_pPub = NULL ;
		usleep(200);
	}

	///再关闭应答服务器
	if(m_pSrv) {
		m_brunning = false ;
		void * pCli = zmq_socket(m_pSink->get_Ctx(),ZMQ_REQ);
		int rc = zmq_connect(pCli,m_strname.c_str());
		if(rc == 0)  {
			zmq_msg_t msg_t ;
			zmq_msg_init_size(&msg_t,sizeof(tag_MCMsg) + sizeof(pthread_t));
			tag_MCMsg * pmsg = (tag_MCMsg *)zmq_msg_data(&msg_t);
			pmsg->cmd = 0xffff ;//退出消息
			pmsg->id =  getpid();
			pmsg->pid = pmsg->id;
			///长度定随机的
			pmsg->len = sizeof(pthread_t) ;

			pthread_t * pInt = (pthread_t *)pmsg->data;
			*pInt = m_trdid;
			int ret  =  zmq_msg_send(&msg_t,pCli, 0);

			zmq_msg_close(&msg_t);

			///接受回应
			zmq_msg_t msg_t1;
			zmq_msg_init(&msg_t1);

			ret = zmq_msg_recv(&msg_t1,pCli,0);

			zmq_msg_close(&msg_t1);
			zmq_close(pCli);
			void * status ;
			if(m_trdid) {
				pthread_join(m_trdid,&status);
			}

			zmq_close(m_pSrv);
		} else {
			///强制关闭
			zmq_close(m_pSrv);
			void * status ;
			if(m_trdid) {
				pthread_join(m_trdid,&status);
			}
		}
		m_pSrv =  0 ;
		m_trdid = 0 ;
	}

	{
		CLockHelper helper((CLocker *)m_pMaplock);
		void * pstatus = 0;
		std::map<int,tag_Cli>::iterator iter = m_cliMap.begin() ;
		while(iter != m_cliMap.end()) {
			pthread_join(iter->second.trdid,&pstatus);
			iter++ ;
		}
		m_cliMap.clear();
	}

}

bool  CIMCSrv::sendData(unsigned short cmd ,const void * pBuffer , int len) {
	if(m_pSrv == 0) {
		return false ;
	}
	zmq_msg_t msg_t ;
	zmq_msg_init_size(&msg_t,sizeof(tag_MCMsg)+len);
	tag_MCMsg * pMsg = (tag_MCMsg *)zmq_msg_data((zmq_msg_t *)&msg_t);
	if(pBuffer) {
		memcpy(pMsg->data,pBuffer,len);
	}
	pMsg->cmd = cmd ;
	pMsg->id = getpid();
	pMsg->len = len ;
	pMsg->pid = pMsg->id ;
	int nsend = zmq_msg_send(&msg_t,m_pSrv, 0);
	zmq_msg_close(&msg_t);
	return (nsend == ((int)sizeof(tag_MCMsg)+len)) ;
}

void   CIMCSrv::cli_running(int cliid) {
	tag_Cli cli ;
	if(get_Cli(cliid,cli)) {
		char szbuffer[4096] = "";
		std::string user ;
        /*VRV:TODO: change get_loginUser to get current active screen user*/
		get_loginUser(user);

		sprintf(szbuffer,"sudo -u %s %s %s %d %s '%s'",user.c_str(),cli.path.c_str()
				,m_strname.c_str()
				,cliid
				,const_cast< char *> (cli.strpw.c_str())
				,const_cast< char *> (cli.strparams.c_str()));
		
		system(szbuffer);
	} else {
		printf("CIMCSrv::cli_running is faild %d \n",cliid);
	}
}

bool  CIMCSrv::get_Cli(int id,tag_Cli & cli) {
	CLockHelper helper((CLocker *)m_pMaplock);
	std::map<int,tag_Cli>::iterator iter = m_cliMap.find(id);
	if(iter != m_cliMap.end()) {
		cli = iter->second ;
		return true ;
	}
	return false ;
}

int    CIMCSrv::exec_Cli(const char * fullPath,const char * plastArg) {

	CLockHelper helper((CLocker *)m_pMaplock);
	/**
	 * 获取随机密码
	 **/

	char buffer[33] = "" ;
	YCommonTool::get_randStr(buffer,33);
	tag_Cli cli ;
	cli.id    =  m_nidIndex++ ;
	cli.pid   =  0 ;
	cli.strpw =  buffer ;
	if(plastArg)
		cli.strparams = plastArg ;

	cli.path  =  fullPath ;
	cli.blogon = false ;
	tag_callCli * pcall = new tag_callCli ;
	if(pcall == NULL) {
		return 0 ;
	}
	pcall->callid = cli.id ;
	pcall->pSrv = this ;
	m_cliMap[cli.id]   = cli ;

	int rc = pthread_create(&(m_cliMap[cli.id].trdid),0,pIMCSrv_callCli,(void *)pcall);
    if(rc != 0) {
    	delete pcall ;
    	return 0 ;
    }
    return cli.id;
}

void  CIMCSrv::del_Cli(int id) {
	CLockHelper helper((CLocker *)m_pMaplock);
	std::map<int,tag_Cli>::iterator iter = m_cliMap.find(id) ;
	//这里不用等带线程结束
	if(iter != m_cliMap.end()) {
		m_cliMap.erase(iter);
	}
}

void  CIMCSrv::Running() {
	zmq_msg_t msg_t ;

	while(m_brunning) {
		zmq_msg_init(&msg_t);
		int ret = zmq_msg_recv(&msg_t,m_pSrv,0);

		if(ret < 0) {
			continue ;
		}

		tag_MCMsg * pMsg = (tag_MCMsg *)zmq_msg_data((zmq_msg_t *)&msg_t);
		if((pMsg->len + sizeof(tag_MCMsg)) != zmq_msg_size((zmq_msg_t *)&msg_t)) {
			printf("长度错误 %d, %lu, %lu\n",pMsg->len,sizeof(tag_MCMsg), zmq_msg_size((zmq_msg_t *)&msg_t));
			sendData(MC_CMD_S2C_BYE,NULL,0);
			continue ;
		}

		///退出信号，这个只能时自己发给自己的，其他客户端发的过滤
		if(pMsg->cmd == 0xffff) {
			pthread_t * pTrd = (pthread_t *)pMsg->data ;
			if(pMsg->id == getpid()
					&& *pTrd == m_trdid) {
				sendData(0xffff,NULL,0);
				break ;
			} else {
				sendData(0xffff,NULL,0);
			}
		} else {
			///客户端登录
			if(pMsg->cmd == MC_CMD_C2S_LOGIN) {
				tag_C2S_MClogon * pLogon = (tag_C2S_MClogon *)pMsg->data;
				CLockHelper helper((CLocker *)m_pMaplock);
				if(pLogon->cbTray == 0xff) { ///托盘登录
					if(strcmp(TRAY_PW,pLogon->pw) == 0) {
						if(!m_pSink->onLogon(pMsg->id,true,pLogon->user)) {
							sendData(MC_CMD_S2C_GOAWAY,NULL,0);
							continue ;
						}

						/**
						 * 根据用户名查找
						 */
						tag_S2CWelcome wel ;
						bool bExsit = false ;
						std::map<int,tag_Cli>::iterator iter = m_cliMap.begin();
						while(iter != m_cliMap.end()) {
							if(pLogon->user == iter->second.strparams
									&& iter->second.bTray) {
								bExsit = true ;
								wel.idforTray = iter->second.id ;
								iter->second.pid = pMsg->pid ;
								break ;
							}
							iter++ ;
						}

						if(!bExsit) {
							tag_Cli cli ;
							cli.id =  m_nidIndex++;
							cli.pid = pMsg->pid ;
							cli.blogon = true ;
							cli.bTray = true ;
							cli.strparams = pLogon->user;
							m_cliMap[cli.id] = cli;
							wel.idforTray = cli.id ;
							char  log[128]="";
							sprintf(log,"托盘id= %d, User = %s\n",cli.id,pLogon->user);
							g_GetlogInterface()->log_trace(log);
						}

						strcpy(wel.szPubAddr,m_strPubName.c_str());
						sendData(MC_CMD_S2C_WELCOME,&wel,sizeof(wel));

						continue ;
					}
				} else {
					std::map<int,tag_Cli>::iterator iter = m_cliMap.find(pMsg->id);
					if(iter != m_cliMap.end()) {
						if(iter->second.strpw == pLogon->pw) {
							if(!m_pSink->onLogon(pMsg->id)) {
								sendData(MC_CMD_S2C_GOAWAY,NULL,0);
								continue ;
							}
							iter->second.blogon = true ;
							iter->second.pid = pMsg->pid ;
							///发送登录成功
							tag_S2CWelcome wel ;
							strcpy(wel.szPubAddr,m_strPubName.c_str());
							sendData(MC_CMD_S2C_WELCOME,&wel,sizeof(wel));
							continue ;
						}
					}
				}

				///登录不成功
				sendData(MC_CMD_S2C_GOAWAY,NULL,0);
			} ///客户端退出
			else if(pMsg->cmd == MC_CMD_C2S_LOGOUT) {
				m_pSink->onLogout(pMsg->id);
				///只要收到退出消息，一律回应
				sendData(MC_CMD_S2C_BYE,NULL,0);
				del_Cli(pMsg->id);
			} else {
				tag_Cli cli ;
				/**
				 * 此客户端必须存在， 而且已经登录，而且记录的客户端进程号和发送来的一样，
				 * 否则不接待。。。。 - -！
				 */
				if(get_Cli(pMsg->id,cli)) {
					if(cli.blogon
							/*&& cli.pid == pMsg->pid*/) {
						m_pSink->Sinkmsg_proc(pMsg->cmd,pMsg->data,pMsg->len,pMsg->id);
					} else {
						sendData(MC_CMD_S2C_GOAWAY,NULL,0);
					}
				} else {
					sendData(MC_CMD_S2C_GOAWAY,NULL,0);
				}
			}
		}
		///睡眠5毫秒
		usleep(5000);
	}
}
