/*
 * CIMCClient.cpp
 *
 *  Created on: 2014-12-4
 *      Author: sharp
 */

#include "CIMCClient.h"
#include "include/zmq/zmq.h"
#include "string.h"
#include <unistd.h>

CIMCClient   *   CIMCClient::m_pIMCCli = NULL ;

void *  pSub_worker(void * pCli) {
	CIMCClient * _pCli = (CIMCClient *)pCli ;
	_pCli->submsg_worker();
	return 0 ;
}

CIMCClient   *   CIMCClient::create_MCCli() {
	if(m_pIMCCli==NULL) {
		m_pIMCCli = new CIMCClient();
	}
	return m_pIMCCli ;
}

void             CIMCClient::destory_MCCli() {
	if(m_pIMCCli) {
		delete  m_pIMCCli ;
	}
}
///获取服务器地址
bool   get_EdpSAddr(char * pAddr) {
	FILE * fp = fopen(TRAY_ADDR,"r");
	if(fp == NULL) {
		return false ;
	}
	fgets(pAddr,128,fp);
	fclose(fp);
	return true ;
}

CIMCClient::CIMCClient() {
	m_pzmqCtx = NULL ;
	m_preqSkt = NULL ;
	m_psubSkt = NULL ;
	m_trdid = 0 ;
	m_pzmqCtx =	zmq_init(1);
	m_bsubrunning = false ;
	m_pSink = NULL ;
	m_bClosefromSrv = false ;
	m_bisTray = false ;
}

CIMCClient::~CIMCClient() {
	Close();
}

bool  CIMCClient::Create(const char * pDeskUser,IMCCliSinkinterface * pSink) {
	m_bisTray = true ;
	m_strSysUser = pDeskUser ;
	/**
	 * 获取地址
	 */
	char  szAddr[128] = "";
	if(!get_EdpSAddr(szAddr)) {
		return false ;
	}

	return Create(0,szAddr,TRAY_PW,pSink);
}

bool  CIMCClient::Create(int cid,const char * pAddr,const char * pw,IMCCliSinkinterface * pSink) {
	if(m_pzmqCtx == NULL) m_pzmqCtx =	zmq_init(1);
	if(m_preqSkt) {
		return true ;
	}
	m_bClosefromSrv = false ;
	m_cid = cid ;
	m_strAddr = pAddr ;
	m_strpw = pw ;
	m_preqSkt = zmq_socket(m_pzmqCtx,ZMQ_REQ);
	if(m_preqSkt == NULL) {
		return false ;
	}

	int  linger = 100 ;
	zmq_setsockopt(m_preqSkt, ZMQ_LINGER, &linger, sizeof(linger));
	m_pSink = pSink ;
	zmq_connect(m_preqSkt,pAddr);

	///发送登录消息
	tag_C2S_MClogon logon ;
	strcpy(logon.pw,pw);
	if(m_bisTray) {
		logon.cbTray = 0xff ;
		strcpy(logon.user,m_strSysUser.c_str());
	}
	if(!sendData(MC_CMD_C2S_LOGIN,&logon,sizeof(logon))) {
		return false ;
	}
	return true;
}

bool  CIMCClient::sendData(unsigned short cmd , void * pbuffer , int len)
{
	if(m_preqSkt == NULL) return false ;
	zmq_msg_t msg_t ;
	int msglen = sizeof(tag_MCMsg) + len ;
	zmq_msg_init_size(&msg_t,sizeof(tag_MCMsg) + len);
	tag_MCMsg * pmsg = (tag_MCMsg *)zmq_msg_data(&msg_t);
	memset(pmsg,0,msglen);
	pmsg->cmd = cmd ;
	pmsg->id =  m_cid;
	pmsg->len = len ;
	pmsg->pid =	getpid();
	if(pbuffer) {
		memcpy(pmsg->data,pbuffer,len);
	}

	int rc = zmq_msg_send(&msg_t,m_preqSkt, 0);
	if(rc < 0)  {
		zmq_msg_close(&msg_t);
		return false ;
	}

	zmq_msg_close(&msg_t);
	return recvMsg() ;
}

void  CIMCClient::Close() {
	if(m_preqSkt) {
		/// 如果不是服务器主动退出
		//  通知服务器退出
		if(!m_bClosefromSrv) {
			sendData(MC_CMD_C2S_LOGOUT,NULL,0);
		}
		zmq_close(m_preqSkt);
		m_preqSkt = NULL;
	}
	//不是服务器主动退出
	if(!m_bClosefromSrv && m_trdid) {
		m_bsubrunning = false ;
		void * status = 0 ;
		pthread_join(m_trdid,&status);
		m_trdid = 0 ;
	}

	if(m_psubSkt) {
		zmq_close(m_psubSkt);
		m_psubSkt = NULL ;
	}

	if(m_pzmqCtx) {
		zmq_term(m_pzmqCtx);
		m_pzmqCtx = NULL ;
	}
	m_bClosefromSrv = false ;
}

void  CIMCClient::submsg_worker() {
#define ZMQ_POLL_MSEC 1000
	///10 毫秒
	int timeout = 10 * ZMQ_POLL_MSEC ;
	///先建立连接
	while(m_bsubrunning) {
		zmq_pollitem_t items [] = { { m_psubSkt, 0, ZMQ_POLLIN, 0 } };
		int rc = zmq_poll (items, 1, timeout);
		if (rc == -1)
			break;

		///有消息到来
		if (items [0].revents & ZMQ_POLLIN) {
			zmq_msg_t msg_t ;
			zmq_msg_init(&msg_t);
			int rc = zmq_msg_recv(&msg_t,m_psubSkt,0);
			if(rc < 0) break ;
			tag_MCMsg * pmsg = (tag_MCMsg *)zmq_msg_data(&msg_t);
			if(pmsg->cmd == MC_CMD_S2C_QUIT) {
				m_bClosefromSrv = true ;
				zmq_msg_close(&msg_t);
				break;
			}
			if(pmsg->id == 0
					|| pmsg->id == m_cid){
				m_pSink->pub_proc(pmsg->cmd,pmsg->data,pmsg->len);
			}
			zmq_msg_close(&msg_t);
		}
	}
	m_bsubrunning = false ;
	m_pSink->call_exit();
}

bool CIMCClient::recvMsg() {
	if(m_preqSkt == NULL) return false ;
	zmq_msg_t msg_t ;
	///接受回应
	zmq_msg_init(&msg_t);

	int rc = zmq_msg_recv(&msg_t,m_preqSkt,0);
	if(rc < 0) {
		zmq_msg_close(&msg_t);
		return false ;
	}

	tag_MCMsg * pmsg = (tag_MCMsg *)zmq_msg_data(&msg_t);
	///登录成功
	if(pmsg->cmd == MC_CMD_S2C_WELCOME) {
		///启动PUB
		tag_S2CWelcome * pwel = (tag_S2CWelcome *)pmsg->data;
		m_strPubAddr = pwel->szPubAddr ;
		///托盘进程，在这里给ID赋值
		if(m_bisTray) {
			m_cid = pwel->idforTray;
		}

		if(m_psubSkt==NULL) { ///
			m_psubSkt = zmq_socket(m_pzmqCtx,ZMQ_SUB);
			if(m_psubSkt == NULL) return false ;
			int  linger = 100 ;
			zmq_setsockopt(m_psubSkt, ZMQ_LINGER, &linger, sizeof(linger));
			int rc = zmq_connect(m_psubSkt,pwel->szPubAddr);
			if(rc != 0){   zmq_msg_close(&msg_t);
				return false ;
			}
			zmq_setsockopt(m_psubSkt,ZMQ_SUBSCRIBE,"",0);
		}

		if(m_trdid == 0) { //启动线程
			m_bsubrunning = true ;
			m_bClosefromSrv = false ;
			int rc = pthread_create(&m_trdid,NULL,pSub_worker,this);
			if(rc != 0){   zmq_msg_close(&msg_t);
				return false ;
			}
		}
	}
	m_pSink->reponse_proc(pmsg->cmd,pmsg->data,pmsg->len);
	zmq_msg_close(&msg_t);
    return true ;
}
