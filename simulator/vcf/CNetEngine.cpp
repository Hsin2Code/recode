/*
 * CNetEngine.cpp
 *
 *  Created on: 2014-12-5
 *      Author: sharp
 */

#include "CNetEngine.h"
#include "CVRVNetProtocol.h"
#include "common/CLocker.h"
#include "stdio.h"

CNetEngine::CNetEngine() {
	m_pNetSink = NULL ;
	m_pProtocol = new CVRVNetProtocol ;
	m_pLocker = new  YCommonTool::CLocker();
}

CNetEngine::~CNetEngine() {
	close() ;
}

bool   CNetEngine::create_Engine(INetEngineSinkinterface * pSink) {

	m_pNetSink = pSink ;
	if(m_pProtocol == NULL) {
		g_GetlogInterface()->loglog("0000000\n");
		return false ;
	}

	return  m_pProtocol->create(this);
}

std::string  CNetEngine::get_Param(std::string & key) {
	if(m_pNetSink==NULL) return "" ;
	if(key == VRVNETPRO_ERROR) {
		return (static_cast<CVRVNetProtocol *>(m_pProtocol))->get_Error();
	} else if(VRVSERVER_LISTEN_PORT == key) {
		char szport[16] = "";
		sprintf(szport,"%d",(static_cast<CVRVNetProtocol *>(m_pProtocol))->get_listenPort());
		return szport ;
	}
	return m_pNetSink->get_Param(key);
}

bool   CNetEngine::sendnetmsg(enNetSmsg msg , void * pData , int len) {
	if(m_pProtocol == NULL) return false ;
	using namespace YCommonTool ;
	CLockHelper  helper(m_pLocker);
	return m_pProtocol->sendData(msg,pData,len) ;
}

void   CNetEngine::close() {

	if(m_pProtocol) {
		m_pProtocol->close();
		delete m_pProtocol ;
		m_pProtocol = NULL ;
	}
	if(m_pLocker) {
		delete m_pLocker ;
		m_pLocker = NULL ;
	}
}
