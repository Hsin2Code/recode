/**
 * CIMCClient.h
 *
 *  Created on: 2014-12-4
 *      Author: sharp
 *  修改请通知作者本人。
 *  module channle client
 *  限制一个客户端只能起一个实例
 */

#ifndef CIMCCLIENT_H_
#define CIMCCLIENT_H_

#include "../include/MCInterface.h"
#include <pthread.h>
#include <string>

/// 客户进程中使用使用该类。
class CIMCClient {
public :
	///创建或者获取单例指针
	static CIMCClient *  create_MCCli();
	///销毁单例指针
	static void          destory_MCCli();
protected :
	CIMCClient();
	virtual ~CIMCClient();
	static CIMCClient *  m_pIMCCli ;
	bool     recvMsg();
	void     submsg_worker();
	friend   void *  pSub_worker(void * pCli);
public:
	/**
	 *  建立与服务器的通道
	 *  (1)cid   为客户端启动的时候发来的标识ID
	 * （2）pAddr 为服务器连接地址
	 * （3）pw    为登录密码
	 *
	 */
	bool   Create(int cid,const char * pAddr,const char * pw,IMCCliSinkinterface * pSink);
	/**
	 *  托盘建立与服务器的通道
	 */
	bool   Create(const char * pDeskUser,IMCCliSinkinterface * pSink);
	/**
	 *  发送消息
	 */
	bool   sendData(unsigned short cmd , void * pbuffer , int len);
	///清理资源
	///bsrv标识是不是服务器发起的退出
	void   Close();
private:
	///ZMQ实例指针
	void     *    m_pzmqCtx ;
	///请求SOCKET指针
	void     *    m_preqSkt ;
	///SUBSOKCET指针
	void     *    m_psubSkt ;
	///接受广播消息线程
	pthread_t     m_trdid ;
	volatile   bool        m_bsubrunning ;
	///关闭是否来在服务器
	volatile   bool        m_bClosefromSrv ;
	int           m_cid ;
	std::string   m_strAddr ;
	std::string   m_strpw ;
	std::string   m_strPubAddr;
	///
	IMCCliSinkinterface * m_pSink;
	bool          m_bisTray;
	std::string   m_strSysUser ;
};

#endif /* CIMCCLIENT_H_ */
