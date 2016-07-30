/*
 * CVRVNetProtocol.h
 *
 *  Created on: 2014-12-8
 *      Author: sharp
 *
 *  faint faint faint .
 */

#ifndef CVRVNETPROTOCOL_H_
#define CVRVNETPROTOCOL_H_

#include "CNetHeader.h"
#include <pthread.h>
#include <list>
#include <map>
#include <vector>

#include  "vrvprotocol/VrvProtocol.h"
#include  "vrvprotocol/VRVProtocol.hxx"
#include  "vrvprotocol/VRVProtocolEx.hxx"
#include "CSoftInstallHelper.h"
//256KB
#define  SEND_LOG_BUF_LEN     (1024*256)


class CVRVNetProtocol: public INetProtocolInterface {
public:
	CVRVNetProtocol();
	virtual ~CVRVNetProtocol();
	friend  void   *   plisten_worker(void * pdata) ;
public:
	///virtual
	///协议初始化
	virtual   bool		 create(INetEngineinterface * pEngine);
	///发送数据
	virtual   bool       sendData(enNetSmsg msg , void * pData , int len);
	///关闭
	virtual   void       close();

public:
	///获取远程链接处理线程数
	int                  getRworkercount() ;
	///关闭远程连接
    /*for debug*/
    void                 close_socket(SOCKET skt, int line = -1);
    int                  getSO_ERROR(int fd);
    void                 closeSocket(int fd);

	int                  get_listenPort() {
		return m_nlistPort ;
	}
public:
	void   *             listen_worker();
	bool                 msg_worker(int skt,DWORD flag,WORD type ,WORD what ,DWORD & pw , char * pData,int len);

	std::string   &      get_Error() {
		return m_strError ;
	}
protected:
	///链接服务器
	bool                 conn_serv(SOCKET skt, const std::string &server_ip = "");
	///上报日志
	bool                 update_log(SOCKET skt,void * pData, int pwd);
	///上报软件日志
	bool                 report_soft_asset(SOCKET skt,unsigned int pwd ,
			std::vector<tag_SoftInstallEx> & _vt,
			unsigned short what ,
			const char * pFront);
	///上报硬件日志
	bool                 report_hard_asset(SOCKET skt ,unsigned int pwd ,
			tag_S_Hard_Asset * pAsset);
private:
	INetEngineinterface *   m_pEngine ;
	/// 启动监听的线程
	pthread_t               m_lstenTrdid ;
	/// 监听SOCKET
	int                     m_listSkt;
	/// 线程ID锁
	void    *               m_plocker ;
	/// 远程连接上来的数
	std::map<int,pthread_t>       m_workeridArray;
	/// 错误
	std::string             m_strError ;
	///发送日志BUFFER，一次可以发送10条日志，每条日志长度定为4K
	char                    m_plogBuffer[SEND_LOG_BUF_LEN];
	///发送日志BUFFER
	char                    m_plogBufferDest[SEND_LOG_BUF_LEN*2+1];
	int                     m_nlistPort ;
};

#endif /* CVRVNETPROTOCOL_H_ */
