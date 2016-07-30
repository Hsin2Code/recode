/*
 * CIMCSrv.h
 *
 *  Created on: 2014-12-2
 *      Author: sharp
 *
 *
 *  module channel srv
 *  进程间通讯服务。
 */

#ifndef CIMCSRV_H_
#define CIMCSRV_H_
#include "../include/MCInterface.h"
#include <pthread.h>
#include <string>
#include <map>

 /// 进程间通讯服务，支持应用程序同多个进程通讯。
class CIMCSrv {
public:
	/**
	 * 客户端数据
	 **/
	struct tag_Cli {
		///由服务器分配的ID
		int     id ;
		///客户端进程ID
		int     pid ;
		///调用线程ID,此线程启动会会被阻塞阻塞住
		pthread_t    trdid ;
		///是否登录
		bool    blogon ;
		///是否托盘
		bool    bTray ;
		///客户端进程密码
		std::string  strpw ;
		///最后一个调用人员自定义的参数, 如果该客户端为托盘的话， 存放登录用户名
		std::string  strparams;
		///启动进程路径
		std::string  path ;
		tag_Cli() {
			id = 0  ;
			pid = 0 ;
			trdid = 0;
			blogon = false ;
			bTray = false ;
		}
	};

public:
	CIMCSrv();
	virtual ~CIMCSrv();
	friend void *  pIMCSrv_worker(void * pSrv)  ;
	friend void *  pIMCSrv_callCli(void * pCall) ;
protected:
	///应答服务器运行
	void			 Running();
	///客户端运行线程
	void             cli_running(int cliid);
public:
	/**
	 *	建立Srv通道
	 *	params : (1) pname 服务器名称， (2) pSink 回调类指针
	 */
	bool    Create(const char * pname,IMCSrvsinkinterface * pSink);
	/**
	 *  发送数据到最近发来消息的客户端通道
	 *  必须在IMCSrvsinkinterface子类的Sinkmsg_proc中调用
	 */
	bool    sendData(unsigned short cmd ,const void * pBuffer , int len);
	/**
	 *  关闭服务通道
	 */
	void    close();
	/**
	 *  获取名称
	 */
	const std::string & get_SrvName() {
		return m_strname ;
	}
	/**
	 *  获取Pub名称
	 */
	const std::string & get_PubSrvName() {
		return m_strPubName ;
	}

	/**
	 * 启动客户端. 当启动进程执行完毕的时候才会返回。
	 * 参数-> (1)  fullPath 可执行文件全路径\n
	 *       (2)  进程的最后一个自定义参数. 将来的客户端进程参数顺序如下
	 *        argv[] = {服务器地址,id,登录密码,pLastArg};
	 * 返回值-> 此次进程执行的唯一ID号 。
	 * 如果时GUI进程的话， 需要每个TTY都启动一个 。
	 * 返回0失败
	 */
	int                    exec_Cli(const char * fullPath,const char * pLastArg);
	/**
	 * 删除一个客户端通道
	 */
	void                   del_Cli(int id);

	///是否登录
	bool                   isLogon(int id);

	///广播消息
	bool                   pub_msg(int id,unsigned short cmd, void * pdata = NULL, int len = 0);

	///向托盘广播
	bool                   pub_msg_4tray(unsigned short cmd, void * pdata = NULL, int len = 0);

	///发送客户端退出消息
	bool                   call_Exit(int id);

	///获取是否托盘
	bool                   isTray(int id);
	///获取客户端信息
	bool                   getCli(int id,tag_Cli & cli) {
		return   get_Cli(id,cli);
	}
	bool                   hasTray();
protected:
	bool                   get_Cli(int id,tag_Cli & cli);
private:
	pthread_t              m_trdid;
	///服务器是否运行
	volatile   bool        m_brunning ;
	///应答服务器
	void   *               m_pSrv ;
	///广播服务器 主要向客户端通知服务器的一些变化情况。
	void   *               m_pPub ;
	///应答服务器名
	std::string            m_strname ;
	///广播服务器名
	std::string            m_strPubName ;
	IMCSrvsinkinterface *  m_pSink      ;
	///客户端数据MAP
	std::map<int,tag_Cli>  m_cliMap   ;
	int                    m_nidIndex ;
	///map锁
	void   *               m_pMaplock ;
};

#endif /* CIMCSRV_H_ */
