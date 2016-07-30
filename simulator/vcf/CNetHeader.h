/*
 * CNetHeader.h
 *
 *  Created on: 2014-12-5
 *      Author: sharp
 *
 *   VCF网络接口定义头文件
 *
 *   属于APP和网络IO方面的接口定义，用来隔离具体的网络协议。
 */

#ifndef CNETHEADER_H_
#define CNETHEADER_H_

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <string>
#include "VCFCmdDefine.h"

extern ILocalogInterface * g_GetlogInterface();

///定义协议类型
#define  VRV_WINSRV_PROTOCOL


#define   SRV_ADDRESS      "svraddress"
#define   SRV_LISTEN_PORT  "srvlistenport"
///定义不同的参数文件
#ifdef   VRV_WINSRV_PROTOCOL
///VRV客户端监听端口
#define   CLI_LISTEN_PORT   "vrv_cli_listen_port"
#endif





class INetEngineinterface ;
class INetEngineSinkinterface ;

#define INVALID_SOCKET   (-1)

#ifndef NULL
#define NULL 0
#endif

#ifndef SOCKET
#define SOCKET  int
#endif

///错误信息KEY
#define   VRVNETPRO_ERROR   "vrvnetprotocol_error"
#define   VRVSERVER_LISTEN_PORT  "vrv_svr_listen_port"

///定义各种网络协议标识号转换。
///以备将来适用不同的网络协议定义
/**
 * 发送消息消息号
 * 定义宏以S_开头
 * 如 S_XXXXXXXXX
 */
enum  enNetSmsg {
	///用户注册消息
	S_CMD_USER_REGISTER,
	///上报日志
	S_CMD_UPLOAD_LOG,
	///获取策略概况
	S_CMD_GET_POLICY_GENERAL,
	///获取策略详情
	S_CMD_GET_POLICY_INFO,
	///发送软件资产
	S_CMD_SOFT_ASSET,
	///即时上报
	S_CMD_UPLOAD_LOG_NOW,
	///发送硬件资产信息
	S_CMD_HARD_ASSET,
	///发送心跳
	S_CMD_HEART_BEAT,
    S_CMD_DETECT_SERVER,
	///发送版本
	S_CMD_CLIENT_UPGRADE,
    S_CMD_GET_SERVER_TIME,
	///上报特殊
	S_CMD_UPLOAD_LOG_NOWEX,
};

///S_CMD_SOFT_ASSET 携带
struct tag_S_Soft_Asset {
	void  *   pAdd ;
	void  *   pDel ;
	void  *   pModify ;
	bool      bFirst ;
	tag_S_Soft_Asset() {
		pAdd = NULL ;
		pDel = NULL ;
		pModify = NULL ;
		bFirst = false;
	}
};

///S_CMD_HARD_ASSET携带
struct tag_S_Hard_Asset {
	void *  pAdd ;
	void *  pDel ;
	void *  pModify ;
	void *  pFrontstr;
	void *  pOld;
	void *  pMap ;
	tag_S_Hard_Asset() {
		pAdd = NULL ;
		pDel = NULL ;
		pModify = NULL ;
	}
};

struct tag_S_UPLOAD_LOGS {
	///上传成功的最大下表
	int  *  curid ;
	void * pArray ;
	tag_S_UPLOAD_LOGS() {
		curid = 0 ;
	}
};

///获取策略概述结构体
struct tag_S_GetPlockyGEN {
	void * pSendStr ;
	void * pGetStr;
	tag_S_GetPlockyGEN() {
		pSendStr = NULL;
		pGetStr = NULL ;
	}
};

/**
 * 接收消息号
 * 定义宏以R_开头
 * 如R_XXXXXXXX
 */
enum  enNetRmsg {
	///策略概况
	R_CMD_DISTRIBUTE_POLICY,
};

///接收消息结构体
struct   tag_NetRmsg {
	///套接字
	SOCKET  skt  ;
	///数据
	void *  pData ;
	///长度
	int     len ;
};



/// 网络模块接口，充当协议和APP之间的桥梁。
class   INetEngineinterface  {
public:
	/**
	 * 创建ENGINE 并进行连接
	 */
	virtual    bool             create_Engine(INetEngineSinkinterface * pSink) = 0;
	/**
	* 获取参数
	* 通过参数名称获取参数
	*/
	virtual  std::string        get_Param(std::string & key) = 0;
	/**
	 *  网络数据
	 */
	virtual   bool              sendnetmsg(enNetSmsg msg , void * pData , int len) = 0 ;

	/// 关闭网络
	virtual   void              close() = 0;
	///
    virtual	 INetEngineSinkinterface *   get_Sink() = 0 ;
};


///网络模块回调接口
class   INetEngineSinkinterface  {
public:
	 /**
	 *  获取配置参数
	 *  通过参数名称获取参数
	 */
	 virtual std::string  get_Param(std::string & key)  = 0;

	 /**
	  *  网络数据
	  */
     virtual bool         recvnetmsg(enNetRmsg msg , void * pData , int len) = 0 ;

     ///本地向外链接成功事件,error = 0 链接成功
     virtual bool         onConnect(int error)  = 0;

     ///关闭事件 close_by_remote 表示是否远端先关闭
     virtual bool         onClose(SOCKET skt, bool close_by_remote) = 0;

     ///接收事件
     ///返回值为false关闭远程链接
     virtual bool         onAccept(SOCKET skt,struct sockaddr_in * pAddr)  = 0;

};


/**
 *  网络协议接口，  用来规范所有的协议及通讯场景
 *  具体的实现各个协议可以不同
 */
class  INetProtocolInterface {
public :
	 ///协议初始化
	 virtual   bool		 create(INetEngineinterface * pEngine) = 0;
	 ///发送数据
	 virtual   bool      sendData(enNetSmsg msg , void * pData , int len) = 0;
	 ///关闭
	 virtual   void      close() = 0 ;
     ///fix UB for sub class
     virtual ~INetProtocolInterface() {}
};


#endif /* CNETHEADER_H_ */
