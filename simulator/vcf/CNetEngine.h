/**
 * CNetEngine.h
 *
 *  Created on: 2014-12-5
 *      Author: sharp
 *
 *  消息通讯模块
 */

#ifndef CNETENGINE_H_
#define CNETENGINE_H_
#include "CNetHeader.h"

namespace YCommonTool {
  class CLocker ;
}



///  APP与网络协议之间的中间类，减少两边模块的耦合。
class CNetEngine  : public INetEngineinterface {
public:
	CNetEngine();
	virtual ~CNetEngine();

	///virtual
public:
	/**
	 * 创建ENGINE 并进行连接
	 */
	virtual   bool              create_Engine(INetEngineSinkinterface * pSink) ;
	/**
	* 获取参数
	* 通过参数名称获取参数
	*/
	virtual  std::string        get_Param(std::string & key) ;
	/**
	 *  网络数据
	 */
	virtual   bool              sendnetmsg(enNetSmsg msg , void * pData , int len);

	/// 关闭网络
	virtual   void              close();

	///
	virtual	 INetEngineSinkinterface   *   get_Sink()  {
		return m_pNetSink ;
	}
public:

public:

	INetEngineSinkinterface *  m_pNetSink ;
	INetProtocolInterface  *   m_pProtocol ;
	YCommonTool::CLocker  *    m_pLocker;
};

#endif /* CNETENGINE_H_ */
