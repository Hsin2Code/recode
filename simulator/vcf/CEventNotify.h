/*
 * CEventNotify.h
 *
 *  Created on: 2015-1-4
 *      Author: sharp
 */

#ifndef CEVENTNOTIFY_H_
#define CEVENTNOTIFY_H_
#include <vector>
#include <map>
#include <string>
#include "common/CLocker.h"
#include "VCFCmdDefine.h"

typedef std::vector<pNotify_func>   CNotifyFuncArray ;
typedef std::map<int , CNotifyFuncArray> CNotifyMap ;

namespace YCommonTool {

class CEventNotify {
public:
	CEventNotify();
	virtual ~CEventNotify();
	/**
	 *  注册消息
	 *  @event 事件号
	 *  @func  事件发生的时候执行函数
	 */
	bool    registerEvent(int event,pNotify_func func) ;
	/**
	 *  反注册消息
	 *  @event
	 */
	void    UnregisterEvent(int event,pNotify_func func) ;
	/**
	 *  发送消息
	 */
	void    sendEvent(int event, void * pParam = NULL);
private:
	CNotifyMap   m_map  ;
	CLocker      m_lock ;
};

}

#endif /* CEVENTNOTIFY_H_ */
