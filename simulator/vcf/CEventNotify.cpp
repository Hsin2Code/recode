/*
 * CEventNotify.cpp
 *
 *  Created on: 2015-1-4
 *      Author: sharp
 */

#include "CEventNotify.h"

namespace YCommonTool {

CEventNotify::CEventNotify() {
	// TODO Auto-generated constructor stub

}

CEventNotify::~CEventNotify() {
	// TODO Auto-generated destructor stub
}

bool   CEventNotify::registerEvent(int event,pNotify_func func) {
	if(func == NULL) {
		return false;
	}
	CLockHelper  helper(&m_lock);
	CNotifyMap::iterator iter = m_map.find(event);
	if(iter != m_map.end()) {
		CNotifyFuncArray & arr = iter->second;
		CNotifyFuncArray::iterator iter1 = arr.begin();
		while(iter1 != arr.end()) {
			if(*iter1 == func) {
				return false ;
			}
			iter1++ ;
		}
		arr.push_back(func);
	} else {
		CNotifyFuncArray arr ;
		arr.push_back(func);
		m_map[event] = arr ;
	}
	return true ;
}

void  CEventNotify::UnregisterEvent(int event,pNotify_func func) {
	CLockHelper  helper(&m_lock);
	CNotifyMap::iterator iter = m_map.find(event);
	if(iter != m_map.end()) {
		CNotifyFuncArray & arr = iter->second;
		CNotifyFuncArray::iterator iter1 = arr.begin();
		while(iter1 != arr.end()) {
			if(*iter1 == func) {
				iter1 = arr.erase(iter1);
			} else
				iter1++ ;
		}
	}
}

void  CEventNotify::sendEvent(int event, void * pParam) {
	CLockHelper  helper(&m_lock);
	CNotifyMap::iterator iter = m_map.find(event);
	if(iter != m_map.end()) {
		CNotifyFuncArray & arr = iter->second;
		CNotifyFuncArray::iterator iter1 = arr.begin();
		while(iter1 != arr.end()) {
			pNotify_func pfunc = *iter1 ;
			(*pfunc)(pParam);
			iter1++ ;
		}
	}
}
}
