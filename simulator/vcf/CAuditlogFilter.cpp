/*
 * CAuditlogFilter.cpp
 *
 *  Created on: 2015-1-8
 *      Author: sharp
 */

#include "CAuditlogFilter.h"
#include <string.h>

CAuditlogFilter::CAuditlogFilter() {
	// TODO Auto-generated constructor stub

}

CAuditlogFilter::~CAuditlogFilter() {
	// TODO Auto-generated destructor stub
}

bool  CAuditlogFilter::filter_log(int type, int what , int time,const char * plog) {
	ClogMap::iterator  iter  =  m_map.find(type);
	if(iter == m_map.end()) {
		tag_logFilter filter ;
		filter.time = time ;
		filter.what = what ;
		filter.log =  plog ;
		Clogvt vt ;
		vt.push_back(filter);
		m_map[type] = vt ;
		return true ;
	}

	Clogvt  &  _vt = iter->second ;
	Clogvt::iterator  _iter = _vt.begin();
	const char * pNew = NULL ;
	while(_iter != _vt.end()) {
		tag_logFilter & filter = *_iter;
		pNew = filter.log.c_str() + 32 ; ///把事件的那块跳过
		if(strcmp(pNew,plog + 32) == 0) {
			///一份钟内， 策略不会变
			if(time - filter.time <= 60) {
				return false ;
			}
			filter.time = time ;
			return true ;
		}
		_iter++ ;
	}

	if(_vt.size() < 10 ) {
		tag_logFilter filter ;
		filter.time = time ;
		filter.what = what ;
		filter.log  = plog ;
		_vt.push_back(filter);
	} else {
		_vt.erase(_vt.begin());
		tag_logFilter filter ;
		filter.time = time ;
		filter.what = what ;
		filter.log  = plog ;
		_vt.push_back(filter);
	}
	return true ;
}
