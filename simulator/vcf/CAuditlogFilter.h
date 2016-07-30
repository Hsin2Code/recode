/*
 * CAuditlogFilter.h
 *
 *  Created on: 2015-1-8
 *      Author: sharp
 *
 *
 *      审计日志过滤类
 */

#ifndef CAUDITLOGFILTER_H_
#define CAUDITLOGFILTER_H_
#include <string>
#include <map>
#include <vector>

class CAuditlogFilter {
	struct  tag_logFilter {
		int  what ;
		int  time ;
		 std::string log;
	};
	typedef std::vector<tag_logFilter> Clogvt ;
	typedef std::map<int , Clogvt> ClogMap ;

public:
	CAuditlogFilter();
	virtual ~CAuditlogFilter();

public:
	bool    filter_log(int type, int what , int time,const char * plog);

private:
	ClogMap      m_map ;
};

#endif /* CAUDITLOGFILTER_H_ */
