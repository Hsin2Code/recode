/**
 * CYlog.h
 *
 *  Created on: 2014-11-26
 *      Author: sharp
 *      本地日志类， 以后可以根据需要进行更新。
 */

#ifndef CYLOG_H_
#define CYLOG_H_

#include <iostream>
#include <map>


const   int   const_log_buffer_size  = 4096 ;

namespace YCommonTool {
	class CLocker ;
}

namespace YCommonTool
{
	/**
	 *  日志级别，以后待用
	 */
	enum enlogType {
		enlog_debug ,
		enlog_trace,
		enlog_notice,
		enlog_warn,
		enlog_err,
		enlog_count,
	};

	const  std::string logTypeName[enlog_count] = {
		"DEBUG","TRACE","NOTICE","WARN","ERROR"
	};

class CYlog {
public:
	CYlog();
	virtual ~CYlog();

	/**
	 * params : (1) 日志级别, (2) 日志名称 (3) 日志目录
	 */
	bool   init(enlogType type,
			 const char * logName ,
			 const char * logdir,bool bappend = true ,bool  bissync = true );

	void   log_close();

	/**
	 * 记录日志，如果有文件句柄的话， 写日志到文件， 如果没有话的，输出到stderr
	  */
	bool   log_log(const char* logformat,...);
protected:
	int    set_logMask(char * pBuffer);
	bool   log_write(char * pBuffer , int len);
private :
	enlogType  m_logLvl ;
	bool       m_bAppend;
	bool       m_bSync  ;
	FILE   *   m_fplog ;
	char       m_logBuffer[const_log_buffer_size];
	char       m_location[260];
	CLocker  *  m_plocker;
};

}

#endif /* CYLOG_H_ */
