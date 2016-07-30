/**
 * CYlog.cpp
 *
 *  Created on: 2014-11-26
 *      Author: sharp
 */

#include "CYlog.h"
#include "memory.h"
#include <stdio.h>
#include <pthread.h>
#include <stdarg.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include "CLocker.h"
#include "Commonfunc.h"
#include <sys/time.h>
#include <unistd.h>

#define  split_string  "#!------------------------------------init------------------------------------!#\n"

using namespace YCommonTool ;

#ifndef NULL
	#define NULL 0
#endif

CYlog::CYlog() {
	m_fplog = NULL ;
	m_logLvl = enlog_debug ;
	memset(m_location,0,sizeof(m_location));
	m_plocker = new CLocker ;
}

CYlog::~CYlog() {
	log_close();
}

void  CYlog::log_close() {
	if(m_fplog) {
		fflush(m_fplog);
		fclose(m_fplog);
		m_fplog = NULL ;
	}
	if(m_plocker) {
		delete m_plocker ;
		m_plocker = NULL ;
	}
}

bool CYlog::init(YCommonTool::enlogType type , const char * logName , const char * logdir , bool bappend , bool bsync) {
	/**
	 * 如果路径存在文件夹，则判断是否存在
	 */
	if (access (logdir, 0) == -1) {
		if (mkdir (logdir, S_IREAD | S_IWRITE ) < 0) {
			printf("CYlog::init create dir failed");
			return false ;
		}
	}
	m_logLvl =  type ;
	m_bAppend = bappend ;
	m_bSync =   bsync ;
	char _location_str[256] = "";
	snprintf(_location_str, 256, "%s%s", logdir, logName);
	strcpy(m_location,_location_str);

	if(m_fplog == NULL) {
		m_fplog = fopen(_location_str, bappend ? "a":"w");
		if(m_fplog==NULL) {
			printf(" %s loglog fopen failed\n",_location_str);
			return false ;
		}
	}

	if(bappend) {
		fwrite(split_string, strlen(split_string), 1, m_fplog);
		if(bsync) {
			fflush(m_fplog);
		}
	}

	return true;
}

int   CYlog::set_logMask(char * pBuffer) {
	time_t now;
	now = time(&now);;
	struct tm vtm;
	localtime_r(&now, &vtm);
	struct timeval  tv;
	gettimeofday(&tv, 0);
	return snprintf(pBuffer, const_log_buffer_size, "%s#[%04d-%02d-%02d %02d:%02d:%02d:%03d] >> ", logTypeName[m_logLvl].c_str(),
	            vtm.tm_year+1900,vtm.tm_mon + 1, vtm.tm_mday, vtm.tm_hour, vtm.tm_min, vtm.tm_sec,tv.tv_usec/1000);
}


bool  CYlog::log_log(const char* logformat,...) {
	int len;
	int masklen = 0;

	char * start = m_logBuffer;
	masklen = set_logMask(start);
	start += masklen;

	va_list args;
	va_start(args, logformat);
	len = vsnprintf(start, const_log_buffer_size - masklen, logformat, args);
	va_end(args);

	if(NULL == m_fplog) {
		fprintf(stderr, "Ylog << %s", m_logBuffer);
		return true;
	}

	return log_write(m_logBuffer, masklen + len);
}

bool CYlog::log_write(char * pBuffer , int len) {
	m_plocker->lock();
	if(0 != access(m_location, W_OK)) {
		log_close();
		if(m_fplog == NULL) {
			m_fplog = fopen(m_location, m_bAppend ? "a":"w");
			if(m_fplog==NULL) {
				m_plocker->unlock();
				return false ;
			}
		}
	}

	if(*(pBuffer+len-1) != '\n') {
		*(pBuffer+len++) = '\n';
		*(pBuffer+len) = '\0';
	}

	if(1 == fwrite(pBuffer, len, 1, m_fplog))  {
		if(m_bSync)
          	fflush(m_fplog);
		*pBuffer='\0';
    } else {
        int x = errno;
	    fprintf(stderr, "Failed write logfile. errno:%s    message:%s", strerror(x), pBuffer);
	    m_plocker->unlock();
	    return false;
	}

	m_plocker->unlock();
	return true;
}
