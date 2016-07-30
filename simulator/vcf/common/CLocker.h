/*
 * CLocker.h
 *
 *  Created on: 2014-11-17
 *      Author: sharp
 */

#ifndef CLOCKER_H_
#define CLOCKER_H_

#include <pthread.h>

namespace YCommonTool  /// 一般通用工具
{

/**
 * gcc 4.1.2后支持
 */
inline  void  lock_inc(volatile  int * val) {
	__sync_fetch_and_add(val,1);
	return ;
}

inline void  lock_dec(volatile   int * val) {
	__sync_fetch_and_sub(val,1);
	return ;
}

/**
 * 锁包装类
 */

class CLocker {
public:
	inline  CLocker() {
        pthread_mutex_init(&m_mutex, NULL);
	}
	virtual inline ~CLocker() {
		pthread_mutex_destroy(&m_mutex);
	}
public:
    virtual inline void lock() {
    	pthread_mutex_lock(&m_mutex);
    }
    virtual inline void unlock() {
    	pthread_mutex_unlock(&m_mutex);
    }
private :
	mutable pthread_mutex_t m_mutex;
};

/**
 * 锁帮助类，借助变量的生命周期自动开闭锁
 */
class CLockHelper {
	volatile int    m_nlockCount ;
	CLocker *       m_pLocker ;
public:
	CLockHelper(CLocker * pLocker , bool bAutoLock = true) {
		m_nlockCount = 0 ;
		m_pLocker = pLocker ;
		if(bAutoLock) {
			lock();
		}
	}
	~CLockHelper() {
		while(m_nlockCount > 0) { unlock();}
	}

public:
	void  lock() {
		lock_inc(&m_nlockCount);
		m_pLocker->lock();
		return ;
	}
	void  unlock() {
		lock_dec(&m_nlockCount);
		m_pLocker->unlock();
		return ;
	}
	unsigned int  inline  getLockcount() {
		return m_nlockCount ;
	}
};

}

#endif /* CLOCKER_H_ */
