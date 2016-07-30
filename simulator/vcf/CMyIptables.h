/*
 * CMyIptables.h
 *
 *  Created on: 2015-4-3
 *      Author: sharp
 */

#ifndef CMYIPTABLES_H_
#define CMYIPTABLES_H_
#include <string>
/**
 * 自定义IPT规则链
 */



class CMyIptables {
public:
	CMyIptables();
	virtual ~CMyIptables();
	void  SetSrvIP(std::string  & str) {
		m_strSrvIp = str ;
	}
public:
	///IPT检测
	void    check();
    void    clearAll();
	///断网,开网
	void    closeNet();
	void    openNet();
protected:
	std::string  m_strSrvIp ;
};

extern char * MY_IPT_CHAIN_NAME ;
extern char * MY_IPT_CHAIN_NAME4httpctrl  ;

#endif /* CMYIPTABLES_H_ */
