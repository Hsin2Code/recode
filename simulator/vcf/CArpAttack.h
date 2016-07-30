/*
 * CArpAttack.h
 *
 *  Created on: 2015-3-12
 *      Author: sharp
 */

#ifndef CARPATTACK_H_
#define CARPATTACK_H_
#include <vector>
#include <string>
#include <map>
#include "common/CLocker.h"

void   *  ArpAttack_work(void * parg);
class CArpAttack {
public:
	CArpAttack();
	virtual ~CArpAttack();
	friend void   *  ArpAttack_work(void * parg);
protected:

public:
	bool   init();
	int    attack_unreg_dev(const char * pIPs);
	void   stop();
protected:
	void   cancle_Attack(std::vector<std::string> & ipvt);
	void   update(std::map<std::string,std::string> & map);
	void   attack(std::map<std::string,std::string> & _map);
	void   getUpdateInfo(std::vector<std::string> & addd ,
			std::vector<std::string> & del);
protected:
	/// ip , mac
	std::vector<std::string> m_ipvt ;
	std::vector<std::string> m_ipadd ;
	std::vector<std::string> m_ipdel ;

	YCommonTool::CLocker     m_locker;
	void         *           m_fp;
	pthread_t                m_trd ;
	volatile     bool        m_brunning ;
	volatile     bool        m_bUpdate;
};

#endif /* CARPATTACK_H_ */
