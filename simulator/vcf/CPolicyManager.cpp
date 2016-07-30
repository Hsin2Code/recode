/*
 * CPolicyManager.cpp
 *
 *  Created on: 2014-12-12
 *      Author: sharp
 */

#include "CPolicyManager.h"
#include "stdio.h"
#include <iostream>

CPolicyManager::CPolicyManager() {
   	m_bUpdateing = false ;
	int i = 0 ;
	for(i = 0 ;i < en_policytype_count ; i++) {
		m_bRefrush[i] = true ;
	}
	for(i = 0 ;i < en_policytype_count ; i++) {
		m_pexecPolicyArray[i] = NULL ;
	}
	for(i = 0 ; i < en_policytype_count ; i++) {
		m_pooicyStat[i] = pstat_noexsit ;
	}
#if 0
    for(i = 0; i < en_policytype_count; i++) {
        m_policy_dismiss_cnt[i] = 0;
    }
#endif
}

void  CPolicyManager::clean_Map() {
	{
		CLockHelper  helper(&m_pMaplocker);
		std::map<enPolicytype ,CPolicyArray>::iterator iter = m_policyMap.begin();
		while(iter != m_policyMap.end()) {
			CPolicyArray & _arr = iter->second ;
			CPolicyArray::iterator  iterP = _arr.begin();
			while(iterP != _arr.end()) {
				free_policy(*iterP);
				iterP++ ;
			}
			_arr.clear();
			iter++ ;
		}
		m_policyMap.clear();
	}
}

CPolicyManager::~CPolicyManager() {
	clean_Map();
	int i =  0 ;
	for(i = 0 ;i < en_policytype_count;i++) {
		if(m_pexecPolicyArray[i]) {
			free_policy(m_pexecPolicyArray[i]);
			m_pexecPolicyArray[i] = NULL ;
		}
	}
}

void   CPolicyManager::update_policyStat(enPolicytype type , en_policy_stat stat) {
	CLockHelper  helper(&m_pstatLocker);

	m_pooicyStat[type]  = stat;
}

en_policy_stat  CPolicyManager::get_policyStat(enPolicytype type) {
	CLockHelper  helper(&m_pstatLocker);
	if(type >= en_policytype_count) {
		return pstat_noexsit ;
	}
	return  m_pooicyStat[type] ;
}

CPolicy  *  CPolicyManager::importFromXml(int id,int type,unsigned int crc,const char * pXml) {
	CPolicy * pPolicy = get_Policy((enPolicytype)type,id);
	if(pPolicy == NULL) {
		pPolicy = create_policy((enPolicytype)type);
	}
	if(pPolicy) {
		if(crc == pPolicy->get_crc()) {
			return pPolicy ;
		}
		if(!pPolicy->import_xml(pXml)) {
			free_policy(pPolicy) ;
			return NULL    ;
		} else { ///更新状态
			CLockHelper  helper(&m_pMaplocker);
			std::map<enPolicytype ,CPolicyArray>::iterator iter = m_policyMap.find((enPolicytype)type);
			if(iter != m_policyMap.end()) {
				bool bexsit = false ;
				CPolicyArray & _array = iter->second ;
				CPolicyArray::iterator  iterTmp = _array.begin();
				while(iterTmp != _array.end()) {
					if(*iterTmp == pPolicy) {
						bexsit = true ;
						break ;
					}
					iterTmp++ ;
				}
				if(!bexsit)
					_array.push_back(pPolicy);
			} else {
				CPolicyArray _array ;
				_array.push_back(pPolicy);
				m_policyMap[(enPolicytype)type] = _array ;
			}
			m_bRefrush[(enPolicytype)type] = true ;
			en_policy_stat stat =  get_policyStat((enPolicytype)type);
			if(stat < pstat_rdy) {
				update_policyStat((enPolicytype)type,pstat_rdy);
			}
		}
	}
	return pPolicy ;
}

enPolicytype    CPolicyManager::typefromTartget(std::string & type) {
	for(int i = SOFT_INSTALL_CTRL ; i < en_policytype_count ; i++) {
		if(type == policy_target[i]) {
			return (enPolicytype)i ;
		}
	}
	return en_policytype_count ;
}

CPolicy  *  CPolicyManager::get_Policy(enPolicytype pType , int  id) {
	CLockHelper  helper(&m_pMaplocker);
	if(pType >= en_policytype_count) {
        return NULL  ;
	}

	std::map<enPolicytype ,CPolicyArray>::iterator iter = m_policyMap.find(pType);
	if(iter == m_policyMap.end()) {
		return NULL ;
	}
	CPolicyArray & _arr = iter->second ;
	CPolicyArray::iterator iterPolicy = _arr.begin() ;
	while(iterPolicy != _arr.end()) {
		CPolicy * pPolicy = (CPolicy *)*iterPolicy;
		if(pPolicy->get_id() == id) {
			return pPolicy ;
		}
		iterPolicy++ ;
	}
	return NULL ;
}

CPolicy  *  CPolicyManager::get_PolicyFromCrc(unsigned int crc) {
	CLockHelper  helper(&m_pMaplocker);
	std::map<enPolicytype ,CPolicyArray>::iterator iter = m_policyMap.begin();
	while(iter != m_policyMap.end()) {
		CPolicyArray & _arr = iter->second ;
		CPolicyArray::iterator iterPolicy = _arr.begin() ;
			while(iterPolicy != _arr.end()) {
				CPolicy * pPolicy = (CPolicy *)*iterPolicy;
				if(pPolicy->get_crc() == crc) {
					return pPolicy ;
				}
				iterPolicy++ ;
		}
		iter++ ;
	}
	return NULL ;
}

void      CPolicyManager::del_PolicyFromCrc(unsigned int crc) {
	CLockHelper  helper(&m_pMaplocker);
	std::map<enPolicytype ,CPolicyArray>::iterator iter = m_policyMap.begin();
	bool bDel = false ;
	while(iter != m_policyMap.end()) {
		CPolicyArray & _arr = iter->second ;
		CPolicyArray::iterator iterPolicy = _arr.begin() ;
		while(iterPolicy != _arr.end()) {
			CPolicy * pPolicy = (CPolicy *)*iterPolicy;
			if(pPolicy->get_crc() == crc) {
				int type = pPolicy->get_type();
				m_bRefrush[type] = true ;
				free_policy(pPolicy);
				///更改状态为不存在
				if(_arr.size()==0) {
					update_policyStat((enPolicytype)type,pstat_noexsit);
				}
				iterPolicy = _arr.erase(iterPolicy);
				bDel = true;
				continue ;
			}
			iterPolicy++ ;
		 }
		 if(bDel) {
			 break ;
		 }
		 iter++ ;
	}
}

CPolicy  *  CPolicyManager::get_Policy(std::string & type , int  id) {
	enPolicytype pType = typefromTartget(type);
	return get_Policy(pType,id);
}

int  CPolicyManager::get_CrcMapEx(std::map<unsigned int,int>  & _map) {
	CLockHelper  helper(&m_pMaplocker);

	std::map<enPolicytype ,CPolicyArray>::iterator iter = m_policyMap.begin();
	while(iter != m_policyMap.end()) {
		CPolicyArray & _arr = iter->second ;
		CPolicyArray::iterator iterPolicy = _arr.begin() ;
		while(iterPolicy != _arr.end()) {
			CPolicy * pPolicy = (CPolicy *)*iterPolicy;
			_map[pPolicy->get_crc()] = pPolicy->get_type() ;
			iterPolicy++ ;
		}
		iter++ ;
	}
	return _map.size();
}

int  CPolicyManager::get_CrcMap( std::map<unsigned int ,int> & _map){
	CLockHelper  helper(&m_pMaplocker);

	std::map<enPolicytype ,CPolicyArray>::iterator iter = m_policyMap.begin();
	while(iter != m_policyMap.end()) {
		CPolicyArray & _arr = iter->second ;
		CPolicyArray::iterator iterPolicy = _arr.begin() ;
		while(iterPolicy != _arr.end()) {
			CPolicy * pPolicy = (CPolicy *)*iterPolicy;
			_map[pPolicy->get_crc()] = pPolicy->get_id() ;
			iterPolicy++ ;
		}
		iter++ ;
	}
	return _map.size();
}

CPolicy  *  CPolicyManager::get_CurExecpolicy(enPolicytype type) {
	if(m_pexecPolicyArray[type] == NULL) {
		m_pexecPolicyArray[type] = create_policy(type);
		if(m_pexecPolicyArray[type] == NULL) {
			return NULL ;
		}
	}
	CPolicy * maxPolicy = NULL ;
	///需要更新策略缓存
	if(m_bRefrush[type]) {
		CLockHelper  helper(&m_pMaplocker);
		///先找一下有没有策略应用
		std::map<enPolicytype ,CPolicyArray>::iterator iterArray = m_policyMap.find(type);
		if(iterArray == m_policyMap.end()) {
			return NULL ;
		}
		CPolicyArray & _arrray = iterArray->second ;
		///寻找ID最大的
		CPolicyArray::iterator  iterP = _arrray.begin();
		int maxid = 0 ;

		while(iterP != _arrray.end()) {
			CPolicy * pPolicy = *iterP ;
			if(maxid < pPolicy->get_id()) {
				maxid = pPolicy->get_id() ;
				maxPolicy = pPolicy ;
			}
			iterP++ ;
		}

		m_bRefrush[type] = false ;
		if(maxPolicy) {
			maxPolicy->copy_to((m_pexecPolicyArray[type]));
		} else { ///一个都没找到， 必然有问题， 返回。
			return NULL ;
		}
	}
	return m_pexecPolicyArray[type] ;
}

#if 0
void CPolicyManager::inc_dismiss_cnt(enPolicytype type) {
    CLockHelper helper (&m_p_dismiss_locker);
    if(type >= en_policytype_count) {
        return;
    }
    m_policy_dismiss_cnt[type]++;
}

int  CPolicyManager::get_dismiss_cnt(enPolicytype type) {
    CLockHelper helper (&m_p_dismiss_locker);
    return m_policy_dismiss_cnt[type];
}

void CPolicyManager::set_dismiss_cnt(enPolicytype type, int cnt) {
    CLockHelper helper (&m_p_dismiss_locker);
    if(type >= en_policytype_count || cnt < 0) {
        return;
    }
    m_policy_dismiss_cnt[type] = cnt;
}
#endif
