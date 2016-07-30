/*
 * CPolicyManager.h
 *
 *  Created on: 2014-12-12
 *      Author: sharp
 *
 *
 *   策略的管理类，实现策略的各种操作。
 */

#ifndef CPOLICYMANAGER_H_
#define CPOLICYMANAGER_H_
#include "policys/policysExport.h"
#include "common/CLocker.h"
using namespace YCommonTool;
enum  en_policy_stat {
	///不存在或者没有应用
	pstat_noexsit,
	///准备运行,包括在准备队列里面
	pstat_rdy,
	///执行前初始化
	pstat_init,
	///在运行队列里
	pstat_willrun,
	///正在运行
	pstat_runing,
	///运行空闲
	pstat_free,

	///取消策略清理
	pstat_uinit,
};


class CPolicyManager {
public:
	CPolicyManager();
	virtual ~CPolicyManager();

public:
	///获取策略个数
    int       get_PolicyCount() {
    	return m_policyMap.size() ;
    }

    void      clean_Map();

    /**
     * 导入一条策略 , 成功的话返回策略指针
     */
   CPolicy  *      importFromXml(int id,int type,unsigned int crc,const char * pXml) ;
   ///获取策略状态，用来判断改策略是否应该执行。
   en_policy_stat  get_policyStat(enPolicytype type);
   ///更新策略状态锁
   void            update_policyStat(enPolicytype type, en_policy_stat stat);

   /**
    * 获取一条策略
    * @type为策略类型
    * @id为策略ID
    */
   CPolicy  *      get_Policy(std::string & type , int  id);
   /**
    * 获取一条策略
    * @type为策略类型
    * @id为策略ID
    */
   CPolicy  *      get_Policy(enPolicytype type , int  id);

   /**
    * 跟据CRC获取策略
    */
   CPolicy  *      get_PolicyFromCrc(unsigned int crc);
   /*
    * 根据CRC删除策略
    */
   void            del_PolicyFromCrc(unsigned int crc);

   /**
    * 获取是否启动更新过程了
    */
   bool            isUpdateing() {
	   return  m_bUpdateing ;
   }
   void            set_Updateing(bool bUpdating) {
	   m_bUpdateing = bUpdating ;
   }

   /**
    * 获取CRCmap
    * KEY为策略CRC，value为策略id
    */
   int                   get_CrcMap(std::map<unsigned int,int>  & _map);
   /**
    * 获取CRCMAP
    * KEY为CRC value为策略type
    */
   int                   get_CrcMapEx(std::map<unsigned int,int>  & _map);

   /**
    * 获取当前执行的策略
    * 该程序不是线程安全，由调用者避免竞争
    */
   CPolicy  *            get_CurExecpolicy(enPolicytype type);
   ///从字符描述获取类型
   enPolicytype          typefromTartget(std::string & type);
#if 0
public:
   void inc_dismiss_cnt(enPolicytype type);
   int  get_dismiss_cnt(enPolicytype type);
   void set_dismiss_cnt(enPolicytype type, int cnt);
#endif
protected:


protected:
   ///策略的保存数组
   std::map<enPolicytype ,CPolicyArray> m_policyMap ;
   ///策略保存MAP锁
   CLocker              m_pMaplocker;
   ///策略的状态
   en_policy_stat       m_pooicyStat[en_policytype_count];
#if 0
   int                  m_policy_dismiss_cnt[en_policytype_count];
   CLocker              m_p_dismiss_locker;
#endif
   ///策略状态锁
   CLocker              m_pstatLocker;
   ///是否正在更新
   volatile	  bool	    m_bUpdateing ;
   /**
    * 策略执行中控制
    */
   ///是否执行缓存需要更新
   volatile   bool      m_bRefrush[en_policytype_count] ;
   ///执行的策略缓存
   CPolicy     *        m_pexecPolicyArray[en_policytype_count];
};

#endif /* CPOLICYMANAGER_H_ */
