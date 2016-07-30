/*
 * CEdpApp.h
 *
 *  Created on: 2015-5-20
 *      Author: sharp
 *
 *
 *    2.0以后的一些其他业务可以加到这里面
 */

#ifndef CEDPAPP_H_
#define CEDPAPP_H_

#include "CVCFApp.h"

class CEdpApp: public CVCFApp {
public:
	CEdpApp();
	virtual ~CEdpApp();
public:

	/**
	 *  VCF初始化函数，
	 *  完成 客户端启动的一些初始化操作。
	 */
	virtual  bool         InitInstances();
	/**
	 * VCF退出清理函数，一些资源的回收操作可以在这里执行
	 */
	virtual  int          ExitInstances(int extid);

	/**
	 * 定时器处理函数， 可以在这里驱动一些周期性的操作
	 * 所有定义的定时器到了固定时间，都会在此处相应
	 * 此函数和主线程通道函数在一个线程。
	 */
	virtual  bool         timer_proc(int id);
	/**
	 *  主线程消息处理函数
	 */
	virtual  bool         msg_proc(unsigned short cmd , PVOID buffer, int len,unsigned int id);

protected:
	///进程间消息通道执行函数
	virtual	bool        IMC_msg_proc(unsigned short cmd , PVOID buffer , int len,unsigned int id);
	///审计日志消息
	virtual bool        Upload_msg_proc(unsigned short cmd , PVOID buffer , int len,unsigned int id);
	///策略执行消息通道
	virtual bool        Policy_msg_proc(unsigned short cmd , PVOID buffer , int len,unsigned int id);

	virtual  bool  get_lconfig(en_lcfg_key key , std::string & val);
	/**
	 * 设置本地配置
	 */
	virtual  bool  set_lconfig(en_lcfg_key key , const std::string & val);

	bool        on_Client_Upgrade();
    bool        register_after_install();
    void        save_spec_value();
 protected:
	/**
	 *  消息回调函数
	 *  cmd     : 消息号
	 *  pbuffer : 缓冲区
	 *  len     : 缓冲区长度
	 *  pid     : 启动时服务器（本地CIMCSrv）传入到客户端的ID
	 */
    virtual   void       Sinkmsg_proc(unsigned short cmd,void * pbuffer,int len,int pid);
    /**
     *  登录消息响应
     *  id 为传入到客户端的ID
     */
    virtual   bool       onLogon(int id, bool btray = false ,const char * pUser = NULL );
    ///客户端登出
    virtual   void       onLogout(int id);
	/**
	 *  从子类获取zmq实例
	 */
protected:
	int         m_nClientUpgradeTimer ;
    int         m_check_protect_id;
private:
    void _get_config_from_db(en_lcfg_key key, std::string &val);
    bool _set_config_to_db(en_lcfg_key key, const std::string &val, bool check_value_empty = true);
    std::string type_to_cfg_name(en_lcfg_key key);
    void get_ipmac_db_cfg(en_lcfg_key key, std::string &val);
    void do_protect();
private:
    std::map<int, std::string> _ipmac_cfg_map;
    std::map<int, int> _msg_proc_cmd_map;
};

#endif /* CEDPAPP_H_ */
