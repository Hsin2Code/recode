/**
 * VCFCmdDefine.h
 *
 *  Created on: 2014-12-2
 *      Author: sharp
 *
 *	VCFAPP进程里面所有的命令定义,主消息通道定义的CMD值必须大于CYApp.h里面的定义的YAPP_CMD_MAX，、\n
 *  非主消息通道的的消息定义可以不遵守以上约定。\n
 *  相同消息通道里面的消息定义号不能相同.\n
 *
 *  当前工程定义成连续的。
 */

#ifndef VCFCMDDEFINE_H_
#define VCFCMDDEFINE_H_
#include "../include/cli_config.h"
#include <string.h>

/**
 *  主消息通道的消息号
 */
enum  {
	///VCFAPP开始进入运行流程
	VCF_CMD_MAIN_SRUNING = 1001,
	///更新策略消息
	VCF_CMD_CALL_POLICYUPDATE ,
	///呼叫策略执行开始
	VCF_CMD_CALL_POLICY_START,
	///呼叫策略停止
	VCF_CMD_CALL_POLICY_STOP,
	///策略初始化失败
	VCF_CMD_POLICYEXECINIT_FAILED,
	///策略初始化成功
	VCF_CMD_POLICYEXECINIT_SUCC,
	///策略执行提醒
	VCF_CMD_POLICYEXEC_NOW,
	///策略执行失败
	VCF_CMD_POLICYEXEC_FAILED,
	///关机
	VCF_CMD_CALL_SHUTDOWN,
	///断网
	VCF_CMD_CALL_CLOSENET,
	///重启
	VCF_CMD_CALL_RESTART,
	///策略被取消
	VCF_CMD_POLICY_UNAPPLY,
	///策略全部取消
	VCF_CMD_POLICY_UNAPPLY_ALL,
	///锁屏
	VCF_CMD_LOCK_SCREEN,
	///开启网络
	VCF_CMD_OPEN_NET,
    ///IP/MAC持久存储
    VCF_CMD_SET_IPMAC_CFG,
    VCF_CMD_GET_IPMAC_CFG,

    //最大的主消息通道
    MAIN_CMD_ZONE_MAX,
};
/**
 * VCF_CMD_OPEN_NET 消息携带
 */
struct tag_openNet {
	///取值范围enPolicytype , 填入需要断网的策略类型
	int    policy ;
};
/**
 * VCF_CMD_CALL_CLOSENET 消息携带
 * tag_closeNet  tmp ;
 * tmp.policy = IPMAC_BIND_CTRL //IPMAC绑定策略发起的断网请求
 * tmp.bAlaways = false ; //非永久断网
 * tmp.bAlaways = true ; //永久断网
 * send_toMain(VCF_CMD_CALL_CLOSENET,&tmp,sizeof(tag_closeNet));
 */
struct tag_closeNet {
	///取值范围enPolicytype , 填入需要断网的策略类型
	int    policy ;
	///永久断网，需要通过服务器解封。
	bool   bAlaways;

	/**
	 * 断网时间，当bAlaways=false的时候有效，
	 * 标识断网多久，单位秒，为零的话，需要重启机器网络才能恢复正常。
	 */
	//int    offlineTime ;
	tag_closeNet() {
		policy = -1;
		bAlaways = false ;
		//offlineTime = 0 ;
	}
};

///呼叫策略执行 VCF_CMD_CALL_POLICY_START 消息携带
struct   tag_CallPolicyStart {
	int  type     ;
	int  interval ;
	bool once     ;
};

///VCF_CMD_POLICY_UNAPPLY携带
struct   tag_PApplyChange {
	void  *  pDelArray   ;
	void  *  pDelUnApply ;
};

typedef void  (*pTips_retfunc)(unsigned int  type);

///VCF_CMD_GUI_TIPS携带
/**
 *  示例
 *
 *  void tipsRet(unsigned int sign);
 *
 *  char buffer[512] = "";
 *  tag_GuiTips * pTips = (tag_GuiTips *)buffer ;
 *  pTips->sign = en_TipsGUI_btnOK | en_TipsGUI_btnCancle ; ///界面标识
 *  pTips->defaultret = en_TipsGUI_btnOK ;
 *  pTips->pfunc = &tipsRet ;
 *  sprintf(pTips->szTitle,"请确认");
 *  sprintf(pTips->szTips,"您是否需要退出系统？");
 *  g_GetSendInterface()->sendto_Imc(VCF_CMD_GUI_TIPS,buffer,sizeof(tag_GuiTips));
 */
struct   tag_GuiTips {
	///取值为enTipsGuiTtype类型
	unsigned int sign ;
	///默认返回值，1.设置了timeout超时默认返回。 2.默认焦点的按钮
	unsigned int defaultret ;
	///返回执行函数
	pTips_retfunc pfunc ;
	///提示框TITLe
	char   szTitle[32];
	///提示信息
    char   szTips[256] ; ///提示信息
    ///参数
    union {
    	int   timeout ; /// 毫秒 当sign含有en_TipsGUI_timeOut标志的时候该字段有效
    } param;

    tag_GuiTips() {
    	memset(this,0,sizeof(tag_GuiTips));
    }
};

///策略执行失败错误号
enum  enPexecError {
	///策略不存在
	policy_noexsit ,
};

///策略执行失败结构体VCF_CMD_POLICYEXEC_FAILED 消息携带
struct  tag_pExecFailed {
	///策略种类
	int  type  ;
	///错误类型
	enPexecError err ;
};
///VCF_CMD_SET_IPMAC_CFG 和 VCF_CMD_GET_IPMAC_CFG 携带
struct tag_ipmac_info {
    int type;
    char info[256];
    tag_ipmac_info() {
        type = -1;
        memset(info, 0, sizeof(info));
    }
};

/**
 *  进程间消息通道的消息号
 */
enum {
	///启动注册界面
	VCF_CMD_MCMSG_TEST = MAIN_CMD_ZONE_MAX + 1,
	///启动注册进程
	VCF_CMD_REGISTER_GUI,
	///注册成功
	VCF_CMD_REGISTER_SUCC,
	///启动提示框
	VCF_CMD_GUI_TIPS,
	///提示框返回
	VCF_CMD_GUI_TIPS_RET,
    VCF_CMD_VAS_GUI_TIPS,
    VCF_CMD_VAS_PULL_UP_SYSTRAY,
	//最大进程通道消息号
	VCF_CMD_IMC_MAX,
};

/**
 *  审计日志记录通道,本地数据库操作通道
 */
enum {
	///策略批量上床
	VCF_CMD_BATCH_UPLOAD = VCF_CMD_IMC_MAX + 1,
	///记录一般日志，缓存再上报的日志。
	VCF_CMD_LOG_NORMAL,
	///上报特殊日志，立即上报
	VCF_CMD_LOG_ALERT,
	///上报特殊日志， 不带BODY的
	VCF_CMD_LOG_ALERT_SPEC,
	///本地数据库操作通道
	VCF_CMD_LDB_OPERATOR,
	///获取资产信息 ,
	VCF_CMD_LDB_GET_ASSET,
	///更新软件资产
	VCF_CMD_LDB_UPDATA_SASSET,
	///更新硬件资产
	VCF_CMD_LDB_UPDATA_HASSET,
	//最大日志消息号
	VCF_CMD_LOG_MAX,
};

///VCF_CMD_LDB_UPDATA_SASSET , VCF_CMD_LDB_UPDATA_HASSET消息携带
struct tag_ldbUpdatasAsset {
	void  *   pAdd    ;
	void  *   pDel    ;
	void  *   pModify ;
	tag_ldbUpdatasAsset() {
		pAdd = NULL ;
		pDel = NULL ;
		pModify = NULL ;
	}
};

///获取资产结构体， VCF_CMD_LDB_GET_ASSET命令携带，需要调用者同步调用
struct tag_ldbGetAsset {
	void  *  pSoftMap ;
	void  *  pHardMap ;
	tag_ldbGetAsset() {
		pSoftMap = NULL ;
		pHardMap = NULL ;
	}
};

///策略日志, VCF_CMD_LOG_NORMAL ,VCF_CMD_LOG_ALERT 都使用此结构体。
struct tag_Policylog {
	int  type ;
	int  what ;
	int  time ;
	char log[0];
};

///操作方式
enum  en_DBOp {
	dbop_add ,
	dbop_modify ,
	dbop_del ,
};


///VCF_CMD_LDB_OPERATOR 消息携带
struct tag_LDBexec {
	///表名
	int  tbl  ;
	///操作方法  取值范围 en_DBOp
	int  cnt  ;
	char cbop ;
	///数据个数
	///数据数组,数据类型与tbl，cbop字段有关系
	char data[0];
};

/**
 *  策略执行通道消息号
 */
enum {
	///由客户端定期时驱动的定时更新策略消息
	VCF_CMD_POLICY_UPDATA_GENERAL = VCF_CMD_LOG_MAX + 1,
	///策略初始化
    VCF_CMD_POLICY_EXEC_INIT ,
	///呼叫策略执行
	VCF_CMD_CALL_POLICYEXEC ,
	//策略反初始化
	VCF_CMD_POLICY_EXEC_UINIT ,
	///获取资产信息
	VCF_CMD_GET_ASSEET,
	///心跳
	VCF_CMD_HEART_BEAT,
    ///客户端升级
    VCF_CMD_CLIENT_UPGRADE,
	VCF_CMD_POLICY_MAX,
};


///策略初始化参数
struct tag_PolicyExecinit {
	///策略类型
	int   type;
	///执行间隔
	int   interval ;
	///是否循环
	bool   bloop;
	///参数
	void  * pdata ;
};


///驱动策略执行结构体, VCF_CMD_CALL_POLICYEXEC 消息携带此结构体
struct  tag_CallPolicyExec {
	int    pType ; ///策略类型
	void * pdata ; ///携带数据
	tag_CallPolicyExec() {
		pType = 0xffffffff ;
		pdata = 0 ;
	}
};


/**
 *   APP类的发送消息接口指针
 */

///发送消息的接口类, 可以在其策略模块里面调用
///以后由其他的发送接口可以在下面定义
///用这个接口把VCFAPP实现和其他模块隔离起来。
///@bsync = true标识同步，下面几个接口方法都相同
class   IVCFAppSendinterface {
public :
	///发送消息到日志执行通道
	virtual	    bool    sendto_Uplog(unsigned short cmd,void * pdata, int len,bool bsync = false) = 0 ;
	///发送消息到进程间消息通道
	virtual     bool    sendto_Imc(unsigned short cmd,void * pdata, int len,bool bsync = false) = 0 ;
	///发送消息到主线程通道
	virtual     bool    sendto_Main(unsigned short cmd,void * pdata, int len,bool bsync = false) = 0;
	///发送消息到策略执行通道
	virtual     bool    sendto_pl4Exec(unsigned short cmd,void * pdata, int len,bool bsync = false) = 0;
};

///策略控制接口
class  IVCFPolicyCtrlinterface {
public :
	/**
	 * 启动执行策略。\n
	 * @pType     策略的类型\n
	 * @interval  策略执行间隔\n
	 * @once      是否执行一次， true执行一次， false循环执行\n
	 * 返回值 :   true为启动成功，false为启动失败。
	 */
	virtual    bool      start_pl4(int pType, int interval,bool once) = 0;
	///获取策略状态
	virtual    int       get_pl4Status(int pType) = 0;
	///关闭策略执行
	virtual    void      stop_pl4(int pType) = 0;
};

class ILocalogInterface {
public:
	/// 输出日志，老接口，以后会删除
	virtual void       loglog(const char *  plog) = 0 ;
	/// trace log
	virtual void       log_trace(const char *  plog) = 0;
	/// debug log
	virtual void       log_debug(const char *  plog) = 0 ;
	/// notice log
	virtual void       log_notice(const char *  plog) = 0 ;
	/// warn
	virtual void       log_warning(const char *  plog) = 0 ;
	/// error
	virtual void       log_error(const char *  plog) = 0 ;
};

/**
 * 获取本地配置的接口
 */
enum  en_lcfg_key {
	///获取注册IP
	lcfg_regip,
	///获取注册MAC
	lcfg_regmac,
	///获取id
	lcfg_devid,
	///获取服务器IP
	lcfg_srvip,
	///获取注册网卡名
	lcfg_regnic,
	///获取桌面用户名
	lcfg_deskName,
	///客户端监听端口
	lcfg_listenPort,
	///注册界面字符串
	lcfg_reguiStr,
    ///for IP/MAC BIND
    lcfg_bind_ip,
    lcfg_bind_mac,
    lcfg_bind_gw,
    lcfg_bind_mask,
    lcfg_bind_pcrc,
    lcfg_get_server_time,
    /*for ui client*/
    lcfg_ui_username,
    lcfg_ui_compname,
    lcfg_ui_depname,
    lcfg_ui_machloc,
    lcfg_ui_email,
    lcfg_ui_phone,
    lcfg_ui_assertno,
    lcfg_ui_desc,
    lcfg_ui_is_reg,
    lcfg_invalid
};

class ILocalCfginterface  {
public:
	/**
	 * 获取本地配置
	 */
	virtual  bool  get_lconfig(en_lcfg_key key , std::string & val) = 0;
	/**
	 * 设置本地配置
	 */
	virtual  bool  set_lconfig(en_lcfg_key key , const std::string & val) = 0;
	/**
	 * 获取是否断网
	 */
	virtual  bool  get_offlstat() = 0;
	/**
	 * 获取终端启动时间 从系统启动时间记时
	 */
	virtual  time_t get_UpTime() = 0 ;
	/**
	 * 是否WIN服务器
	 */
	virtual  bool  is_WinSrv() = 0 ;
};

/**
 * 事件消息
 */
///变化执行函数 不要在此函数里面执行费时的操作
typedef void (*pNotify_func)(void * pParam);
enum enNotifyerEvent {
	enNotifyer_policyAdvcfg_statChange, ///高级策略状态改变
	enNotifyer_deskUser_logon, ///桌面用户登录
};
class IEventNotifyInterface {
public:
	///注册消息
	virtual bool  registerEvent(enNotifyerEvent event , pNotify_func pfunc) = 0;
	///注销消息
	virtual void  UnregisterEvent(enNotifyerEvent event , pNotify_func pfunc) = 0;
};

#endif /* VCFCMDDEFINE_H_ */

