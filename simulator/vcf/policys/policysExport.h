/*
 * policysExport.h
 *
 *  Created on: 2014-12-11
 *      Author: sharp
 *
 *
 *  所有Policys
 */

#ifndef POLICYSEXPORT_H_
#define POLICYSEXPORT_H_
#include <string>
#include <vector>
#include <map>
#include <string.h>
#include "../VCFCmdDefine.h"
#include "../common/Commonfunc.h"
#include "../CNetHeader.h"
#include "../../include/Markup.h"
#include "../../include/cli_config.h"

#ifndef NULL
#define NULL  0
#endif

#define property_def(name,ot) \
private :  ot  m_##name ;    \
public  :  void  set_##name( ot & x) { \
	m_##name = x ; }        \
	 ot & get_##name() { \
           return m_##name  ;  \
		}
///获取发送消息的接口
extern IVCFAppSendinterface * g_GetSendInterface() ;
///获取日志记录的LOG
extern ILocalogInterface *    g_GetlogInterface() ;
///获取网络回调接口
extern INetEngineSinkinterface  *  g_GetNetEnginesinkInterface();
///获取本地配置接口
extern ILocalCfginterface *   g_GetlcfgInterface();
///获取改变消息接口
extern IEventNotifyInterface * g_GetEventNotifyinterface();

class  CPolicy ;

///策略类型
enum  enPolicytype {
	///软件安装策略
    SOFT_INSTALL_CTRL,
    ///进程策略
    PROCESS_CTRL,
    ///ip绑定控制
    IPMAC_BIND_CTRL,
    ///
    SOFT_DOWN_CTRL,
    ///违规外联
    ONLINE_DEAL_CTRL,
    ///
    UDISK_ACT_CTRL,
    ///端口保护
    ///PORT_PROTECT_CTRL,
    ///设备安装控制
    DEV_INSTALL_CTRL,
    ///文件保护控制
    FILE_PROTECT_CTRL,
    ///上网访问审计
    HTTP_VISIT_CTRL,
    ///
    POLICY_SEC_BURN,
    ///文件操作控制
    FILE_OP_CTRL,
    ///策略加密
    POLICY_ENCRYPTION,
    ///HTTP接入控制
    HTTP_ACCESS_CTRL,
    ///
    POLICY_AUTO_SHUTDOWN,
    ///文件校验和
    FILE_CHECKSUM_EDIT,
    ///服务控制
    SERVICE_CTRL,
    ///链接监视
    SYSTEM_CONN_MONITOR,
    ///虚拟机检查
    VIRTUAL_MACHINE_CHECK,
    ///客户端流量控制
    CLI_FLOW_CTRL,
    ///用户权限策略
    USER_RIGHT_POLICY,
    ///主机配置策略
    HOST_CFG_EDIT,
    ///违规操作检查
    VIOLATION_ACT_CHK,
    ///运行信息
    RUN_INFOMATION,
	 ///
    CONNECT_GATEWAY_AFFIRM,
    //边界检查
    NET_BD_CHK,
    //协议防火墙
    PROTOCOL_FIREWALL_CTRL,
    ///终端健康体检
    POLICY_HEALTHCHECK,
    ///终端设置策略
    POLICY_CLIENT_SET,
    en_policytype_count,
};

extern  const char * policy_target[en_policytype_count] ;


/**
 *  策略设置开始执行相应函数,初始化
*/
typedef bool  (*policy_pInit)();
/**
 *  策略执行函数指针
 *  pPolicy 为当前执行策略的副本结构体
 *  pParam ; 策略定时器设置的时候参数
 */
typedef bool (*policy_pworker)(CPolicy * pPolicy, void * pParam);
///策略清理函数
typedef void (*policy_pUninit)();

///策略执行结构体
struct  tag_PolicyExecHelper {
	int   interval  ;    ///执行间隔，单位毫秒,最小间隔10毫秒， 如果为零，默认为100毫秒
	policy_pInit pInit ; ///策略初始化函数
	policy_pworker pworker ;
	policy_pUninit pUninit ;
	tag_PolicyExecHelper(int _invterval, policy_pInit _pinit,policy_pworker _worker ,policy_pUninit _puninit) {
		interval = _invterval ;
		pInit = _pinit;
		pworker = _worker ;
		pUninit = _puninit ;
	}
};


///策略执行结构体定义
extern   tag_PolicyExecHelper   g_PolicyExecHelper[en_policytype_count];

//======================================================================
/**
 *  上报日志
 *  @type  标识不同的策略，取值和之前的版本一样
 *  @waht  取值和之前的一样。
 *  @pcontent 策略内容
 *  @bNow 是否立即上报 true为立即上报，false为定时上报。
 *
 *  参考以前的函数 Report_client_info(string info,WORD m_type,WORD m_what,DWORD pkt_CRC)函数
 *  for example :
 *
 *  char buffer[2048]=“”;
 *  tag_Policylog * plog = (tag_Policylog *)buffer ;
 *  plog->type = m_type;
 *	plog->what = m_what ;
 *	sparintf(plog->log,"%s",info.c_str());
 *	///非立即上报调用d
 *  report_policy_log(plog);
 *	///立即上报调用
 *	report_policy_log(plog,true);
 */
bool    report_policy_log(tag_Policylog * plog,bool bNow = false);
///立即上传一类特殊日志 比如IPMACBIND策略的不带BODY的日志
bool    report_policy_log_spec(tag_Policylog * plog);


/**
 *  基本上策略按执行特点来划分分5种
 *  (1) 执行一次，     执行时间短 （可以放在主线程顺序执行）
 *  (2) 执行一次,      执行时间长（可放在单独的线程中执行）
 * （3） 执行多次      每次执行时间短（可以通过定时器驱动执行）
 * （4） 执行多次，    每次执行时间较长（可以通过定时器驱动启动单独的线程执行）
 * （5） 执行时间可能非常长，有安全隐患的（内存泄漏，容易崩溃的）  放到单独进程执行，避免影响主程序运行。
 *
 *  大部分策略的执行都是开定时器，定期驱动发送消息到主线程驱动策略执行通道的线程池执行某个策略，主线程根据实际情况，
 *  判断策略是否需要执行。
 */
///动态申请一个策略
CPolicy   *    create_policy(enPolicytype  type);
///释放一个策略内存
void           free_policy(CPolicy   * p);

/**
 *  检查策略是否生效,策略高级配置的统一实现
 *  返回值: true 有效; false无效
 */
bool           check_policy_validate(CPolicy * pPolicy);

///桌面用户操作函数
void           add_desk_user(std::string & user);
void           del_desk_user(std::string & user);
bool           is_desk_user(std::string & user);
void           get_desk_user(std::string & usrlst);

///策略基类
class  CPolicy {
public:
	CPolicy() {
		m_type = en_policytype_count ;
		m_id = 0;
		m_crc = 0 ;
		m_pri = 0;
		m_risk = 0 ;
		m_springMode = 1 ;
		m_DoweekDay = 0 ;
		m_startTime = 0;
		m_liveStartTime = "" ;
		m_liveEndTime =  "";
		m_InvalWeekDay =  0;
		m_dbt1 = m_det1 = 0 ;
		m_dbt2 = m_det2 = 0 ;
		m_dbt3 = m_det3 = 0 ;
		m_invalGatwayMod = 0 ;

		m_invalNetMod =  0;
		m_outline = 0 ;
		m_cloneMode = 0 ;
		m_import =  0;
		m_invalUserMod = false ;
		m_interval = 0;
		m_delay = 0;
	}
	virtual ~CPolicy() {

	}
	/**
	 * 讲对象复制给另外一个对象
	 */
	virtual void  copy_to(CPolicy * pDest) {
		pDest->m_id = m_id ;
		pDest->m_name = m_name;
		pDest->m_type = m_type ;
		pDest->m_crc = m_crc ;
		pDest->m_pri = m_pri ;
		pDest->m_risk = m_risk ;
		pDest->m_springMode = m_springMode ;
		pDest->m_DoweekDay = m_DoweekDay ;
		pDest->m_startTime = m_startTime ;
		pDest->m_liveStartTime = m_liveStartTime ;
		pDest->m_liveEndTime = m_liveEndTime ;
		pDest->m_InvalWeekDay = m_InvalWeekDay ;
		pDest->m_dbt1 = m_dbt1 ;
		pDest->m_det1 = m_det1 ;
		pDest->m_dbt2 = m_dbt2 ;
		pDest->m_det2 = m_det2 ;
		pDest->m_dbt3 = m_dbt3 ;
		pDest->m_det3 = m_det3 ;
		pDest->m_invalGatway = m_invalGatway;
		pDest->m_invalGatwayMod =m_invalGatwayMod ;
		pDest->m_invalNetMod = m_invalNetMod;
		pDest->m_outline = m_outline ;
		pDest->m_cloneMode = m_cloneMode ;
		pDest->m_import =  m_import;
		pDest->m_ExceptUser = m_ExceptUser;
		pDest->m_invalUserMod = m_invalUserMod ;
		pDest->m_interval = m_interval ;
		pDest->m_delay = m_delay ;
	}

	virtual bool   import_xml(const char * pxml)=0;
protected:
	bool           import_xmlobj(CMarkup & xml);
public:
	///策略ID
	property_def(id,int)
	///策略类型
	property_def(type,enPolicytype)
	///策略名称
	property_def(name,std::string)
	///校验和
	property_def(crc,unsigned int)
	///策略优先级
	property_def(pri,int)
	///startPolicy
	property_def(startPolicy,int)
	///风险级别
	property_def(risk,int)
	///触发方式 1：启动时触犯 ，2，定点触发。3：间隔触发 4: 32 终端登录延迟触犯
	property_def(springMode,int)
	///间隔 单位分钟
	property_def(interval,int)
	///延迟
	property_def(delay,int)
	///触发时间
	property_def(startTime,int)
	///触发时间-星期
	property_def(DoweekDay,char)
	///存活 起始时间
	property_def(liveStartTime,std::string)
	///存活 终止时间
	property_def(liveEndTime,std::string)
	///策略无效工作日星期 0 1 2 4 8 16 32 64
	property_def(InvalWeekDay,int)
	///策略无效时间段1
	property_def(dbt1,int)
	property_def(det1,int)
	///策略无效时间段2
	property_def(dbt2,int)
	property_def(det2,int)
	///策略无效时间段2
	property_def(dbt3,int)
	property_def(det3,int)
	///策略有效网关 0除例外网关中的网关地址均 有效 1除例外网关中的网关地址均 无效
	property_def(invalGatway,std::vector<std::string>)
	property_def(invalGatwayMod,int)
	///策略有效网络 0在所有网络均 有效 1仅在内部网络中 有效 2仅在外部网络中 有效
	property_def(invalNetMod,int)
	///0包含离线  1包含离线
	property_def(outline,int)
	///备注
	property_def(reMark,std::string)
	///锁定对策略的停用操作
	property_def(import,int)
	///克隆机MODE
	property_def(cloneMode,int)
	///例外用户
	property_def(ExceptUser,std::vector<std::string>)
	property_def(invalUserMod,int)
};

///策略数组
typedef   std::vector<CPolicy *>   CPolicyArray ;

#endif /* POLICYSEXPORT_H_ */
