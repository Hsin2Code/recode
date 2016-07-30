/*
 * policysExport.cpp
 *
 *  Created on: 2014-12-16
 *      Author: sharp
 *
 *   各种策略的定义，解析。
 */
#include "policysExport.h"
#include <stdio.h>
#include "../common/Commonfunc.h"
#include <iconv.h>
#include <stdio.h>
#include "../common/CLocker.h"
/************************************************************************************
 *  策略与框架接口编码规范
 *  1. 各个策略暴露的3个函数前缀为策略类型enPolicytype定义枚举变量的字符串，
 *     后缀为（_init,_worker,uninit）这3者之一。
 *  2.
 *
 *
 *
 *
 *
 *************************************************************************************/
//===================================================================================
/// include zone
//#include "HTTP_VISITED_CTRL/http_visit_ctrl.h"
//#include "POLICY_AUTO_SHUTDOWN/policy_auto_shutdown.h"
//#include "HTTP_ACCESS_CTRL/http_access_ctrl.h"
//#include "FILE_OP_CTRL/file_op_ctl.h"
//#include "PROCESS_CTRL/process_ctrl.h"
//#include "RUN_INFORAMTION/run_inforamtion.h"
//#include "SEC_BURN_CTRL/sec_burn_ctl.h"
//#include "SERVICE_CTRL/service_ctrl.h"
//#include "USER_RIGHT_AUDIT/user_right_audit.h"
//#include "SOFT_INSTALL_CTRL/soft_install_ctrl.h"
//#include "DEV_INSTALL_CTRL/dev_install_ctrl.h"
//#include "UDISK_ACT_CTRL/udisk_act_ctrl.h"
//#include "SOFT_DOWN_CTRL/soft_down_ctl.h"
//#include "ONLINE_DEAL_CTRL/online_deal_ctrl.h"
//#include "IPMAC_BIND_CTRL/ipmac_bind_ctrl.h"
//#include "SYSTEM_CONN_MONITOR/sys_conn_monitor.h"
//#include "FILE_CHECKSUM_EDIT/file_checksum_edit.h"
//#include "CONNECT_GATEWAY_AFFIRM/connect_gateway_affirm.h"
//#include "NET_BD_CHK/net_bd_chk.h"
//#include "PROTOCOL_FIREWALL_CTRL/protocol_firewall_ctrl.h"
//#include "POLICY_HEALTHCHECK/policy_healthcheck.h"
//#include "POLICY_CLIENT_SET/policy_client_set.h"
//=====================================================================
//策略高级设置 ， 对高级设置中一些资源消耗较大的检测，实行间隔控制
static  const  time_t  g_policycheck_interval = 10 ; ///10秒
static  time_t         g_policycheck_lastTime[en_policytype_count] = {0};
///上一次执行时间
static  time_t         g_policycheck_lastExec[en_policytype_count] = {0};

//=====================================================================
///桌面用户
static  std::vector<std::string>  g_vtDeskUser ;
static  YCommonTool::CLocker  g_vtUserLock;

void           get_desk_user(std::string & usrlst) {
	YCommonTool::CLockHelper helper(&g_vtUserLock);
	std::vector<std::string>::iterator iter = g_vtDeskUser.begin();
	while(iter != g_vtDeskUser.end()) {
		usrlst = *iter + " ";
		iter++;
	}

	if(usrlst.length()==0) {
		YCommonTool::get_loginUser(usrlst);
	}
}

void           add_desk_user(std::string & user) {
	YCommonTool::CLockHelper helper(&g_vtUserLock);
	std::vector<std::string>::iterator iter = g_vtDeskUser.begin();
	while(iter != g_vtDeskUser.end()) {
		if(user == *iter) {
			return ;
		}
		iter++;
	}
	g_vtDeskUser.push_back(user);
}
void           del_desk_user(std::string & user) {
	YCommonTool::CLockHelper helper(&g_vtUserLock);
	std::vector<std::string>::iterator iter = g_vtDeskUser.begin();
	while(iter != g_vtDeskUser.end()) {
		if(user == *iter) {
			g_vtDeskUser.erase(iter);
			return ;
		}
		iter++;
	}
}
bool           is_desk_user(std::string & user) {
	YCommonTool::CLockHelper helper(&g_vtUserLock);
	std::vector<std::string>::iterator iter = g_vtDeskUser.begin();
	while(iter != g_vtDeskUser.end()) {
		if(user == *iter) {
			return true;
		}
		iter++;
	}
	return false ;
}


//===================================================================================
const char * policy_target[en_policytype_count] = {"SOFT-INSTALL-CONTROL","PROCESS-CONTROL","IPMAC-BIND-CONTROL",\
						   "SOFT-DOWN-CONTROL","ONLINE-DEAL-CONTROL","UDISK-ACTION-CONTROL", \
						   "DEVICE-INSTALL-CONTROL","FILE-PROTECT-CONTROL", \
						   "HTTP-VISITED-CONTROL","POLICY-SECURITY-BURN","FILE-OPERATOR-CONTROL", \
						   "POLICY-ENCRYPTION","HTTP-ACCESS-CONTROL","POLICY-AUTO-SHUTDOWN",
						   "FILE-CHECKSUM-EDIT","SERVICE-CONTROL","SYSTEM-CONNECT-MONITOR", \
						   "VIRTUAL-MACHINE-CHECK","CLIENT-FLOW-CONTROL","USERRIGHT-POLICY", \
						   "HOST-CONFIG-EDIT","VIOLATION-ACTION-CHECK","RUN-INFORAMTION","CONNECT-GATEWAY-AFFIRM", \
						   "POLICY-CLIENT-BORDERCHECK","PORT-PROTECT","POLICY-HEALTHCHECK", "POLICY-CLIENT-SET"};

///上报日志,把赋值交给每个策略
bool    report_policy_log(tag_Policylog * plog,bool bNow) {
	int len = sizeof(tag_Policylog) + strlen(plog->log) + 1;
	plog->time = YCommonTool::get_Timesec();
	if(bNow) {
	    return g_GetSendInterface()->sendto_Uplog(VCF_CMD_LOG_ALERT,plog,len);
	} else {
		return g_GetSendInterface()->sendto_Uplog(VCF_CMD_LOG_NORMAL,plog,len);
	}
}

bool    report_policy_log_spec(tag_Policylog * plog) {
	int len = sizeof(tag_Policylog) + strlen(plog->log) + 1;
	plog->time = YCommonTool::get_Timesec();
	return g_GetSendInterface()->sendto_Uplog(VCF_CMD_LOG_ALERT_SPEC,plog,len);
}

/**
 *  赋值，各自策略的函数数组进行赋值
 */

#ifdef __APPLE__
/*remove here when we start to imp this*/
static const int IPMAC_INTERVAL = 10;
static const int ONLINE_DEAL_CTRL_INTERVAL = 10000;
#endif

tag_PolicyExecHelper  g_PolicyExecHelper[en_policytype_count] = {
		///SOFT_INSTALL_CTRL
		tag_PolicyExecHelper(10000,NULL,NULL,NULL),
		///PROCESS_CTRL
		tag_PolicyExecHelper(10000,NULL,NULL,NULL),
		///IPMAC_BIND_CTRL
		tag_PolicyExecHelper(IPMAC_INTERVAL*1000,NULL,NULL,NULL),
		///SOFT_DOWN_CTRL
		tag_PolicyExecHelper(10000,NULL,NULL,NULL),
		///ONLINE_DEAL_CTRL
		tag_PolicyExecHelper(ONLINE_DEAL_CTRL_INTERVAL,NULL,NULL,NULL),
		///UDISK_ACT_CTRL
		tag_PolicyExecHelper(1000,NULL,NULL,NULL),
		///DEV_INSTALL_CTRL
		tag_PolicyExecHelper(1000,NULL,NULL,NULL),
		///FILE_PROTECT_CTRL
		tag_PolicyExecHelper(0,0,0,0),
		///HTTP_VISIT_CTRL 10S
		tag_PolicyExecHelper(10000,NULL,NULL,NULL),
		///POLICY_SEC_BURN
		tag_PolicyExecHelper(1000,NULL,NULL,NULL),
		///FILE_OP_CTRL
		tag_PolicyExecHelper(500,NULL,NULL,NULL),
		///POLICY_ENCRYPTION
		tag_PolicyExecHelper(0,0,0,0),
		///HTTP_ACCESS_CTRL
		tag_PolicyExecHelper(60*1000,NULL,NULL,NULL),
		///POLICY_AUTO_SHUTDOWN
		tag_PolicyExecHelper(60000, NULL, NULL, NULL),
		///FILE_CHECKSUM_EDIT
		tag_PolicyExecHelper(40*1000,NULL,NULL,NULL),
		///SERVICE_CTRL
		tag_PolicyExecHelper(10000,NULL,NULL,NULL),
		///SYSTEM_CONN_MONITOR
		tag_PolicyExecHelper(1000,NULL,NULL,NULL),
		///VIRTUAL_MACHINE_CHECK
		tag_PolicyExecHelper(0,0,0,0),
		///CLI_FLOW_CTRL
		tag_PolicyExecHelper(0,0,0,0),
		///USE_RIGHT_POLICY
		tag_PolicyExecHelper(10000,NULL,NULL,NULL),
		///HOST_CFG_EDIT
		tag_PolicyExecHelper(0,0,0,0),
		///VIOLATION_ACT_CHK
		tag_PolicyExecHelper(0,0,0,0),
		///RUN_INFOMATION
		tag_PolicyExecHelper(1000,NULL,NULL,NULL),
		///CONNECT_GATEWAY_AFFIRM
		tag_PolicyExecHelper(5000, NULL,NULL,NULL),
		///NET_BD_CHK
		tag_PolicyExecHelper(60*1000,NULL,NULL,NULL),
		///PROTOCOL_FIREWALL_CTRL
		tag_PolicyExecHelper(10000,NULL,NULL,NULL),
		///POLICY-HEALTHCHECK
		tag_PolicyExecHelper(5000, NULL, NULL, NULL),
        ///POLICY-CLIENT-SET
		tag_PolicyExecHelper(12345, NULL, NULL, NULL)
};
///==============================================================================================================
///获取策略公用数据  策略名称可能为中文， 注意转码
int   strTimeToint(std::string & str) {
	if(str.length() == 0) {
		return 0 ;
	}
	int hour = atoi(str.substr(0,2).c_str());
	int minute = atoi(str.substr(3,2).c_str());
	return (hour * 3600 + minute * 60);
}
extern int code_convert(const char *from_charset,const char *to_charset,char *inbuf,int inlen,char *outbuf,int & outlen);
bool   CPolicy::import_xmlobj(CMarkup & xml) {
	xml.ResetPos();
	std::string  PolicyName;
	if(xml.FindElem("vrvscript")) {
		///需要转ma
		m_name = xml.GetAttrib("PolicyName");
		char outbuffer[129]="";
		int  out_len = 129 ;
		code_convert("gb2312","utf-8",const_cast<char *>(m_name.c_str()),m_name.length(),outbuffer,out_len);
		m_name = outbuffer;
	}

	m_pri = atoi(xml.GetAttrib("Priority").c_str());
	m_risk = atoi(xml.GetAttrib("PolicyRiskLevel").c_str());
	m_springMode = atoi(xml.GetAttrib("SpringMode").c_str());
	m_DoweekDay = atoi(xml.GetAttrib("DoWeekDay").c_str());
	m_startTime = atoi(xml.GetAttrib("DoHour").c_str()) * 3600 + atoi(xml.GetAttrib("DoMinute").c_str()) * 60 ;
	m_liveStartTime= xml.GetAttrib("PolicyStartTime");
	m_liveEndTime= xml.GetAttrib("PolicyEndTime");

	m_interval = atoi(xml.GetAttrib("IntervalTime").c_str());
	m_delay = atoi(xml.GetAttrib("Delay").c_str());

	m_InvalWeekDay = atoi(xml.GetAttrib("InvalidWeekDay").c_str());
	std::string tmp = xml.GetAttrib("DBT1");
	m_dbt1 = strTimeToint(tmp);
	tmp = xml.GetAttrib("DET1");
	m_det1 = strTimeToint(tmp);
	tmp = xml.GetAttrib("DBT2");
	m_dbt2 = strTimeToint(tmp);
	tmp = xml.GetAttrib("DET2");
	m_det2 = strTimeToint(tmp);
	tmp = xml.GetAttrib("DBT3");
	m_dbt3 = strTimeToint(tmp);
	tmp = xml.GetAttrib("DET3");
	m_det3 = strTimeToint(tmp);

	m_invalNetMod = atoi(xml.GetAttrib("NetValidMode").c_str());

	m_invalUserMod = atoi(xml.GetAttrib("UserValidMode").c_str());
	tmp = xml.GetAttrib("ExceptUser").c_str() ;
	m_ExceptUser.clear();
	YCommonTool::split_new(tmp,m_ExceptUser,";");

	m_invalGatwayMod = atoi(xml.GetAttrib("GatewayValidMode").c_str());
	m_cloneMode = atoi(xml.GetAttrib("CloningMachineValidMode").c_str());
	m_import = atoi(xml.GetAttrib("ImportPolicyNotStop").c_str());
	tmp = xml.GetAttrib("ExceptGateway").c_str() ;
	m_invalGatway.clear();
	YCommonTool::split_new(tmp,m_invalGatway,";");
	m_outline = atoi(xml.GetAttrib("outline").c_str());
	m_reMark = xml.GetAttrib(" Remark");

	return true ;
}

void        free_policy(CPolicy   * p) {

	delete p ;
}

CPolicy   *    create_policy(enPolicytype  type) {
	switch(type) {
	case SOFT_INSTALL_CTRL:
        return NULL;
	case PROCESS_CTRL:
        return NULL;
	case IPMAC_BIND_CTRL:
        return NULL;
	case SOFT_DOWN_CTRL:
        return NULL;
	case ONLINE_DEAL_CTRL:
        return NULL;
	case UDISK_ACT_CTRL:
        return NULL;
	case DEV_INSTALL_CTRL:
        return NULL;
	case FILE_PROTECT_CTRL:
		return NULL ;
	case HTTP_VISIT_CTRL:
        return NULL;
	case POLICY_SEC_BURN:
        return NULL;
	case FILE_OP_CTRL:
        return NULL;
	case POLICY_ENCRYPTION:
		return NULL ;
	case POLICY_AUTO_SHUTDOWN:
		return NULL ;
	case FILE_CHECKSUM_EDIT:
		return NULL ;
	case SERVICE_CTRL:
		return NULL ;
	case SYSTEM_CONN_MONITOR:
		return NULL ;
	case VIRTUAL_MACHINE_CHECK:
		return NULL ;
	case CLI_FLOW_CTRL:
		return NULL ;
	case USER_RIGHT_POLICY:
		return NULL ;
	case HOST_CFG_EDIT:
		return NULL ;
	case VIOLATION_ACT_CHK:
		return NULL ;
	case RUN_INFOMATION:
		return NULL ;
	case HTTP_ACCESS_CTRL:
		return NULL ;
	case CONNECT_GATEWAY_AFFIRM: 
		return NULL ;
	case NET_BD_CHK:
		return NULL ;
	case PROTOCOL_FIREWALL_CTRL:
		return NULL ;
	case POLICY_HEALTHCHECK:
		return NULL ;
    case POLICY_CLIENT_SET:
		return NULL ;
	default:
		return NULL ;
	}
    return NULL ;
}

/**
 *  检查策略是否生效
 *  返回值: true 有效; false无效
 */
bool       check_policy_validate(CPolicy * pPolicy) {
	char curTime[32] = "" ;
	time_t timep;
	struct tm *p;
	time(&timep);
	p = localtime(&timep);
	sprintf(curTime, "%d-%02d-%02d", (1900 + p->tm_year),(1 + p->tm_mon), p->tm_mday);
	time_t start_sec =  YCommonTool::get_Startsec();

	///先判断存活时间
	std::string & liveStart = pPolicy->get_liveStartTime();
	std::string & livEnd = pPolicy->get_liveEndTime();
	if(liveStart.length() && livEnd.length()) {
		///小于起始日期
		if(strcmp(curTime,liveStart.c_str()) < 0) {
			return false ;
		}
		if(strcmp(curTime,livEnd.c_str()) > 0) {
			return false ;
		}
	}

	int start = 0 ;
	bool bcheck = false ;
	if(pPolicy->get_springMode() & 0x01) {///启动
		start++ ;
		bcheck = true ;
	}

	if(pPolicy->get_springMode() & 0x02) {
		int hour = pPolicy->get_startTime() / 3600 ;
		int minute = (pPolicy->get_startTime() - 3600 * hour) / 60;
		if(p->tm_hour == hour && p->tm_min == minute) {
			start++;
		}
		if(pPolicy->get_DoweekDay()) {
			if((pPolicy->get_DoweekDay() -1) == p->tm_wday) {
				start++;
			}
		}
		bcheck = true ;
	}

	if(pPolicy->get_springMode() & 0x04) {///间隔触发
		///未实现
		int nInterval = pPolicy->get_interval() * 60;
		if(start_sec - g_policycheck_lastExec[pPolicy->get_type()] >= nInterval) {
			start++;
		}
		bcheck = true ;
	}

	if(pPolicy->get_springMode() & 0x20) {///终端启动延时触发
		///未实现
		int sec = pPolicy->get_delay() * 60 ;
		if(start_sec - g_GetlcfgInterface()->get_UpTime() >= sec) {
			start++;
		}
		bcheck = true ;
	}
	if(start == 0 && bcheck) {
		return false ;
	}

	///无效星期
	if(pPolicy->get_InvalWeekDay()) {
		char weekSign[7] = {64,1,2,4,8,16,32};
		if(weekSign[p->tm_wday] & pPolicy->get_InvalWeekDay()) {
			return false ;
		}
	}

	int curSec  = p->tm_hour * 3600 + p->tm_min * 60 ;

	//无效时间段
	if(pPolicy->get_det1() != 0) {
		if(pPolicy->get_dbt1() <= curSec && curSec <= pPolicy->get_det1()) {
			return false ;
		}
	}

	if(pPolicy->get_det2() != 0) {
		if(pPolicy->get_dbt2() <= curSec && curSec <= pPolicy->get_det2()) {
			return false ;
		}
	}

	if(pPolicy->get_det3() != 0) {
		if(pPolicy->get_dbt3() <= curSec && curSec <= pPolicy->get_det3()) {
			return false ;
		}
	}

	////下面的这些需要时间控制,减少资源消耗。
	if(timep - g_policycheck_lastTime[pPolicy->get_type()] < g_policycheck_interval) {
		g_policycheck_lastTime[pPolicy->get_type()] = timep ;
		g_policycheck_lastExec[pPolicy->get_type()] = start_sec ;
		return true ;
	}
	g_policycheck_lastTime[pPolicy->get_type()] = timep ;

	///获取本地网关
	if(pPolicy->get_invalGatway().size()) {
		std::string nic = "";
		nic = YCommonTool::get_gatWay(nic);
		printf("本地网关=‘%s’\n",nic.c_str());
		///特殊网关
		if(pPolicy->get_invalGatwayMod() == 0) {
			bool bisExsit = false ;
			std::vector<std::string>::iterator iter = pPolicy->get_invalGatway().begin();
			while(iter != pPolicy->get_invalGatway().end()) {
				if(nic == *iter) {
					bisExsit = true ;
					break ;
				}
				iter++ ;
			}
			///存在
			if(bisExsit) {
				return false ;
			}
		} else {
			bool bisExsit = false ;
			std::vector<std::string>::iterator iter = pPolicy->get_invalGatway().begin();
			while(iter != pPolicy->get_invalGatway().end()) {
				if(nic == *iter) {
					bisExsit = true ;
					break ;
				}
				iter++ ;
			}
			///存在
			if(!bisExsit) {
				return false ;
			}
		}
	}

	YCommonTool::en_netaddrtype nettype = YCommonTool::check_addr_type();

	///本身地址检查
	switch(pPolicy->get_invalNetMod()) {
	case 0: { ///所有网络中均有效
			break ;
		}
	case 1: { ///仅在内部网络中
			if(nettype !=  YCommonTool::addr_only_internal)
				return false ;
			break ;
		}
	case 2: { ///仅在外部网络中
			if(nettype !=  YCommonTool::addr_only_internet)
				return false ;
			break ;
		}
	}
	///例外用户检查
	if(pPolicy->get_ExceptUser().size() > 0) {
		bool bisExsit = false ;
		std::vector<std::string>::iterator iter = pPolicy->get_ExceptUser().begin();
		while(iter != pPolicy->get_ExceptUser().end()) {
			if(is_desk_user(*iter)) {
				bisExsit = true ;
				break ;
			}
			iter++ ;
		}
		///除例外用户中的所有用户均 有效
		if(pPolicy->get_invalUserMod() == 0) {
			if(bisExsit) {
				return false ;
			}
		} else { ///除例外用户中的所有用户均 无效
			if(!bisExsit) {
				return false ;
			}
		}
	}
	g_policycheck_lastExec[pPolicy->get_type()] = start_sec ;
	return true ;
}
