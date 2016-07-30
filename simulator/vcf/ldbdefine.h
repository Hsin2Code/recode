/**
 * ldbdefine.h
 *
 *  Created on: 2014-12-10
 *      Author: sharp
 *  本地数据库的定义文件
 */

#ifndef LDBDEFINE_H_
#define LDBDEFINE_H_

#include "include/fastdb/fastdb.h"
#include <string>

USE_FASTDB_NAMESPACE

#define LDB_NAME  "edp_localdb"

enum  {
	dbCOMMIT = 0x01,
	dbDESTORYCONTEXT = 0x02,
};




///数据库版本，记录到tbl_config里面
///可能以后版本的数据库表结构会变
///=======================================
// value常量 定义
#define  LDB_VERSION_1_0_0_0 "1.0.0.0"
#define  LDB_VERSION_2_0_0_0 "2.0.0.0"
#define  LDB_VERSION_VAL     LDB_VERSION_2_0_0_0
#define  LDB_TRUE_VAL            "true"
#define  LDB_FALSE_VAL           "false"


///=======================================
//KEY常量定义
#define  LDB_VERSION        "ldb_version"  //数据库版本号
#define  LDB_REGISTER       "ldb_register" //是否注册
#define  LDB_REGIP          "ldb_regip"    //本地注册IP
#define  LDB_REGMAC         "ldb_regmac"   //本地注册MAC
#define  LDB_SRVIP          "ldb_srvip"    //服务器地址
#define  LDB_OFFL_ALAWAYS   "ldb_offl_alaways"  ///是否一直断网
#define  LDB_REGNIC         "ldb_regNic"        ///注册网卡名
#define  LDB_REGGUISTR      "ldb_regguistr"  ///注册界面发来的字符串
#define  LDB_SRVTYPE        "ldb_srvType"    ///0是LINUX ，1是WIN
/*IP/MAC绑定策略*/
#define  LDB_BIND_MAC       "ldb_bind_mac"
#define  LDB_BIND_GW        "ldb_bind_gw"
#define  LDB_BIND_IP        "ldb_bind_ip"
#define  LDB_BIND_MASK      "ldb_bind_mask"
#define  LDB_BIND_PCRC      "ldb_bind_pcrc"

/*for client settting info*/
#define LDB_VAS_CFG_USER_NAME    "LDB_VAS_CFG_USER_NAME"
#define LDB_VAS_CFG_COMP_NAME    "LDB_VAS_CFG_COMP_NAME"
#define LDB_VAS_CFG_DEP_NAME     "LDB_VAS_CFG_DEP_NAME"
#define LDB_VAS_CFG_MACH_LOC     "LDB_VAS_CFG_MACH_LOC"
#define LDB_VAS_CFG_ASSERT_NO    "LDB_VAS_CFG_ASSERT_NO"
#define LDB_VAS_CFG_EMAIL        "LDB_VAS_CFG_EMAIL"
#define LDB_VAS_CFG_PHONE        "LDB_VAS_CFG_PHONE"
#define LDB_VAS_CFG_DESC         "LDB_VAS_CFG_DESC"
#define LDB_VAS_CFG_IS_REG       "LDB_VAS_CFG_IS_REG"



/**
 * 定义表类型
 */
enum  en_localTbl {
	tbl_log,     ///审计日志
	tbl_asset,      ///硬件资产
	tbl_asset_soft, ///软件资产
	tbl_config,  ///配置
	tbl_policy,  ///策略
	tbl_tipslog, ///提示日志
};

/**
 * 表名格式T_name,"T_"为前缀
 */
///本地配置表
class  T_base {
protected :

	int  T_type ;
public:
	///自增标识
	unsigned  int  id ;
	en_localTbl  get_Type() {
		return (en_localTbl)T_type ;
	}
};

class  T_localcfg: public T_base {
public:
	T_localcfg() {
		T_type = tbl_config ;
	}

public:
	///配置名称
	char  const  *  name ;
	///配置值
	char  const  *  vals ;

	TYPE_DESCRIPTOR((KEY(id,INDEXED|AUTOINCREMENT),
			        FIELD(name),
			        FIELD(vals),
			        FIELD(T_type)));
};

///日志类型
enum  en_logType {

};

///审计日志表
class  T_localog: public T_base {
public:
	T_localog() {
		T_type = tbl_log ;
	}

public:
	///日志类型 取值范围 en_logType 定义
	int      type  ;
	///what
	int      what  ;
	///日志内容
	char const  *  pContent ;
	///产生时间单位秒,
	int      time ;

	TYPE_DESCRIPTOR((KEY(id,INDEXED|AUTOINCREMENT),
				        FIELD(type),
				        FIELD(what),
				        FIELD(pContent),
				        FIELD(T_type),
				        FIELD(time)));
};

///硬件资产类型
enum  en_assetType {
	asset_hd , ///硬盘
	asset_cd , ///光驱
	asset_cpu, ///处理器
	asset_mbd, ///主板
	asset_mem, ///内存
	asset_vc , ///显卡
	asset_kb,  ///键盘
	asset_svctl , ///声音，视频和游戏控制器
	asset_mouse, ///鼠标和其他指针设备
	asset_nic,  ///网卡
	asset_fd,   ///软盘驱动器
	asset_slot,  ///系统插槽
	asset_usb, ///USB接口类型
	asset_nic_speed, ///网卡速率
	asset_mem_used , ///内存使用情况
	asset_hd_used,   ///硬盘使用情况
	asset_count,
};

extern const  char * g_asset_desc[asset_count];

///资产表
class T_localasset : public T_base{
public:
	T_localasset() {
		T_type = tbl_asset ;
	}
public:

	///资产类型 取值范围 en_assetType 定义
	int       type  ;
	///内容
	char   const *  pContent ;

	TYPE_DESCRIPTOR((KEY(id,INDEXED|AUTOINCREMENT),
					        FIELD(type),
					        FIELD(pContent),
					        FIELD(T_type)));
};

///软件资产表
class T_lasset_soft : public T_base {
public:
	T_lasset_soft() {
		T_type = tbl_asset_soft ;
	}
public:
	char const    *    pName ;
	char const    *    pVer ;
	char const    *    pTime ;

	TYPE_DESCRIPTOR((KEY(id,INDEXED|AUTOINCREMENT),
								FIELD(T_type),
						        FIELD(pName),
						        FIELD(pVer),
						        FIELD(pTime)));
};

///策略
class T_policy : public T_base{
public:
	T_policy() {
		T_type = tbl_policy ;
	}

	///策略ID
	int   pid  ;
	///策略类型
	int   type ;
	///crc校验和
	unsigned int	  crc  ;
	///策略内容
	char  const  *    pContent ;

	TYPE_DESCRIPTOR((KEY(id,INDEXED|AUTOINCREMENT),
								FIELD(T_type),
						        FIELD(pid),
						        FIELD(type),
						        FIELD(crc),
						        FIELD(pContent)));
};

///提示信息
class  T_Tipslog : public T_base {
public:
	T_Tipslog() {
		T_type = tbl_tipslog;
	}
public :
	///时间
	int               time ;
	///提示框类型
	unsigned int      sign ;
	///返回值
	unsigned int      ret ;
	///其他参数格式字符串
	char  const  *    param ;
	///提示内容
	char  const  *    pContent ;

	TYPE_DESCRIPTOR((KEY(id,INDEXED|AUTOINCREMENT),
									FIELD(T_type),
							        FIELD(time),
							        FIELD(sign),
							        FIELD(ret),
							        FIELD(param),
							        FIELD(pContent)));
};


#endif /* LDBDEFINE_H_ */
