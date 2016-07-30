
/**
 * user_right_audit.h
 *
 *  Created on: 2015-01-30
 *      Author: liu
 *
 *
 *   该文件是用户权限审计策略类对应的头文件；
 */

#ifndef _VRV_POLICY_USER_RIGHT_AUDIT_H
#define _VRV_POLICY_USER_RIGHT_AUDIT_H

#include "../policysExport.h"

/**
 *用于外部调用的函数声明。
 */
extern bool user_right_audit_init(void);
extern bool user_right_audit_worker(CPolicy *pPolicy, void *pParam);
extern void user_right_audit_uninit(void);

/**
 *枚举类型定义
 */
enum check_type_e
{
    CHECK_TYPE_USER_ADD = 0,
    CHECK_TYPE_USER_DEC,
    CHECK_TYPE_SYSTEM_USER,
    CHECK_TYPE_CHANGE_USER_STAT,
    CHECK_TYPE_SYSTEM_GRP,
    CHECK_TYPE_GRP_ADD,
    CHECK_TYPE_GRP_DEC
};

/**
 *助手类定义
 */
//上报信息
class Auditinfo
{
    public:
        string WatchClass;
        string UpInfo;
        string Prompt;
        string PromptInfo;
};

//用户信息
class Userinfo
{
    public:
		int status;
		
		string userid;
        string username;
		string usergroup;
};
typedef vector<Userinfo> userinfo_vector;

//用户组信息
class Groupinfo
{
	public:
		string groupid;
		string groupname;
		string groupuser;	
};
typedef vector<Groupinfo> groupinfo_vector;

//用户组用户信息
class Groupuser
{
	public:
		string groupname;
		list<string> groupusers;
};
typedef vector<Groupuser> groupuser_vector;

typedef list<string> strlst;

/**
 *用户权限策略类定义
 */
class CUserRightAudit: public CPolicy{
public:
	CUserRightAudit();
	virtual ~CUserRightAudit();

public:
	virtual bool import_xml(const char*);
	virtual void copy_to(CPolicy * pDest);

public:
	//控制列表容器
	vector<Auditinfo> auditlist; 
};
#endif //_VRV_POLICY_USER_RIGHT_AUDIT_H
