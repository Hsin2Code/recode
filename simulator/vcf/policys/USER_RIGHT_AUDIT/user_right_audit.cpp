
/**
 * user_right_audit.cpp
 *
 *  Created on: 2015-01-30
 *  Author:liu 
 *
 *
 *  该文件包含了用户权限审计略策所需的所有函数；
 */
using namespace std;
#include <unistd.h>
#include <stdio.h>
#include <sstream>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>
#include "user_right_audit.h"
#include "../../../include/Markup.h"
#include "../../../include/MCInterface.h"
#include "../../VCFCmdDefine.h"
#include "../../vrvprotocol/VRVProtocol.hxx"
#include "../../common/Commonfunc.h"

/*本地宏定义*/
#define USER_INFO_TMP_FILE "/tmp/vrv_uid_tmp" 
#define GRP_INFO_TMP_FILE "/tmp/vrv_gid_tmp" 


/*本地全局变量*/
//用户信息
userinfo_vector userlist_new_add;
userinfo_vector userlist_old_add;

userinfo_vector userlist_new_del;
userinfo_vector userlist_old_del;

userinfo_vector userlist_new_rig;
userinfo_vector userlist_old_rig;

userinfo_vector userlist_new_status;
userinfo_vector userlist_old_status;
		
//变更用户信息
userinfo_vector userlist_add;
userinfo_vector userlist_del;
userinfo_vector userlist_rig;

list<string> start_user;
list<string> stop_user;

//用户组信息
groupinfo_vector grouplist_new_add;
groupinfo_vector grouplist_old_add;

groupinfo_vector grouplist_new_del;
groupinfo_vector grouplist_old_del;

groupinfo_vector grouplist_new_rig;
groupinfo_vector grouplist_old_rig;

//变更用户组信息
groupinfo_vector grouplist_add;
groupinfo_vector grouplist_del;

//用户组所属用户变更信息
groupuser_vector grouplist_rig_add;
groupuser_vector grouplist_rig_del;
		
//用户组所属用户
list<string> srclist;
list<string> dstlist;

//用户变更标志
int flag_add_user = 0;
int flag_del_user = 0;
int flag_rig_user = 0;

//用户组变更标志
int flag_add_group = 0;
int flag_del_group = 0;
int rig_add_group = 0;
int rig_del_group = 0;

//用户状态发生变化
int flag_start_user = 0;
int flag_stop_user = 0;

/*外部函数声明*/
extern int code_convert(const char *from_charset,const char *to_charset,char *inbuf,int inlen,char *outbuf,int & outlen);

/*本地使用的函数声明*/
static void userRightAudit_log_run_info(const char *log_content);
static void userRightAudit_show_dlg(const char *info);
static int userRightAudit_update_user_add_info(void);
static int executeCMD(const char *cmd, char *result);
static int userRightAudit_user_add_check(CUserRightAudit *pUsrRight, string rpt_flg, string tip_flg, string tip_info);
static int userRightAudit_user_dec_check(CUserRightAudit *pMe, string rpt_flg, string tip_flg, string tip_info);
static int userRightAudit_group_add_check(CUserRightAudit *pUsrRight, string rpt_flg, string tip_flg, string tip_info);
static int userRightAudit_group_dec_check(CUserRightAudit *pUsrRight, string rpt_flg, string tip_flg, string tip_info);
static int userRightAudit_system_user_check(CUserRightAudit *pMe, string rpt_flg, string tip_flg, string tip_info);
static int userRightAudit_system_grp_check(CUserRightAudit *pMe, string rpt_flg, string tip_flg, string tip_info);
static int userRightAudit_user_stat_check(CUserRightAudit *pMe, string rpt_flg, string tip_flg, string tip_info);
static int user_right_audit_get_check_type(string str_type, enum check_type_e *type);
static void userRightAudit_rpt_evt_to_server(string logContent);
static string  userRightAudit_build_log_info(CUserRightAudit *pMe, int kind, string evt_info);

/*外部函数*/
extern bool  report_policy_log(tag_Policylog * plog,bool bNow);
extern ILocalogInterface * g_GetlogInterface(void) ;

typedef int (*pCheck_fun)(CUserRightAudit *pMe, string rpt_flg, string tip_flg, string tip_info);

pCheck_fun userRightAudit_check[] = {
                                    userRightAudit_user_add_check,
                                    userRightAudit_user_dec_check,
                                    userRightAudit_system_user_check,
                                    userRightAudit_user_stat_check,
                                    userRightAudit_system_grp_check,
                                    userRightAudit_group_add_check,
                                    userRightAudit_group_dec_check
                                   };
/**
 * 类的构造方法
 */
CUserRightAudit::CUserRightAudit()
{
    enPolicytype type = USER_RIGHT_POLICY ;
	set_type(type);
	userRightAudit_log_run_info("constructor.");
}
/**
 * 类的析构函数
 */
CUserRightAudit::~CUserRightAudit()
{
	userRightAudit_log_run_info("destroy.");
}

/**
 *父类虚函数实现：copy函数
 */
void CUserRightAudit::copy_to(CPolicy * pDest)
{
	userRightAudit_log_run_info("copy_to_start.");

	((CUserRightAudit*)pDest)->auditlist = auditlist;

   	CPolicy::copy_to(pDest);
	userRightAudit_log_run_info("copy_to end.");
}

/**
 *父类虚函数实现：策略导入函数
 */
bool CUserRightAudit::import_xml(const char *pxml)
{
    char buf_policy[512] = {0};
    int nodenum = 0;

    userRightAudit_log_run_info("import_xml start.");
    if(pxml == NULL)
    {
        userRightAudit_log_run_info("import_xml:pxml is null.");
        return false ;
    }

    CMarkup  xml ;
    if(!xml.SetDoc(pxml))
    {
        userRightAudit_log_run_info("import_xml:SetDoc failed.");
        return false ;
    }

    auditlist.clear();

    Auditinfo item;

    if(xml.FindElem("vrvscript"))
    {
        xml.IntoElem();
        std::string tmp_str;

        while(xml.FindElem("item"))
        {
            nodenum  ++;

            item.WatchClass.clear();
            item.UpInfo.clear();
            item.Prompt.clear();
            item.PromptInfo.clear();

            tmp_str = xml.GetAttrib("WatchClass");
            if(0 != tmp_str.length())
            {
                item.WatchClass.assign(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "watchclass:%s", item.WatchClass.c_str());
                userRightAudit_log_run_info(buf_policy);
            }

            tmp_str = xml.GetAttrib("UpInfo");
            if(0 != tmp_str.length())
            {
                item.UpInfo.assign(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "     UpInfo:%s", item.UpInfo.c_str());
                userRightAudit_log_run_info(buf_policy);
            }

            tmp_str = xml.GetAttrib("Prompt");
            if(0 != tmp_str.length())
            {
                item.Prompt.assign(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "     Prompt:%s", item.Prompt.c_str());
                userRightAudit_log_run_info(buf_policy);
            }

            tmp_str = xml.GetAttrib("PromptInfo");
            if(0 != tmp_str.length())
            {
                item.PromptInfo.assign(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "     PromptInfo:%s", item.PromptInfo.c_str());
                userRightAudit_log_run_info(buf_policy);
            }

		    auditlist.push_back(item);
        }
        xml.OutOfElem();
    }

    snprintf(buf_policy, sizeof(buf_policy), "import policy end,item num:%d", nodenum);
    userRightAudit_log_run_info(buf_policy);

    return CPolicy::import_xmlobj(xml);
}


/**
 * 函数名:user_right_audit_init()
 * 说明:供外部调用的用户权限策略的init函数
 *  	成功返回true，失败返回false；
 */
bool user_right_audit_init(void)
{
    userRightAudit_log_run_info("init end.");
    return true;
}

/**
 * 函数名:user_right_audit_worker()
 * 说明:供外部调用的用户权限策略的worker函数
 *  	成功返回true，失败返回false；
 */
bool user_right_audit_worker(CPolicy *pPolicy, void *pParam)
{
    CUserRightAudit *pMe = (CUserRightAudit*)pPolicy;
	vector<Auditinfo> auditlist = ((CUserRightAudit*)pPolicy)->auditlist;
    int ret = 0;
    enum check_type_e check_type = CHECK_TYPE_USER_ADD;

    if(USER_RIGHT_POLICY != pPolicy->get_type())
    {
        char buf[512] = {0};
        snprintf(buf, sizeof(buf), "policy type %d invalid, should be %d", pPolicy->get_type(), USER_RIGHT_POLICY);
        userRightAudit_log_run_info(buf);
        return false;
    }


	vector<Auditinfo>::iterator p_ite;
	for(p_ite = auditlist.begin(); p_ite != auditlist.end(); p_ite ++)
    {
        ret = user_right_audit_get_check_type(p_ite->WatchClass, &check_type);
        if(0 != ret)
        {
            continue;
        }

        (void)userRightAudit_check[check_type](pMe, p_ite->UpInfo, p_ite->Prompt, p_ite->PromptInfo);
    }

    return true;
}

/**
 * 函数名:user_right_audit_uninit()
 * 说明:供外部调用的用户权限策略的uninit函数
 */
void user_right_audit_uninit()
{
    userRightAudit_log_run_info("uninit end.");
}

static int user_right_audit_get_check_type(string str_type, enum check_type_e *type)
{
    unsigned int i = 0;
    int match_type = -1;
    const char *a_type[]= { "UserAdd", 
                      "UserDec",
                      "SystemUser",
                      "ChangeUserState",
                      "SystemGroup",
                      "GroupAdd",
                      "GroupDec"
                    };
    enum check_type_e a_ret[] = { CHECK_TYPE_USER_ADD,
                                  CHECK_TYPE_USER_DEC,
                                  CHECK_TYPE_SYSTEM_USER,
                                  CHECK_TYPE_CHANGE_USER_STAT,
                                  CHECK_TYPE_SYSTEM_GRP,
                                  CHECK_TYPE_GRP_ADD,
                                  CHECK_TYPE_GRP_DEC
                                };

    for(i = 0; i < sizeof(a_type)/sizeof(a_type[0]); i++)  
    {
        if(0 == strcmp(str_type.c_str(), a_type[i])) 
        {
            match_type = i;
            break;
        }
    }

    if(-1 != match_type)
    {
        *type = a_ret[match_type]; 
        return 0;
    }

    return -1;
}

/**
 * 函数名:userRightAudit_log_run_info()
 * 说明:该函数将运行策略信息写入log文件;
 */
static void userRightAudit_log_run_info(const char *log_content)
{
	char log_info[2048] = {0};

	if(NULL == log_content)
	{
		return ;
	}
	
	snprintf(log_info, sizeof(log_info), "usr_right_adt:%s\n", log_content);

	g_GetlogInterface()->loglog(log_info);
}

/**
 * 函数名:userRightAudit_show_dlg()
 * 说明:该函数显示信息提示框，超时或者按确定后关闭;
 */
static void userRightAudit_show_dlg(const char *info)
{
    char buffer[512] = "";
    char buf_convert_info[512] = {0};     
    int dst_len = sizeof(buf_convert_info);

    if(NULL == info || 0 == strlen(info))
    {
        return;
    }

    code_convert("gb2312","utf-8", (char*)info , strlen(info), buf_convert_info, dst_len);

    tag_GuiTips * pTips = (tag_GuiTips *)buffer;
    pTips->sign = en_TipsGUI_btnOK | en_TipsGUI_timeOut; 
    pTips->defaultret = en_TipsGUI_None ;
    pTips->pfunc = NULL;
    pTips->param.timeout = 3;//以秒为单位
    sprintf(pTips->szTitle,"确认");
    snprintf(pTips->szTips, sizeof(pTips->szTips), "%s", buf_convert_info);
    g_GetSendInterface()->sendto_Imc(VCF_CMD_GUI_TIPS, buffer, sizeof(tag_GuiTips));
}

//把含有逗号的用户字串拆分存放
int get_condtion_list(string src,char delim,list <string> &mylist)
{
    string temp;
    stringstream ss(src);
    string sub_str;
    mylist.clear();
    while(0 < getline(ss,sub_str,delim))
    {
        if(sub_str !="")
        {
            mylist.push_back(sub_str);
        }
    }
    return 0;
}


//组织用户上报信息
string get_audit_user(list<string> user)
{
	list<string>::iterator p_user_audit;
	string conent;

	for(p_user_audit=user.begin();p_user_audit != user.end();p_user_audit++)
	{
		conent += *p_user_audit + ',';
	}

	return conent;
}


//获取用户当前状态
int get_user_status(string username)
{
	//去除stirng中的\n
	for(unsigned int i=0;i<username.length();i++)
 	{
 		if(username[i]=='\n')
		{
			username.erase(i, 1);
 			i--;
		}
	}

	char cmd1[256] = {0};
    memset(cmd1,0,sizeof(cmd1));
   	sprintf(cmd1,"awk -F: '$1 == \"%s\"{print $2}' /etc/shadow",username.c_str());

	char result[256] = {0};
    memset(result,0,sizeof(result));
    executeCMD(cmd1,result);

    if(0 == result[0])
    {
    	return -1;
    }
    else
    {
        if(('!' == result[0])&&(('$' == result[1])||('$' == result[2])))
        {
            return 1;
        }
        else
        {
            return 0;
        }
    }
}


//获取命令执行结果
int executeCMD(const char *cmd, char *result)
{
    FILE *ptr = NULL;
    char buf_ps[1024] = {0};
    char ps[1024]={0};
    char buf_log[512] = {0};

    strcpy(ps, cmd);

    if((ptr = popen(ps, "r"))!=NULL)
    {
        while(fgets(buf_ps, 1024, ptr) != NULL)
        {
            strcat(result, buf_ps);
            pclose(ptr);
            return 0;
        }
        pclose(ptr);
        return 1;
    }
    else
    {
        snprintf(buf_log, sizeof(buf_log), "executeCMD:popen %s error", ps);
        userRightAudit_log_run_info(buf_log);

        return 1;
    }
}


//去除字串后\n
string string_handle(string src_user)
{
	for(unsigned int i=0;i<src_user.length();i++)
	{
		if(src_user[i]=='\n')
		{
			src_user.erase(i, 1);
			i--;
		}
	}

	return src_user;
}


//判断用户组用户增加
list<string> compare_user_add(list<string> dstlist,list<string> srclist)
{
	list<string>::iterator p_user_dst;
	list<string>::iterator p_user_src;

	string user;
	list<string> groupuser_tmp;

	int flag = 0;
	
	for(p_user_dst=dstlist.begin();p_user_dst != dstlist.end();p_user_dst++)
	{
		if(srclist.empty())
		{
			flag = 1;
		}
		else
		{
			for(p_user_src=srclist.begin();p_user_src != srclist.end();p_user_src++)
			{
				if(0==strcmp((*p_user_dst).c_str(),(*p_user_src).c_str()))
				{
					flag = 0;
					break;
				}
				else
				{
					flag = 1;
				}
			}
		}
		if(1 == flag)
		{
			user = *p_user_dst;
			groupuser_tmp.push_back(user);
		}
	}

	return groupuser_tmp;
}


//判断用户组用户减少
list<string> compare_user_del(list<string> dstlist,list<string> srclist)
{
	list<string>::iterator p_user_dst;
	list<string>::iterator p_user_src;

	string user;
	list<string> groupuser_tmp;

	int flag = 0;
	
	for(p_user_dst=dstlist.begin();p_user_dst != dstlist.end();p_user_dst++)
	{
		if(srclist.empty())
		{
			flag = 1;
		}
		else
		{
			for(p_user_src=srclist.begin();p_user_src != srclist.end();p_user_src++)
			{
				if(0==strcmp((*p_user_dst).c_str(),(*p_user_src).c_str()))
				{
					flag = 0;
					break;
				}
				else
				{
					flag = 1;
				}
			}
		}
		if(1 == flag)
		{
			user = *p_user_dst;
			groupuser_tmp.push_back(user);
		}
	}

	return groupuser_tmp;
}

//比较用户UID
userinfo_vector compare_uid(userinfo_vector userlist_dst, userinfo_vector userlist_src)
{
	vector<Userinfo>::iterator p_dst;
	vector<Userinfo>::iterator p_src;

	int flag_add_del = 0;

	//变更用户信息
	Userinfo user_item;
	userinfo_vector userlist_tmp;

	//判断用户或用户组的增删
	for(p_dst=userlist_dst.begin();p_dst!=userlist_dst.end();p_dst++)
    {
        for(p_src=userlist_src.begin();p_src!=userlist_src.end();p_src++)
        {
	        if(0==strcmp(p_dst->userid.c_str(),p_src->userid.c_str()))
	        {
	        	flag_add_del = 0; //该用户已存在
	        	break;
			}
			else
			{
				flag_add_del = 1;//该用户未存在
			}
        }
		
		//变更用户信息存储
		if(1 == flag_add_del)
		{
			user_item.status = p_dst->status;
			user_item.userid = p_dst->userid;
			user_item.username = p_dst->username;
			user_item.usergroup = p_dst->usergroup;

			userlist_tmp.push_back(user_item);
		}	
	}

	return userlist_tmp;
}


//比较用户组GID
groupinfo_vector compare_gid(groupinfo_vector grouplist_dst, groupinfo_vector grouplist_src)
{
	vector<Groupinfo>::iterator p_dst;
	vector<Groupinfo>::iterator p_src;

	int flag_add_del = 0;

	//变更用户信息
	Groupinfo group_item;
	groupinfo_vector grouplist_tmp;

	//判断用户或用户组的增删
	for(p_dst=grouplist_dst.begin();p_dst != grouplist_dst.end();p_dst++)
    {
        for(p_src=grouplist_src.begin();p_src != grouplist_src.end();p_src++)
        {
	        if(0==strcmp(p_dst->groupid.c_str(),p_src->groupid.c_str()))
	        {
	        	flag_add_del = 0; //该用户已存在
	        	break;
			}
			else
			{
				flag_add_del = 1;//该用户未存在
			}
        }
		
		//变更用户信息存储
		if(1 == flag_add_del)
		{
			group_item.groupid = p_dst->groupid;
			group_item.groupname = p_dst->groupname;
			group_item.groupuser = p_dst->groupuser;

			grouplist_tmp.push_back(group_item);
		}	
	}

	return grouplist_tmp;
}


//判断用户状态
int compare_status(userinfo_vector user_status,list<string> &user_stop, list<string> &user_start)
{
	int status = 0;
	vector<Userinfo>::iterator p_stu;

	for(p_stu=user_status.begin();p_stu!= user_status.end();p_stu++)
	{
		//获取系统当前状态
		status = get_user_status(p_stu->username);

		if(-1 == status)
		{
			#ifdef debug
			cout<<"该用户不存在！"<<endl;
			#endif
		}
		else
		{
			if((1 == status) && (0 == p_stu->status))
			{
				user_stop.push_back(p_stu->username);
			}
			if((0 == status) && (1 == p_stu->status))
			{
				user_start.push_back(p_stu->username);
			}
		}
	}

	return 0;
}


//判断用户权限
userinfo_vector compare_user_rig(userinfo_vector user_old,userinfo_vector user_new)
{
	vector<Userinfo>::iterator p_dst;
	vector<Userinfo>::iterator p_src;

	//变更用户信息
	Userinfo user_item;
	userinfo_vector userlist_tmp;

	int flag_user_change = 0;

	for(p_dst=user_old.begin();p_dst != user_old.end();p_dst++)
    {
        for(p_src=user_new.begin();p_src != user_new.end();p_src++)
        {
        	if(0==strcmp(p_dst->username.c_str(),p_src->username.c_str()))
        	{
				if(0==strcmp(p_dst->usergroup.c_str(),p_src->usergroup.c_str()))
				{
					flag_user_change = 0;//用户所在组没有发生变化
					break;
				}
				else
				{
					flag_user_change = 1;//用户所在组发生变化
					break;
				}
        	}
		}

		if(1 == flag_user_change)
		{
			user_item.status = p_dst->status;
			user_item.userid = p_dst->userid;
			user_item.username = p_dst->username;
			user_item.usergroup = p_src->usergroup;

			userlist_tmp.push_back(user_item);
		}
	}
	
	return userlist_tmp;
}


//用户组用户增加
groupuser_vector group_rig_add(groupinfo_vector group_old,groupinfo_vector group_new)
{
	vector<Groupinfo>::iterator p_dst;
	vector<Groupinfo>::iterator p_src;

	//变更用户组用户信息
	list<string> groupuser_add;
	int flag_user_add = 0;

	//变更用户信息
	Groupuser group_item_add;
	groupuser_vector grouplist_tmp;
	
	for(p_dst=group_old.begin();p_dst != group_old.end();p_dst++)
    {
        for(p_src=group_new.begin();p_src != group_new.end();p_src++)
        {
        	if(0==strcmp(p_dst->groupid.c_str(),p_src->groupid.c_str()))
        	{
	        	//存储string 类型用户到list<string> 中
	        	string dst_user = string_handle(p_dst->groupuser);
	        	dstlist.clear();
				get_condtion_list(dst_user,',',dstlist);

				string src_user = string_handle(p_src->groupuser);
				srclist.clear();
				get_condtion_list(src_user,',',srclist);
				
				//用户组用户增加
				groupuser_add = compare_user_add(srclist,dstlist);
				if(groupuser_add.empty())
				{
					flag_user_add = 0;
					break;
				}
				else
				{
					flag_user_add = 1;
					break;
				}
        	}
		}
			
		if(1 == flag_user_add)   
		{
			group_item_add.groupname = p_dst->groupname;
			group_item_add.groupusers.assign(groupuser_add.begin(),groupuser_add.end());

			grouplist_tmp.push_back(group_item_add);
		}
	}

	return grouplist_tmp;
}


//用户组用户减少
groupuser_vector group_rig_del(groupinfo_vector group_old,groupinfo_vector group_new)
{
	vector<Groupinfo>::iterator p_dst;
	vector<Groupinfo>::iterator p_src;

	//变更用户组用户信息
	list<string> groupuser_del;
	int flag_user_del = 0;

	//变更用户信息
	Groupuser group_item_del;
	groupuser_vector grouplist_tmp;
	
	for(p_dst=group_old.begin();p_dst != group_old.end();p_dst++)
    {
        for(p_src=group_new.begin();p_src != group_new.end();p_src++)
        {
        	if(0==strcmp(p_dst->groupid.c_str(),p_src->groupid.c_str()))
        	{
	        	//存储string 类型用户到list<string> 中
				string dst_user = string_handle(p_dst->groupuser);
	        	dstlist.clear();
				get_condtion_list(dst_user,',',dstlist);

				string src_user = string_handle(p_src->groupuser);
				srclist.clear();
				get_condtion_list(src_user,',',srclist);
				
				groupuser_del = compare_user_del(dstlist,srclist);
				if(groupuser_del.empty())
				{
					flag_user_del = 0;
					break;
				}
				else
				{
					flag_user_del = 1;
					break;
				}
        	}
		}
		if(1 == flag_user_del) 
		{
			group_item_del.groupname = p_dst->groupname;
			group_item_del.groupusers.assign(groupuser_del.begin(),groupuser_del.end());

			grouplist_tmp.push_back(group_item_del);
		}
	}

	return grouplist_tmp;
}

//获取系统用户
int get_uid(userinfo_vector &userlist)
{
    char cmd[256] = {0};

    //判断是否有缓冲文USER_INFO_TMP_FILE 件
    if(0 == access(USER_INFO_TMP_FILE, F_OK)) 
    {
        if(-1 == unlink(USER_INFO_TMP_FILE))
        {
            userRightAudit_log_run_info("get-uid:removing usr-info-tmp-file,err.");
        }
    }
	
    snprintf(cmd, sizeof(cmd), "cat /etc/passwd | awk -F: '$3>=500' | cut -f 1,3,4 -d : > %s",USER_INFO_TMP_FILE);
    if(-1 == system(cmd))
    {
        userRightAudit_log_run_info("get-uid:cat passwd file,err.");
    }

    snprintf(cmd, sizeof(cmd), "wc -l %s | cut -f 1 -d ' '", USER_INFO_TMP_FILE);

    char result[256] = {0};
    memset(result,0,sizeof(result));
    executeCMD(cmd,result);

    Userinfo user_item;

    for(int i=1; i <= atoi(result);i++)
    {
        //获取用户名
        snprintf(cmd, sizeof(cmd), "sed -n '%dp' %s | cut -f 1 -d :", i, USER_INFO_TMP_FILE);

        char result1[256] = {0};
        memset(result1,0,sizeof(result1));
        executeCMD(cmd,result1);
        user_item.username.assign(result1);

        //获取用户状态
        user_item.status = get_user_status(user_item.username);
		
        //获取用户ID
        snprintf(cmd, sizeof(cmd), "sed -n '%dp' %s | cut -f 2 -d :", i, USER_INFO_TMP_FILE);

        char result2[256] = {0};
        memset(result2,0,sizeof(result2));
        executeCMD(cmd,result2);
        user_item.userid.assign(result2);

        //获取用户组ID
        snprintf(cmd, sizeof(cmd), "sed -n '%dp' %s | cut -f 3 -d :", i, USER_INFO_TMP_FILE);

        char result3[256] = {0};
        memset(result3,0,sizeof(result3));
        executeCMD(cmd,result3);
        user_item.usergroup.assign(result3);

        //压栈用户信息
        userlist.push_back(user_item);
    }
	
    return 0;
}

//获取系统用户组
int get_gid(groupinfo_vector &grouplist)
{
    char cmd[256] = {0};

    if(0 == access(GRP_INFO_TMP_FILE, F_OK)) 
    {
        if(-1 == unlink(GRP_INFO_TMP_FILE))
        {
            userRightAudit_log_run_info("get-gid:rm grp-info-tmp-file err.");
        }
    }

    //获取用户组数
    snprintf(cmd, sizeof(cmd), "cat /etc/group | awk -F: '$3>=500' | cut -f 1,3,4 -d : > %s", GRP_INFO_TMP_FILE);
    if(-1 == system(cmd))
    {
        userRightAudit_log_run_info("get-gid:cat grp file err.");
    }

    //获取行数
    snprintf(cmd, sizeof(cmd), "wc -l %s | cut -f 1 -d ' '", GRP_INFO_TMP_FILE);

    char result[256] = {0};
    memset(result,0,sizeof(result));
    executeCMD(cmd,result);

    Groupinfo group_item;

    for(int i = 1; i <= atoi(result);i++)
    {
        //获取用户组名
        snprintf(cmd, sizeof(cmd), "sed -n '%dp' %s | cut -f 1 -d :", i, GRP_INFO_TMP_FILE);

        char result1[256] = {0};
        memset(result1,0,sizeof(result1));
        executeCMD(cmd,result1);
        group_item.groupname.assign(result1);
	
        //获取用户组ID
        snprintf(cmd, sizeof(cmd), "sed -n '%dp' %s | cut -f 2 -d :", i, GRP_INFO_TMP_FILE);

         char result2[256] = {0};
        memset(result2,0,sizeof(result2));
        executeCMD(cmd,result2);
        group_item.groupid.assign(result2);

        //获取用户组所属用户
        snprintf(cmd, sizeof(cmd), "sed -n '%dp' %s | cut -f 3 -d :", i, GRP_INFO_TMP_FILE);

        char result3[256] = {0};
        memset(result3,0,sizeof(result3));
        executeCMD(cmd,result3);
        group_item.groupuser.assign(result3);
		
        //压栈用户组信息
        grouplist.push_back(group_item);
    }

    return 0;
}


//用户信息保存
int user_change(userinfo_vector &userlist_old,userinfo_vector &userlist_new)
{
	//保存旧的用户信息
	vector<Userinfo>::iterator p_tmp;
	Userinfo old_item;
	
	if(0 == userlist_old.size())
	{
		for(p_tmp=userlist_new.begin();p_tmp != userlist_new.end();p_tmp++)
		{
			old_item.status = p_tmp->status;
			old_item.userid = p_tmp->userid;
			old_item.username = p_tmp->username;
			old_item.usergroup = p_tmp->usergroup;

			userlist_old.push_back(old_item);
		}
	}
	else
	{
		userlist_old.clear();
		for(p_tmp=userlist_new.begin();p_tmp != userlist_new.end();p_tmp++)
		{
			old_item.status = p_tmp->status;
			old_item.userid = p_tmp->userid;
			old_item.username = p_tmp->username;
			old_item.usergroup = p_tmp->usergroup;

			userlist_old.push_back(old_item);
		}
	}

	//获取系统当前用户信息
	userlist_new.clear();
	get_uid(userlist_new);

	return 0;
}


//判断用户增加
static int userRightAudit_update_user_add_info(void)
{
	user_change(userlist_old_add,userlist_new_add);

	userlist_add.clear();
	userlist_add = compare_uid(userlist_new_add,userlist_old_add);
	if(userlist_add.empty())
	{
		flag_add_user = 0;
	}
	else
	{
		flag_add_user = 1;
	}

	return 0;
}

//判断用户减少
static int userRightAudit_update_user_del_info(void)
{
	user_change(userlist_old_del,userlist_new_del);

	userlist_del.clear();
	userlist_del = compare_uid(userlist_old_del,userlist_new_del);
	if(userlist_del.empty())
	{
		flag_del_user = 0;
	}
	else
	{
		flag_del_user = 1;
	}

	return 0;
}


//判断用户权限是否放生变化
int user_rig(void)
{
	user_change(userlist_old_rig,userlist_new_rig);
	
	userlist_rig.clear();
	userlist_rig = compare_user_rig(userlist_old_rig,userlist_new_rig);
	if(userlist_rig.empty())
	{
		flag_rig_user = 0;
	}
	else
	{
		flag_rig_user = 1;
	}

	return 0;
}


//判断用户状态是否发生变化
int user_status(void)
{
	user_change(userlist_old_status,userlist_new_status);

	start_user.clear();
	stop_user.clear();
		
	compare_status(userlist_old_status,stop_user,start_user);
		
	if(start_user.empty())
	{
		flag_start_user = 0;
	}
	else
	{
		flag_start_user = 1;
	}

	if(stop_user.empty())
	{
		flag_stop_user = 0;
	}
	else
	{
		flag_stop_user = 1;
	}

	return 0;
}


//用户组信息保存
int group_change(groupinfo_vector &grouplist_old,groupinfo_vector &grouplist_new)
{
	//保存旧的用户信息
	vector<Groupinfo>::iterator p_tmp;
	Groupinfo old_item;

	//备份旧数据
	if(0 == grouplist_old.size())
	{
		for(p_tmp=grouplist_new.begin();p_tmp != grouplist_new.end();p_tmp++)
		{
			old_item.groupid = p_tmp->groupid;
			old_item.groupname = p_tmp->groupname;
			old_item.groupuser = p_tmp->groupuser;

			grouplist_old.push_back(old_item);
		}
	}
	else
	{
		grouplist_old.clear();
		for(p_tmp=grouplist_new.begin();p_tmp != grouplist_new.end();p_tmp++)
		{
			old_item.groupid = p_tmp->groupid;
			old_item.groupname = p_tmp->groupname;
			old_item.groupuser = p_tmp->groupuser;

			grouplist_old.push_back(old_item);
		}
	}

	//获取系统当前用户组信息
	grouplist_new.clear();
	get_gid(grouplist_new);  //含有用户信息
	
	return 0;
}

	
//判断用户组增加
int userRightAudit_update_group_add_info()
{
	group_change(grouplist_old_add,grouplist_new_add);

	grouplist_add.clear();
	grouplist_add = compare_gid(grouplist_new_add,grouplist_old_add);
	if(grouplist_add.empty())
	{
		flag_add_group = 0;
	}
	else
	{
		flag_add_group = 1;
	}
	
	return 0;
}


//判断用户组减少
static int userRightAudit_update_group_del_info(void)
{
	group_change(grouplist_old_del,grouplist_new_del);

	grouplist_del.clear();
	grouplist_del = compare_gid(grouplist_old_del,grouplist_new_del);
	if(grouplist_del.empty())
	{
		flag_del_group = 0;
	}
	else
	{
		flag_del_group = 1;
	}

	return 0;
}


//判断用户组是否增加用户
int group_user_add(groupinfo_vector grouplist_old_rig,groupinfo_vector grouplist_new_rig)
{
	grouplist_rig_add.clear();
	grouplist_rig_add = group_rig_add(grouplist_new_rig,grouplist_old_rig);

	if(grouplist_rig_add.empty())
	{
		rig_add_group = 0;
	}
	else
	{
		rig_add_group = 1;
	}

	return 0;
}


//判断用户组是否减少用户
int group_user_del(groupinfo_vector grouplist_old_rig,groupinfo_vector grouplist_new_rig)
{
	grouplist_rig_del.clear();
	grouplist_rig_del = group_rig_del(grouplist_old_rig,grouplist_new_rig);

	if(grouplist_rig_del.empty())
	{
		rig_del_group = 0;
	}
	else
	{
		rig_del_group = 1;
	}
	
	return 0;
}

static int userRightAudit_group_add_check(CUserRightAudit *pMe, string rpt_flg, string tip_flg, string tip_info)
{
    string log_content;
    char buf_log[512] = {0};

    if(NULL == pMe)
    {
        return 0;
    }
    
    if("0" == rpt_flg && "0" == tip_flg)
    {
        return 0;
    }
   
    userRightAudit_update_group_add_info();
    if(!flag_add_group)
    {
        return 0;
    }

    userRightAudit_log_run_info("found group add");

    if("1" == rpt_flg)
    {
        for(unsigned int i=0;i<grouplist_add.size();i++)
        {
            string  group_info;
            char group_char[128]={0};
            sprintf(group_char,"增加用户组:%s,增加成功.",grouplist_add[i].groupname.c_str());
            group_info.assign(group_char);
							
            log_content = userRightAudit_build_log_info(pMe, 507, group_info);

            userRightAudit_rpt_evt_to_server(log_content);
        }
    }

    snprintf(buf_log, sizeof(buf_log), "grpadd:tip-info len:%d", tip_info.length());
    userRightAudit_log_run_info(buf_log);

    if("1" == tip_flg && 0 != tip_info.length())
    {
        sleep(5);/*避免和其他提示框冲突*/
        userRightAudit_show_dlg(tip_info.c_str());
        sleep(5);/*避免和其他提示框冲突*/
    }
    
    return 0;
}

static int userRightAudit_group_dec_check(CUserRightAudit *pMe, string rpt_flg, string tip_flg, string tip_info)
{
    string log_content;
    char buf_log[512] = {0};

    if(NULL == pMe)
    {
        return 0;
    }
    
    if("0" == rpt_flg && "0" == tip_flg)
    {
        return 0;
    }
   
    userRightAudit_update_group_del_info();
    if(!flag_del_group)
    {
        return 0;
    }

    userRightAudit_log_run_info("found group del");

    if("1" == rpt_flg)
    {
        for(unsigned int i=0;i<grouplist_del.size();i++)
        {
            string  group_info;
            char group_char[128]={0};
            sprintf(group_char,"减少用户组:%s,减少成功.",grouplist_del[i].groupname.c_str());
            group_info.assign(group_char);
							
            log_content = userRightAudit_build_log_info(pMe, 511, group_info);

            userRightAudit_rpt_evt_to_server(log_content);
        }
    }

    snprintf(buf_log, sizeof(buf_log), "grpdel:tip-info len:%d", tip_info.length());
    userRightAudit_log_run_info(buf_log);

    if("1" == tip_flg && 0 != tip_info.length())
    {
        sleep(5);/*避免和其他提示框冲突*/
        userRightAudit_show_dlg(tip_info.c_str());
        sleep(5);/*避免和其他提示框冲突*/
    }
    
    return 0;
}

static int userRightAudit_user_add_check(CUserRightAudit *pMe, string rpt_flg, string tip_flg, string tip_info)
{
    string log_content;
    char buf_log[512] = {0};

    if(NULL == pMe)
    {
        return 0;
    }
    
    if("0" == rpt_flg && "0" == tip_flg)
    {
        return 0;
    }
   
    userRightAudit_update_user_add_info();
    if(!flag_add_user)
    {
        return 0;
    }

    userRightAudit_log_run_info("found user add");

    if("1" == rpt_flg)
    {
        for(unsigned int i=0;i<userlist_add.size();i++)
        {
            string  user_info;
            char user_char[128]={0};
            sprintf(user_char,"增加用户:%s,增加成功.",userlist_add[i].username.c_str());
            user_info.assign(user_char);
							
            log_content = userRightAudit_build_log_info(pMe, 505, user_info);

            userRightAudit_rpt_evt_to_server(log_content);
        }
    }

    snprintf(buf_log, sizeof(buf_log), "useradd tip-info len:%d", tip_info.length());
    userRightAudit_log_run_info(buf_log);

    if("1" == tip_flg && 0 != tip_info.length())
    {
        userRightAudit_show_dlg(tip_info.c_str());
    }
    
    return 0;
}

static int userRightAudit_user_dec_check(CUserRightAudit *pMe, string rpt_flg, string tip_flg, string tip_info)
{
    string log_content;
    char buf_log[512] = {0};

    if(NULL == pMe)
    {
        return 0;
    }
   
    if("0" == rpt_flg && "0" == tip_flg)
    {
        return 0;
    }

    userRightAudit_update_user_del_info();

	if(!flag_del_user)
    {
        return 0;
    }

    userRightAudit_log_run_info("found user dec");

    if("1" == rpt_flg)
    {
        for(unsigned int i=0;i<userlist_del.size();i++)
        {
            string  user_info;
            char user_char[128]={0};
            sprintf(user_char,"减少用户:%s,减少成功.",userlist_del[i].username.c_str());
            user_info.assign(user_char);
							
            log_content = userRightAudit_build_log_info(pMe, 506, user_info);

            userRightAudit_rpt_evt_to_server(log_content);
        }
    }

    snprintf(buf_log, sizeof(buf_log), "userdel tip-info len:%d", tip_info.length());
    userRightAudit_log_run_info(buf_log);

    if("1" == tip_flg && 0 != tip_info.length())
    {
        userRightAudit_show_dlg(tip_info.c_str());
    }
    
    return 0;
}

static int userRightAudit_system_user_check(CUserRightAudit *pMe, string rpt_flg, string tip_flg, string tip_info)
{
    string log_content;
    char buf_log[512] = {0};

    if(NULL == pMe)
    {
        return 0;
    }
   
    if("0" == rpt_flg && "0" == tip_flg)
    {
        return 0;
    }

    user_rig();

	if(!flag_rig_user)
    {
        return 0;
    }

    userRightAudit_log_run_info("found system user change");

    if("1" == rpt_flg)
    {
        for(unsigned int i=0;i<userlist_rig.size();i++)
        {
            string  user_info;
            char user_char[128]={0};
            sprintf(user_char,"用户%s更改用户组为%s,更改成功.",userlist_rig[i].username.c_str(),userlist_rig[i].usergroup.c_str());
            user_info.assign(user_char);
							
            log_content = userRightAudit_build_log_info(pMe, 503, user_info);

            userRightAudit_rpt_evt_to_server(log_content);
        }
    }

    snprintf(buf_log, sizeof(buf_log), "system userchange:tip-info len:%d", tip_info.length());
    userRightAudit_log_run_info(buf_log);

    if("1" == tip_flg && 0 != tip_info.length())
    {
        userRightAudit_show_dlg(tip_info.c_str());
    }
    
    return 0;
}

static int userRightAudit_user_stat_check(CUserRightAudit *pMe, string rpt_flg, string tip_flg, string tip_info)
{
    string log_content;
    string audit;
    string user_info;
    char user_char[128]={0};
    char buf_log[512] = {0};

    if(NULL == pMe)
    {
        return 0;
    }
   
    if("0" == rpt_flg && "0" == tip_flg)
    {
        return 0;
    }

    user_status();

    if(1 == flag_start_user)
    {
        if("1" == rpt_flg)
        {
            audit = get_audit_user(start_user);

            snprintf(user_char, sizeof(user_char), "启动用户%s,启动成功.",audit.c_str());
            user_info.assign(user_char);
									
            log_content = userRightAudit_build_log_info(pMe, 514, user_info);

            userRightAudit_rpt_evt_to_server(log_content);
        }

        snprintf(buf_log, sizeof(buf_log), "enable user:tip-info len:%d", tip_info.length());
        userRightAudit_log_run_info(buf_log);

        if("1" == tip_flg && 0 != tip_info.length())
        {
            userRightAudit_show_dlg(tip_info.c_str());
        }
    }

    if(1 == flag_stop_user)
    {
        if("1" == rpt_flg)
        {
            audit = get_audit_user(stop_user);

            snprintf(user_char, sizeof(user_char), "禁止用户%s,禁止成功.",audit.c_str());
			user_info.assign(user_char);
									
            log_content = userRightAudit_build_log_info(pMe, 514, user_info);

            userRightAudit_rpt_evt_to_server(log_content);
        }

        snprintf(buf_log, sizeof(buf_log), "disable user:tip-info len:%d", tip_info.length());
        userRightAudit_log_run_info(buf_log);

        if("1" == tip_flg && 0 != tip_info.length())
        {
            userRightAudit_show_dlg(tip_info.c_str());
        }
   }
    
    return 0;
}

static int userRightAudit_system_grp_check(CUserRightAudit *pMe, string rpt_flg, string tip_flg, string tip_info)
{
    string log_content;
    string audit;
    string user_info;
    char user_char[128]={0};
    char buf_log[512] = {0};

    if(NULL == pMe)
    {
        return 0;
    }
   
    if("0" == rpt_flg && "0" == tip_flg)
    {
        return 0;
    }

    group_change(grouplist_old_rig,grouplist_new_rig);

    group_user_add(grouplist_new_rig,grouplist_old_rig);
    if(1 == rig_add_group)//用户组用户增加
    {
        if("1" == rpt_flg)
        {
            for(unsigned int i=0;i<grouplist_rig_add.size();i++)
            {
                audit = get_audit_user(grouplist_rig_add[i].groupusers);
								
                snprintf(user_char, sizeof(user_char), "用户组%s增加用户%s增加成功.",grouplist_rig_add[i].groupname.c_str(),audit.c_str());
                user_info.assign(user_char);
							
                log_content = userRightAudit_build_log_info(pMe, 504, user_info);
                userRightAudit_rpt_evt_to_server(log_content);
            }
        }

        snprintf(buf_log, sizeof(buf_log), "sysgrp, useradd:tip-info len:%d", tip_info.length());
        userRightAudit_log_run_info(buf_log);

        if("1" == tip_flg && 0 != tip_info.length())
        {
            userRightAudit_show_dlg(tip_info.c_str());
        }
					
        grouplist_rig_add.clear();
    }
    
    group_user_del(grouplist_old_rig,grouplist_new_rig);
    if(1 == rig_del_group)//用户组用户减少
    {
        if("1" == rpt_flg)
        {
            for(unsigned int i=0;i<grouplist_rig_del.size();i++)
            {
                audit = get_audit_user(grouplist_rig_del[i].groupusers);
							
                snprintf(user_char, sizeof(user_char), "用户组%s减少用户%s减少成功.",grouplist_rig_del[i].groupname.c_str(),audit.c_str());
                user_info.assign(user_char);
								
                log_content = userRightAudit_build_log_info(pMe, 504, user_info);
                userRightAudit_rpt_evt_to_server(log_content);
            }
        }

        snprintf(buf_log, sizeof(buf_log), "sysgrp, userdel:tip-info len:%d", tip_info.length());
        userRightAudit_log_run_info(buf_log);

        if("1" == tip_flg && 0 != tip_info.length())
        {
            userRightAudit_show_dlg(tip_info.c_str());
        }
					
        grouplist_rig_del.clear();
    }

    return 0;
}

static void userRightAudit_rpt_evt_to_server(string logContent)
{
	tag_Policylog * plog = NULL;
	int ret = 0;
	char buf_run_info[128] = {0};

	/*审计信息上报服务器*/
	plog = (tag_Policylog *)malloc(sizeof(tag_Policylog) + logContent.length() + 1);
	if(NULL == plog)
	{
		userRightAudit_log_run_info("rpt to server:malloc err.");
		return ;
	}

	memset(plog, 0, sizeof(tag_Policylog) + logContent.length() + 1);
	plog->type = AGENT_RPTAUDITLOG;		
	plog->what = AUDITLOG_REQUEST;
	strncpy(plog->log, logContent.c_str(), logContent.length());

	ret = report_policy_log(plog, 0);
	snprintf(buf_run_info, sizeof(buf_run_info), "rpt to server ret:%d", ret);
	userRightAudit_log_run_info(buf_run_info);

	free(plog);
}

static string  userRightAudit_build_log_info(CUserRightAudit *pMe, int kind, string evt_info)
{
    std::string audit_time;
    char str_audit_time[256]= {0};
	YCommonTool::get_local_time(str_audit_time);
    audit_time.assign(str_audit_time);

    char ch_action[8] = { '\0' };
    sprintf(ch_action, "%d", Abnormal_Behavior);
    char ch_risk[8] = { '\0' };
    sprintf(ch_risk, "%d", Event_Caution);

    if(NULL == pMe)
    {
        return "";
    }

    std::string SysUserName;
    get_desk_user(SysUserName);
    if("" == SysUserName)
    {
        SysUserName.assign("root");
    }

    for (unsigned int i = 0; i<evt_info.length(); i++)
    {
        if (evt_info[i] == '\n')
        {
            evt_info.erase(i, 1);
            i--;
        }
    }

    char ContextChar[2048]= {0};

    sprintf(ContextChar, "time=%s<>kind=%d<>policyid=%d<>policyname=%s<>context=%s<>KeyUserName=%s<>classaction=%s<>riskrank=%s", audit_time.c_str(), kind, pMe->get_id(), pMe->get_name().c_str(), evt_info.c_str(), SysUserName.c_str(), ch_action, ch_risk);

    std::string audit_info;
    audit_info.assign(ContextChar);

	userRightAudit_log_run_info(ContextChar);

	userRightAudit_log_run_info("build report info end.");

    return audit_info;
}

