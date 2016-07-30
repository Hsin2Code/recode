
/**
 * soft_down_ctl.h
 *
 *  Created on: 2015-02-02
 *  Author: liu
 *
 *
 *  该文件是普通文件分发策略类对应的头文件；
 *
 */

#ifndef _VRV_SOFT_DOWN_CTRL_H
#define _VRV_SOFT_DOWN_CTRL_H

#include "../policysExport.h"

/**
 *用于外部调用的函数声明。
 */
extern bool soft_down_ctl_init(void);
extern bool soft_down_ctl_worker(CPolicy *pPolicy, void *pParam);
extern void soft_down_ctl_uninit(void);

/**
 *宏定义
 */
#define LEN_FILE_NAME 256
#define LEN_PARAM 256
#define LEN_TIP_MSG 256
#define LEN_STR_INSTALL_CHK_ITEM 256
#define LEN_STR_UP_FILE_ATTR 256

/**
 *枚举,结构类型定义
 */

enum option
{
    WRONG,
    RIGHT
};

enum crc_stat_e
{
   CRC_NOT_CHANGE = 0,
   CRC_CHANGED = 1
};

struct dl_file_info_st
{
    char full_name[LEN_FILE_NAME + 1];
    int stat_ok; 
};

struct policy_st
{
	option runhidden:1,		//是否后台运行
		issystem:1,		//是否以系统权限运行
		run:1,		//是否分发完成后运行
		prompt:1,		//是否运行前提示
		deletesource:1,		//是否运行后删除源文件
		repeatdo:1,		//是否重复执行
		autosync:1,		//文件变化自动同步
		filecrc:1;		//数据包CRC校验

	int installoktime;		//安装结果检测时间
	int redownintervaltime;		//重新下载时间
    int dl_file_type;//下载的文件类型

	char filename[LEN_FILE_NAME + 1];		//文件名
	char targetpath[LEN_FILE_NAME + 1];		//客户端文件接收路径
	char cmdargv[LEN_PARAM + 1];		//命令行参数
	char runmsg[LEN_TIP_MSG + 1];		//安装提示信息
	char installokfileversion[LEN_STR_INSTALL_CHK_ITEM + 1];		//安装检测：文件版本
	//char *installokreg;		//安装检测:注册表
	char installokfile[LEN_STR_INSTALL_CHK_ITEM + 1];		//安装检测：文件名称
	char installokprocess[LEN_STR_INSTALL_CHK_ITEM + 1];		//安装检测：进程
	char lastupfileattr[LEN_STR_UP_FILE_ATTR + 1];
};

/**
 *普通文件分发类定义
 */
class CSoftDownCtl: public CPolicy{
public:
	CSoftDownCtl();
	virtual ~CSoftDownCtl();

public:
	virtual bool import_xml(const char*);
	virtual void copy_to(CPolicy * pDest);

public:
    struct policy_st  m_policy;
    struct dl_file_info_st dl_file_info;
    int   flg_dl_file_success;
    int   flg_dl_src_file_exist;/*标记下载的源文件是否存在*/
    int   retry_dl_time_count;
    int   flg_delete_dir;
    unsigned int m_pwd;   
    
};
#endif// _VRV_SOFT_DOWN_CTRL_H


