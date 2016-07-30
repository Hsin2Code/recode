
/**
 * file_op_ctl.h
 *
 *  Created on: 2014-12-23
 *      Author: yanchongjun
 *
 *
 *   该文件是文件操作控制(打印控制和文件共享)策略类对应的头文件；
 */

#ifndef _VRV_POLICY_FILE_OP_CTL_H
#define _VRV_POLICY_FILE_OP_CTL_H

#include "../policysExport.h"

/**
 *用于外部调用的函数声明。
 */
extern bool file_op_ctl_init(void);
extern bool file_op_ctl_worker(CPolicy *pPolicy, void *pParam);
extern void file_op_ctl_uninit(void);

/**
 *宏定义
 */

/*文件名宏定义*/
#define PRINTER_CONF_FILE ("/etc/cups/printers.conf")

/*审计数据字段字符串长度*/
#define AUDIT_DAT_STR_LEN (50)
/*审计缓冲区中最大打印任务数目*/
#define PRINT_AUDIT_NUM_MAX_JOBS (10)
/*审计缓冲的最大打印机数目*/
#define PRINT_AUDIT_NUM_MAX_PRINTER (10)
/*打印机名称的最大长度*/
#define PRINTER_NAME_LEN 100
/*ip地址长度*/
#define LEN_IP_ADDR 15
/*网卡名称长度*/
#define LEN_IF_NAME 64 
/*本机最大网卡数目*/
#define NUM_MAX_INTERFACE 5

/*文件长度*/
#define LEN_FILE_NAME 256 

/*macro presenting printer state*/
#define STATE_PRINTER_IDLE ("3")
#define STATE_PRINTER_STOPPED ("5")

/*macro for returned value */
#define RET_ERR_OOM (2)
#define RET_ERR (1)
#define RET_SUCCESS (0)

/**
 *结构体定义
 */

/*记录最终打印审计信的结构体定义*/
typedef struct info_print
{
	char filename[LEN_FILE_NAME];/*打印的文件名*/
    char flg_print_ok[2];/*打印成功取"1";打印失败取"0"*/
    int flg_print_cancelled_by_usr;/*打印被用户取消时设置为1.*/
    char copies[AUDIT_DAT_STR_LEN];
    char pages[AUDIT_DAT_STR_LEN];
    char filesize[AUDIT_DAT_STR_LEN];
    char usr[AUDIT_DAT_STR_LEN];/*打印文件的用户.*/
	char print_time[AUDIT_DAT_STR_LEN];/*打印时间*/
	char print_name[PRINTER_NAME_LEN];/*打印机名称*/
}info_print;

/*生成打印审计数据时用到的中间结构体*/
struct print_audit_dat_t
{
	int id;
	char title[AUDIT_DAT_STR_LEN + 1];/*打印的文件名*/
	int flg_used;
	int flg_audit;/*审计标志,只有此标志为1时才上报.*/
	char usr[AUDIT_DAT_STR_LEN + 1];
	char time[AUDIT_DAT_STR_LEN + 1];
	char printer[AUDIT_DAT_STR_LEN + 1];
	char page_range[AUDIT_DAT_STR_LEN + 1];
	char num_copies[AUDIT_DAT_STR_LEN + 1];
	char size[AUDIT_DAT_STR_LEN + 1];
	int flg_print_ok;
	int flg_print_cancelled_by_policy;/*如果打印被策略禁止，本字段置1.*/
};

/*记录打印机信息的结构体*/
struct st_printer_info
{
    char name[PRINTER_NAME_LEN + 1];
    char ip[LEN_IP_ADDR + 1];
    char local_flg;/*如果是本地打印机，则本字段置1.*/
};

/*网卡具体信息结构体*/
struct st_if_info_item 
{
	char name[LEN_IF_NAME + 1];
	char ip[LEN_IP_ADDR + 1];
};

/*网卡信息结构体*/
struct st_if_info
{
	unsigned int num_if;/*网卡个数*/
	struct st_if_info_item *if_item;/*网卡信息*/
};

typedef struct iprange
{
    char ip_begin[LEN_IP_ADDR + 1];
    char ip_end[LEN_IP_ADDR + 1];
}ip_range;

typedef std::vector <ip_range> range_vector;

/**
 *文件操作控制类定义
 */
class CFileOpCtl: public CPolicy{
public:
	CFileOpCtl();
	virtual ~CFileOpCtl();

public:
	virtual bool import_xml(const char*);
	virtual void copy_to(CPolicy * pDest);

	int Get_type(std::string src, char delim, std::vector<std::string> &mylist);
	void Audit_Info_Deal(std::string logContent);
	std::string Info_ReportToServer(int flag, int kind, std::string str, std::string filename);
public:
	char   AllowedPrinterServerIP[128];
	std::string g_DisablePrintFile;
	std::string g_RefusePrintExtName;
	std::string g_AllowPrintFile;
	std::string g_AllowPrintExtName;
	std::string g_AuditPrintFile;
	std::string g_BackupPrintFile;
	std::string g_UpRegionService;
	std::string g_WriteLocalFile;
	std::string DisabledCopyFileFromUDisk;
	std::string DisableNetFile;
	std::string RefuseNetFileExtName;
	std::string AuditNetFileExtName;
	std::string AuditNetFile;
	std::string CheckKeyWorkInFile;
	std::string FindKeyWorkHowToDeal;
	std::string KeyWorkInFileString;

	std::vector<std::string> refuse_file_type;/*禁止打印的文件类型*/
	std::vector<std::string> allow_file_type;/*允许打印的文件类型*/
	std::vector<std::string> refuse_share_type;
	std::vector<std::string> audit_share_type;
	range_vector printer_ip_range;/*允许使用的打印机ip范围*/

	//打印信息审计
	info_print print_data;
	int printer_allow_flg;/*标记本次打印任务操作中，打印机是否合法*/
};
#endif //_VRV_POLICY_FILE_OP_CTL_H
