
/**
 * file_op_ctl.cpp
 *
 *  Created on: 2014-12-23
 *  Author: yanchongjun
 *
 *
 *  该文件包含了打印控制和文件共享策略所需的所有函数；
 */
#include <unistd.h>
#include <stdio.h>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <iostream>
#include "file_op_ctl.h"
#include "../../../include/Markup.h"
#include "../../../include/MCInterface.h"
#include "../../VCFCmdDefine.h"
#include "../../vrvprotocol/VRVProtocol.hxx"
#include "cups_h/cups.h"
#include "../../common/Commonfunc.h"
#include "../../common/TIniFile.h"

using namespace std;

/*本地宏定义*/
#define FILE_OPERATOR_CONTROL_PATH "/var/log/file_operator_audit"
#define PRINT_RET_OK (1)
#define PRINT_RET_FAIL (0)

/*dbg 宏定义*/
#define PRINT_AUDIT_DBG 

/*本地全局变量*/
static struct print_audit_dat_t *g_print_audit_dat_buf;/*打印审计数据缓冲区*/
static struct st_printer_info *g_pPrinter_info;/*存储打印机信息的数据缓冲区*/
static struct st_if_info *g_ifcfg_info;/*存储本地的网卡配置信息*/

/*本地使用的函数声明*/
static int printAudit_init(void);
static int printAudit_main(CPolicy *pPolicy, void *pParam);
static void printAudit_uninit(void);
static void printAudit_processJob(int num_jobs, cups_job_t *ite_jobs, 
				 struct print_audit_dat_t *audit_dat,
				 std::string disablePrintFlg, std::vector<std::string> &refuse_file, 
				 std::string allowPrintFlg, std::vector<std::string> &allow_file,
                 int printer_allow_flg);
static int printAudit_getPrinterInfo(struct st_printer_info *printerInfo, int cap);
static int printAudit_getPrinter_allowFlg(char *dst_printer, struct st_printer_info *pPrinter_info, struct st_if_info *plocalIfInfo, range_vector &printer_ip_range);
static int printAudit_writeAuditDat(cups_job_t *job, struct print_audit_dat_t *audit_dat, char flgJobCancel);
static int printAudit_updateAuditDat(cups_job_t *job, struct print_audit_dat_t *audit_dat);
static int printAudit_matchJob(char *job_title, std::vector<std::string> &file);
static int printAudit_getAuditItem(struct print_audit_dat_t *auditDat, info_print *printDat);
static void printAudit_getJobPageInfo(int jobId, char *pageRange, char *copies);
static int printAudit_extract_copies_number(const char *file_name, short *pNum_copies);
static int printAudit_extract_page_number(const char *file_name);
static void printAudit_log_run_info(const char *log_content);
static int printAudit_getIfInfo(struct st_if_info **pIf_info);
static void printAudit_show_dlg(const char *info);

/*利于本地调试的函数*/
static int Deal_IPRange(char *org_range,range_vector &ip_ran_list);
static int IP_Range_Judged(char *ip, char *start_ip, char *end_ip);

/*外部函数*/
extern bool  report_policy_log(tag_Policylog * plog,bool bNow);
extern ILocalogInterface * g_GetlogInterface(void) ;

/*共享部分变量及函数*/
static unsigned int g_crc;
static int g_timer_count;
static int g_tftp_pid = 0;
static std::vector<std::string> g_share_path;            //共享路径列表
static std::vector<std::string> g_share_file_list;       //共享文件列表
static std::vector<std::string> g_share_path_mode;       //共享路径对应的模式 samba,tftp,nfs
static std::vector<std::string> g_share_file_list_mode;  //共享文件对应模式  samba,tftp,nfs
static std::vector<std::string> refuse_share_file_list;  //禁止共享文件列表
static std::vector<std::string> audit_share_file_list;   //审计共享文件列表
static void share_previous_recovery(void);
static int share_main(CPolicy *pPolicy, void *pParam);


/**
 * 类的构造方法
 */
CFileOpCtl::CFileOpCtl()
{
    enPolicytype type = FILE_OP_CTRL ;
	set_type(type);
	printAudit_log_run_info("file_op_ctl constructor.");
}

/**
 * 类的析构函数
 */
CFileOpCtl::~CFileOpCtl()
{
	printAudit_log_run_info("file_op_ctl destroy.");
}

/**
 *父类虚函数实现：copy函数
 */
void CFileOpCtl::copy_to(CPolicy * pDest)
{
	printAudit_log_run_info("copy_to_start.");

	/*string 及字符串数组成员*/
	memset(((CFileOpCtl*)pDest)->AllowedPrinterServerIP, 0, sizeof(AllowedPrinterServerIP));
    strcpy(((CFileOpCtl*)pDest)->AllowedPrinterServerIP, AllowedPrinterServerIP);

	(((CFileOpCtl*)pDest)->g_DisablePrintFile).assign(g_DisablePrintFile.c_str());

	(((CFileOpCtl*)pDest)->g_RefusePrintExtName).assign(g_RefusePrintExtName.c_str());

	(((CFileOpCtl*)pDest)->g_AllowPrintFile).assign(g_AllowPrintFile.c_str());

	(((CFileOpCtl*)pDest)->g_AllowPrintExtName).assign(g_AllowPrintExtName.c_str());

	(((CFileOpCtl*)pDest)->g_AuditPrintFile).assign(g_AuditPrintFile.c_str());

	(((CFileOpCtl*)pDest)->g_UpRegionService).assign(g_UpRegionService.c_str());

	(((CFileOpCtl*)pDest)->g_WriteLocalFile).assign(g_WriteLocalFile.c_str());
	(((CFileOpCtl*)pDest)->DisableNetFile).assign(DisableNetFile.c_str());
	(((CFileOpCtl*)pDest)->AuditNetFile).assign(AuditNetFile.c_str());

	/*vector 成员*/
	((CFileOpCtl*)pDest)->refuse_file_type = refuse_file_type;
	((CFileOpCtl*)pDest)->allow_file_type = allow_file_type;
	((CFileOpCtl*)pDest)->refuse_share_type = refuse_share_type;
	((CFileOpCtl*)pDest)->audit_share_type = audit_share_type;
	((CFileOpCtl*)pDest)->printer_ip_range = printer_ip_range;

   	CPolicy::copy_to(pDest);
	printAudit_log_run_info("copy_to end.");
}

/**
 *父类虚函数实现：策略导入函数
 */
bool CFileOpCtl::import_xml(const char *pxml)
{
    char buf_policy[512] = {0};

    printAudit_log_run_info("import_xml start.");
    if(pxml == NULL)
    {
        printAudit_log_run_info("import_xml:pxml is null.");
        return false ;
    }

    CMarkup  xml ;
    if(!xml.SetDoc(pxml))
    {
        printAudit_log_run_info("import_xml:SetDoc failed.");
        return false ;
    }

    if(xml.FindElem("vrvscript"))
    {
        xml.IntoElem();
        std::string tmp_str;

        while(xml.FindElem("item"))
        {
            memset(AllowedPrinterServerIP, 0, sizeof(AllowedPrinterServerIP));
            tmp_str = xml.GetAttrib("AllowedPrinterServerIP");
            if(0 != tmp_str.length())
            {
                strncpy(AllowedPrinterServerIP, tmp_str.c_str(), sizeof(AllowedPrinterServerIP) - 1);
                Deal_IPRange(AllowedPrinterServerIP, printer_ip_range);
                snprintf(buf_policy, sizeof(buf_policy), "Allowed PrinterIP:%s", AllowedPrinterServerIP);
                printAudit_log_run_info(buf_policy);
            }

            tmp_str = xml.GetAttrib("DisablePrintFile");
            if(0 != tmp_str.length())
            {
                g_DisablePrintFile.assign(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "disable print:%s", g_DisablePrintFile.c_str());
                printAudit_log_run_info(buf_policy);
            }

            tmp_str = xml.GetAttrib("RefusePrintExtName");
            if(0 != tmp_str.length())
            {
                g_RefusePrintExtName.assign(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "RefusePrintExtName:%s", g_RefusePrintExtName.c_str());
                printAudit_log_run_info(buf_policy);

                if(0 == strcmp(g_DisablePrintFile.c_str(),"1"))
                {
                    Get_type(g_RefusePrintExtName,'.',refuse_file_type);
                }
            }

            tmp_str = xml.GetAttrib("AllowPrintFile");
            if(0 != tmp_str.length())
            {
                g_AllowPrintFile.assign(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "allow print:%s", g_AllowPrintFile.c_str());
                printAudit_log_run_info(buf_policy);
            }

            tmp_str = xml.GetAttrib("AllowPrintExtName");
            if(0 != tmp_str.length())
            {
                g_AllowPrintExtName.assign(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "allowed file ext:%s", g_AllowPrintExtName.c_str());
                printAudit_log_run_info(buf_policy);

                if(0 == strcmp(g_AllowPrintFile.c_str(),"1"))
                {
                    Get_type(g_AllowPrintExtName, '.', allow_file_type);
                }
            }

            tmp_str = xml.GetAttrib("AuditPrintFile");
            if(0 != tmp_str.length())
            {
                g_AuditPrintFile.assign(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "audit print file:%s", g_AuditPrintFile.c_str());
                printAudit_log_run_info(buf_policy);
            }

            tmp_str = xml.GetAttrib("BackupPrintFile");
            if(0 != tmp_str.length())
            {
                g_BackupPrintFile.assign(tmp_str.c_str());
            }

            tmp_str = xml.GetAttrib("UpRegionService");
            if(0 != tmp_str.length())
            {
                g_UpRegionService.assign(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "report to server:%s", g_UpRegionService.c_str());
                printAudit_log_run_info(buf_policy);
            }

            tmp_str = xml.GetAttrib("WriteLocalFile");
            if(0 != tmp_str.length())
            {
                g_WriteLocalFile.assign(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "write local file:%s", g_WriteLocalFile.c_str());
                printAudit_log_run_info(buf_policy);
            }

            tmp_str = xml.GetAttrib("DisableNetFile");
            if(0 != tmp_str.length())
            {
                DisableNetFile.assign(tmp_str.c_str());
            }

            tmp_str = xml.GetAttrib("RefuseNetFileExtName");
            if(0 != tmp_str.length())
            {
                RefuseNetFileExtName.assign(tmp_str.c_str());
                if("0" != DisableNetFile)
                {
                    Get_type(RefuseNetFileExtName,'.',refuse_share_type);
                }
            }
            else
            {
                refuse_share_type.clear();
            }

            tmp_str = xml.GetAttrib("AuditNetFile");
            if(0 != tmp_str.length())
            {
                AuditNetFile.assign(tmp_str.c_str());
            }

            tmp_str = xml.GetAttrib("AuditNetFileExtName");
            if(0 != tmp_str.length())
            {
                AuditNetFileExtName.assign(tmp_str.c_str());
                if("0" != AuditNetFile)
                {
                    Get_type(AuditNetFileExtName,'.',audit_share_type);
                }
            }
            else
            {
                audit_share_type.clear();
            }

            tmp_str = xml.GetAttrib("CheckKeyWorkInFile");
            if(0 != tmp_str.length())
            {
                CheckKeyWorkInFile.assign(tmp_str.c_str());
            }

            tmp_str = xml.GetAttrib("FindKeyWorkHowToDeal");
            if(0 != tmp_str.length())
            {
                FindKeyWorkHowToDeal.assign(tmp_str.c_str());
            }

            tmp_str = xml.GetAttrib("KeyWorkInFileString");
            if(0 != tmp_str.length())
            {
                KeyWorkInFileString.assign(tmp_str.c_str());
            }
        }
        xml.OutOfElem();
    }

    printAudit_log_run_info("import_xml end.");
    return CPolicy::import_xmlobj(xml);
}

/**
 * 函数名:Get_type()
 * 说明:CFileOpCtl类生成vector的助手函数
 */
int CFileOpCtl:: Get_type(std::string src, char delim, std::vector<std::string> &mylist)
{
    std::string temp;
    std::stringstream ss(src);
    std::string sub_str;
    mylist.clear();
	
    while(0 < getline(ss,sub_str,delim))
    {
        if(sub_str !="")
        {
            temp=delim;
            temp = temp+sub_str;
            mylist.push_back(temp);
        }
    }
    return 0;
}

/**
 * 函数名:Audit_Info_Deal()
 * 说明:CFileOpCtl类的审计信息处理函数,进行信息上报，或者写入本地文件；
 */
void CFileOpCtl::Audit_Info_Deal(std::string logContent)
{
    int fd = 0;
    tag_Policylog * plog = NULL;
    int ret = 0;
    char buf_run_info[128] = {0};

	/*审计信息写入文件*/
    if("1" == g_WriteLocalFile)
    {
        if(-1 == access(FILE_OPERATOR_CONTROL_PATH,F_OK)) //file doesn't exist
        {
            if(-1 != (fd = open(FILE_OPERATOR_CONTROL_PATH,O_WRONLY|O_CREAT|O_APPEND,0664)))
            {
                write(fd,logContent.c_str(),logContent.length());
                close(fd);
            }
        }
        else
        {
            if(-1 != (fd = open(FILE_OPERATOR_CONTROL_PATH,O_WRONLY|O_APPEND,0664)))
            {
                write(fd,logContent.c_str(),logContent.length());
                close(fd);
            }
        }
    }

	/*审计信息上报服务器*/
    if("1" == g_UpRegionService)
	{
		plog = (tag_Policylog *)malloc(sizeof(tag_Policylog) + logContent.length() + 1);
		if(NULL == plog)
		{
			printAudit_log_run_info("rpt to server:malloc err.");
			return ;
		}

		memset(plog, 0, sizeof(tag_Policylog) + logContent.length() + 1);
		plog->type = AGENT_RPTAUDITLOG;		
		plog->what = AUDITLOG_REQUEST;
		strncpy(plog->log, logContent.c_str(), logContent.length());

		ret = report_policy_log(plog, 0);
		snprintf(buf_run_info, sizeof(buf_run_info), "rpt to server ret:%d", ret);
		printAudit_log_run_info(buf_run_info);

		free(plog);
	}
}

/**
 * 函数名:CFileOpCtl()
 * 说明:CFileOpCtl类生成,并返回上报信息的函数
 */
std::string CFileOpCtl:: Info_ReportToServer(int flag, int kind, std::string str, std::string filename)
{
    std::string print_time;
    char str_printtime[256]= {0};
	YCommonTool::get_local_time(str_printtime);
    print_time.assign(str_printtime);

    char ch_action[8] = {0};
    std::string str_act_ilegal;
    sprintf(ch_action, "%d", Illegal_Behavior);
    str_act_ilegal.assign(ch_action);
    
    char ch_risk[8]= {0};
    std::string str_rk_alarm;
    sprintf(ch_risk, "%d", Event_Alarm);
    str_rk_alarm.assign(ch_risk);
	
    std::string str_act_abnormal;
    sprintf(ch_action, "%d", Abnormal_Behavior);
    str_act_abnormal.assign(ch_action);

    std::string str_act_general;
    sprintf(ch_action, "%d", General_Behavior);
    str_act_general.assign(ch_action);

    std::string str_rk_inform;
    sprintf(ch_risk, "%d", Event_Inform);
    str_rk_inform.assign(ch_risk);

    std::string SysUserName;
    get_desk_user(SysUserName);
    if("" == SysUserName)
    {
        SysUserName.assign("root");
    }

    //获取打印信息
    char ContextChar[2048]= {0};

    switch(kind)
    {
    	case 600: //print output
		{
        	if(1 == flag)//打印成功
        	{
           		sprintf(ContextChar,"time=%s<>kind=600<>policyid=%d<>policyname=%s\
<>classaction=%s<>riskrank=%s<>context=打印文件:%s,打印页数:%s,打印份数:%s,打印机名:%s,用户:%s,打印成功.<>filename=%s<>KeyUserName=%s",
            	print_time.c_str(),get_id(),get_name().c_str(),
str_act_general.c_str(),str_rk_inform.c_str(),
print_data.filename,print_data.pages,print_data.copies,print_data.print_name,print_data.usr,print_data.filename,SysUserName.c_str());
        	}
        	else if(0 == flag)//打印失败
        	{
            	if(print_data.flg_print_cancelled_by_usr)/*print job is cancelled by user*/
            	{
                	sprintf(ContextChar,"time=%s<>kind=600<>policyid=%d<>policyname=%s\
<>classaction=%s<>riskrank=%s<>context=打印文件:%s,打印页数:%s,打印份数:%s,打印机名:%s,用户:%s,打印失败,被用户取消.<>filename=%s<>KeyUserName=%s",
            		print_time.c_str(),get_id(),get_name().c_str(),
str_act_abnormal.c_str(),str_rk_inform.c_str(),print_data.filename,print_data.pages,print_data.copies,print_data.print_name,print_data.usr,print_data.filename,SysUserName.c_str());
            	}
            	else/*print job is cancelled by policy*/ 
            	{
                	sprintf(ContextChar,"time=%s<>kind=600<>policyid=%d<>policyname=%s\
<>classaction=%s<>riskrank=%s<>context=打印文件:%s,打印页数:%s,打印份数:%s,打印机名:%s,用户:%s,打印失败,违反了打印策略.<>filename=%s<>KeyUserName=%s",
            print_time.c_str(),get_id(),get_name().c_str(),
str_act_ilegal.c_str(),str_rk_alarm.c_str(),print_data.filename,print_data.pages,print_data.copies,print_data.print_name,print_data.usr,print_data.filename,SysUserName.c_str());
            	}
        	}
       		break;
		}
    	case 602: //share output
    	{
        	if(0 == flag) //audit share
        	{
            	sprintf(ContextChar,"time=%s<>kind=%d<>policyid=%d<>policyname=%s<>context=%s<>filename=%s<>KeyUserName=%s<>classaction=%d<>riskrank=%d",
                    print_time.c_str(),kind,get_id(),get_name().c_str(),str.c_str(),filename.c_str(),SysUserName.c_str(),General_Behavior,Event_Inform);
        	}
        	else //forbit share
        	{
            	sprintf(ContextChar,"time=%s<>kind=%d<>policyid=%d<>policyname=%s<>context=%s<>filename=%s<>KeyUserName=%s<>classaction=%d<>riskrank=%d",
                    print_time.c_str(),kind,get_id(),get_name().c_str(),str.c_str(),filename.c_str(),SysUserName.c_str(),Illegal_Behavior,Event_Alarm);

        	}
    		break;
    	}
    	case 601: //E-mail output
        	break;
		default:
			break;
    }

    std::string audit_info;
    audit_info.assign(ContextChar);

	printAudit_log_run_info(ContextChar);

	printAudit_log_run_info("build report info end.");

    return audit_info;
}

/**
 * 函数名:file_op_ctl_init()
 * 说明:供外部调用的文件操作控制策略的init函数
 *  	成功返回true，失败返回false；
 */
bool file_op_ctl_init(void)
{
    int ret = 0;

    ret = printAudit_init();

    if(RET_SUCCESS != ret)	
    {
        return false;	
    }
	
    return true;
}

/**
 * 函数名:file_op_ctl_worker()
 * 说明:供外部调用的文件操作控制策略的worker函数,完成打印监控和文件共享控制;
 *  	成功返回true，失败返回false；
 */
bool file_op_ctl_worker(CPolicy *pPolicy, void *pParam)
{
    if(FILE_OP_CTRL != pPolicy->get_type())
    {
        return false;
    }
    (void)printAudit_main(pPolicy, pParam);

    if(0 == g_timer_count)
    {
        if(pPolicy->get_crc() != g_crc)
        {
            if(0 != refuse_share_file_list.size())
            {
                share_previous_recovery();
            }
            g_crc = pPolicy->get_crc();
        }
        share_main(pPolicy, pParam);
    }
    if(g_timer_count < 20)
    {
        g_timer_count++;
    }
    else
    {
        g_timer_count = 0;
    }
    return true;
}

/**
 * 函数名:file_op_ctl_uninit()
 * 说明:供外部调用的文件操作控制策略的uninit函数,完成策略停止时的资源清理;
 */
void file_op_ctl_uninit()
{
    printAudit_uninit();
    if(g_tftp_pid != 0)
    {
        kill(g_tftp_pid,SIGINT);
    }
}

/**
 * 函数名:printAudit_init()
 * 说明:打印控制部分的初始化函数;
 *  	成功返回0，失败返回其他值；
 */
static int printAudit_init(void)
{
	char cmd[256] = {0};
        char restart[256] = {0};
	/*if cann't get infomation,replace the cupsd.conf*/
       /* char cups[60] = "/opt/edp_vrv/bin/cupsd.conf";
        snprintf(cmd, sizeof(cmd),"mv /opt/edp_vrv/bin/cupsd.conf /etc/cups/");
        snprintf(restart,sizeof(restart),"service cups restart");
        if(! access(cups,0))
        {
                system(cmd);
                system(restart);
        }
	*/
	snprintf(cmd,sizeof(cmd),"sed -i 's/JobPrivateAccess default/JobPrivateAccess yes/' /etc/cups/cupsd.conf");
	system(cmd);
	snprintf(cmd,sizeof(cmd),"sed -i 's/JobPrivateValues default/JobPrivateValues yes/' /etc/cups/cupsd.conf");
	system(cmd);
	snprintf(cmd,sizeof(cmd),"sed -i 's/SubscriptionPrivateAccess default/SubscriptionPrivateAccess yes/' /etc/cups/cupsd.conf");
	system(cmd);
	snprintf(cmd,sizeof(cmd),"sed -i 's/SubscriptionPrivateValues default/SubscriptionPrivateValues yes/' /etc/cups/cupsd.conf");
	system(cmd);
	snprintf(restart,sizeof(restart),"service cups restart");
	system(restart);
    g_print_audit_dat_buf = (struct print_audit_dat_t *)calloc(PRINT_AUDIT_NUM_MAX_JOBS, sizeof(struct print_audit_dat_t));
    if(NULL == g_print_audit_dat_buf)
    {
        printAudit_log_run_info("print_ctl_init: calloc error.\n");
        return RET_ERR_OOM;
    }

    g_pPrinter_info = (struct st_printer_info *)calloc(PRINT_AUDIT_NUM_MAX_PRINTER, sizeof(struct st_printer_info));
    if(NULL == g_pPrinter_info)
    {
        printAudit_log_run_info("print_ctl_init: calloc error.\n");
        printAudit_uninit();
        return RET_ERR_OOM;
    }
 
     g_ifcfg_info = (struct st_if_info *)calloc(1, sizeof(struct st_if_info));
    if(NULL == g_ifcfg_info)
    {
        printAudit_log_run_info("print_ctl_init: calloc error.\n");
        printAudit_uninit();
        return RET_ERR_OOM;
    }

    g_ifcfg_info->if_item = (struct st_if_info_item *)calloc(NUM_MAX_INTERFACE, sizeof(struct st_if_info_item)); 
    if(NULL == g_ifcfg_info->if_item)
    {
        printAudit_log_run_info("print_ctl_init: calloc error.\n");
        printAudit_uninit();
        return RET_ERR_OOM;
    }

    (void)printAudit_getIfInfo(&g_ifcfg_info);

    (void)printAudit_getPrinterInfo(g_pPrinter_info, PRINT_AUDIT_NUM_MAX_PRINTER);

    printAudit_log_run_info("print audit init end.");

    return RET_SUCCESS;
}

/**
 * 函数名:printAudit_main()
 * 说明:打印控制部分的功能实现函数,完成打印审计/控制功能;
 *  	成功返回0，失败返回其他值；
 *
 * pPolicy:输入参数，可以转换为文件操作控制类对象的指针;
 * pParam:输入参数;
 */
static int printAudit_main(CPolicy *pPolicy, void *pParam)
{
    CFileOpCtl *pPrintCtl = (CFileOpCtl *)pPolicy;
    cups_dest_t *dests = NULL;
    cups_dest_t *dest = NULL;
    int i = 0;
    int num_dests = 0;
    char dst_printer[50] = {0};
    const char *pStateValue  = NULL; 
    cups_job_t  *ite_jobs = NULL;
    int num_jobs = 0;
    std::string info_rpt_server;

    if(NULL == pPrintCtl)
    {
        printAudit_log_run_info("printAudit_main:no policy, take no action.");
        return -1;
    }

    /*get printer info*/	
    num_dests = cupsGetDests(&dests);
    for(i=num_dests, dest=dests; i>0; i--, dest ++)
    {
        pStateValue  = cupsGetOption("printer-state", dest->num_options, dest->options);

        memset(dst_printer, 0, sizeof(dst_printer));
        strncpy(dst_printer, dest->name, sizeof(dst_printer)-1); 
        //printf("------------------here!\n");
        /*
         *If the current printer has no name,go to the next printer.
         */
        if(strlen(dst_printer) <= 0)
        {
            continue;
        }

        /*If the current printer is stopped, go to the next printer.*/
        if(0 == strcmp(pStateValue, STATE_PRINTER_STOPPED))
        {
            continue;
        }
        //	 printf("------------------here：%s\n",dst_printer);
        pPrintCtl->printer_allow_flg = printAudit_getPrinter_allowFlg(dst_printer, g_pPrinter_info, g_ifcfg_info, pPrintCtl->printer_ip_range);
	
        num_jobs = cupsGetJobs(&ite_jobs, dst_printer, 0, CUPS_WHICHJOBS_ALL);	
        if(NULL == ite_jobs)
        {
            char log[256] ={0};
            snprintf(log,sizeof(log),"dst_printer:%s\t ite_jobs is NULL",dst_printer);
            printAudit_log_run_info(log);
        }
        //	printf("------------------here：%s----%d\n",dst_printer,num_jobs);
        printAudit_processJob(num_jobs, ite_jobs, g_print_audit_dat_buf,
                pPrintCtl->g_DisablePrintFile, pPrintCtl->refuse_file_type, 
                    pPrintCtl->g_AllowPrintFile, pPrintCtl->allow_file_type,
                    pPrintCtl->printer_allow_flg
                    );

        /*If there is audit info, write to log file or report it to server. */
        memset(&(pPrintCtl->print_data), 0, sizeof(pPrintCtl->print_data));        
        if(printAudit_getAuditItem(g_print_audit_dat_buf, &(pPrintCtl->print_data)))
        {
            if(0 == strcmp("1", pPrintCtl->print_data.flg_print_ok)) 
            {
                if(0 == strcmp("1", pPrintCtl->g_AuditPrintFile.c_str()))
                {
                    info_rpt_server = pPrintCtl->Info_ReportToServer(PRINT_RET_OK , 600, "","");
                }
            }
            else
            {
                info_rpt_server = pPrintCtl->Info_ReportToServer(PRINT_RET_FAIL, 600, "","");
            }
    
            pPrintCtl->Audit_Info_Deal(info_rpt_server);
            info_rpt_server.clear();
        }
		
        cupsFreeJobs(num_jobs, ite_jobs);
    }//for each printer loop
		
    cupsFreeDests(num_dests, dests);

    return 0;
}

/**
 * 函数名:printAudit_processJob()
 * 说明:该函数对打印机的打印任务进行控制;对于不符合打印策略的打印任务，执行取消操作.
 *
 * num_jobs:输入参数，打印任务的数目；
 * ite_jobs:输入参数，打印任务的指针；
 * audit_dat:输入参数，打印审计数据缓冲区指针；
 * disablePrintFlg:输入参数，禁止打印标记；
 * refuse_file:输入参数，禁止打印文件后缀名vector；
 * allowPrintFlg:输入参数，允许打印标记；
 * allow_file:输入参数，允许打印文件后缀名vector；
 * printer_allow_flg:输入参数,打印机允许使用标记;
 */
static void printAudit_processJob(int num_jobs, cups_job_t *ite_jobs, 
				 struct print_audit_dat_t *audit_dat,
				 std::string disablePrintFlg, std::vector<std::string> &refuse_file, 
				 std::string allowPrintFlg, std::vector<std::string> &allow_file,
                 int printer_allow_flg)
{
    cups_job_t *jobs = ite_jobs;
    int i = 0;
    int ret = 0;
    char flg_job_cancel = 0;
    char slash_ch = '/';
    char *pjob_title_ex = NULL;
    char dlg_info_str[256] = {0};
    char dlg_info_str_p1[] = "禁止打印文件:";
#if defined (PRINT_AUDIT_DBG) 
    char buf_log[128] = {0};
#endif//PRINT_AUDIT_DBG
    if(NULL == jobs)
    {
        char log[256] = {0};
		snprintf(log,sizeof(log),"jobs is NULL :%s\n",cupsLastErrorString());
		printAudit_log_run_info(log);
	}
    if(num_jobs <= 0 || NULL  == jobs)	
    {
        return;
    }

    for(i = 0; i < num_jobs; i++)
    {
        jobs = ite_jobs + i;

        if( IPP_JOB_STOPPED != jobs->state &&
                IPP_JOB_CANCELED != jobs->state &&
                IPP_JOB_ABORTED != jobs->state &&
                IPP_JOB_COMPLETED != jobs->state 
          )
        {
            printf("---disableprint!\n");
            if(0 == strcmp("1", disablePrintFlg.c_str())) 
            {
                if(0 == refuse_file.size())
                {
                    ret = cupsCancelJob(jobs->dest, jobs->id);
#if defined (PRINT_AUDIT_DBG)
                    printf("---jobs:%s----%d\n",jobs->dest,jobs->id) ;
                    snprintf(buf_log, sizeof(buf_log), "cancel job-all %d-%s,ret:%d, state:%d", jobs->id, jobs->title, ret, jobs->state);
                    printAudit_log_run_info(buf_log);
#endif//PRINT_AUDIT_DBG
                    flg_job_cancel = 1;
                }
                else 
                {
                    if(printAudit_matchJob(jobs->title, refuse_file) || !printer_allow_flg)
                    {
                        ret = cupsCancelJob(jobs->dest, jobs->id);
#if defined (PRINT_AUDIT_DBG) 
                        snprintf(buf_log, sizeof(buf_log), "cancel job-match %d-%s,ret:%d, state:%d", jobs->id, jobs->title, ret, jobs->state);
                        printAudit_log_run_info(buf_log);
#endif//PRINT_AUDIT_DBG

                        flg_job_cancel = 1;
                    }
                }
            }
            else
            if(0 == strcmp("1", allowPrintFlg.c_str())) 
            { 
                if(0 != allow_file.size())
                {
                    if(!printAudit_matchJob(jobs->title, allow_file) || !printer_allow_flg)
                    {
                        ret = cupsCancelJob(jobs->dest, jobs->id);
#if defined (PRINT_AUDIT_DBG) 
                        snprintf(buf_log, sizeof(buf_log), "cancel job-allow %d-%s,ret:%d, state:%d", jobs->id, jobs->title, ret, jobs->state);
                        printAudit_log_run_info(buf_log);
#endif//PRINT_AUDIT_DBG

                        flg_job_cancel = 1;
                    }
                }
                else
                {
                    if(!printer_allow_flg)
                    {
                        ret = cupsCancelJob(jobs->dest, jobs->id);
#if defined (PRINT_AUDIT_DBG) 
                        snprintf(buf_log, sizeof(buf_log), "cancel job-allow-a %d-%s,ret:%d, state:%d", jobs->id, jobs->title, ret, jobs->state);
                        printAudit_log_run_info(buf_log);
#endif//PRINT_AUDIT_DBG

                        flg_job_cancel = 1;
                    }
                }
            }
            else
            {
                //..
            }

            /*如果打印任务被禁止，给以提示.*/
            if(flg_job_cancel)
            {
                memset(dlg_info_str, 0, sizeof(dlg_info_str));

                pjob_title_ex = strrchr(jobs->title, slash_ch); 
                if(NULL != pjob_title_ex)
                {
                    snprintf(dlg_info_str, sizeof(dlg_info_str), "%s %s", 
                            dlg_info_str_p1, pjob_title_ex + 1);
                }
                else
                {
                    snprintf(dlg_info_str, sizeof(dlg_info_str), "%s %s", 
                            dlg_info_str_p1, jobs->title);
                }

                printAudit_show_dlg(dlg_info_str);
            }

            if( IPP_JOB_HELD == jobs->state && !flg_job_cancel)
            {
                //ret = printAudit_releaseJob(jobs); 
#if defined (PRINT_AUDIT_DBG) 
                snprintf(buf_log, sizeof(buf_log), "Releasing job %d-%s,ret:%d", jobs->id, jobs->title, ret);
                printAudit_log_run_info(buf_log);
#endif//PRINT_AUDIT_DBG
            }

            (void)printAudit_writeAuditDat(jobs, audit_dat, flg_job_cancel);
            flg_job_cancel = 0;
		   
        }
        else if(IPP_JOB_CANCELED == jobs->state || 
                IPP_JOB_COMPLETED == jobs->state) 
        {
            printAudit_updateAuditDat(jobs, audit_dat);
        }
        else
        {
            //...
        }
    }//for loop
}

/**
 * 函数名:printAudit_uninit()
 * 说明:打印控制部分的资源释放函数,在策略停止时调用打;
 */
static void printAudit_uninit(void)
{
	if(NULL != g_print_audit_dat_buf)
	{
		printAudit_log_run_info("printAudit uninit freeing print_audit_dat_buf.");
		free(g_print_audit_dat_buf);
		g_print_audit_dat_buf = NULL;
	}

	if(NULL != g_pPrinter_info)
	{
		printAudit_log_run_info("printAudit uninit freeing printer_info.");
		free(g_pPrinter_info);
		g_pPrinter_info = NULL;
	}

	if(NULL != g_ifcfg_info)
	{
		if(NULL != g_ifcfg_info->if_item)
		{
			printAudit_log_run_info("printAudit uninit freeing ifcfg_info-item.");
			free(g_ifcfg_info->if_item);
		}

		printAudit_log_run_info("printAudit uninit freeing ifcfg_info.");
		free(g_ifcfg_info);
		g_ifcfg_info = NULL;
	}
	printAudit_log_run_info("printAudit uninit end.");
}

/**
 * 函数名:printAudit_getAuditItem()
 * 说明:该函数用于获取打印审计数据，并填充到参数printDat中;
 * 		成功返回1；否则返回0；
 *
 * audit_dat:打印审计数据缓冲区指针；
 * printDat:待填充并输出的打印审计数据；
 */
static int printAudit_getAuditItem(struct print_audit_dat_t *auditDat, info_print *printDat)
{
	int i = 0;
	struct print_audit_dat_t *pdat = auditDat; 
    int page_count = 0;
    char str_page_count[10] = {0};
    char job_file_name[256] = {0};
	char job_file_tmp_basedir[] = "/tmp/printertmp/";
    short num_copies = 1;
    int ret = 0;
	#if defined (PRINT_AUDIT_DBG) 
	char buf_log[128] = {0};
	#endif//PRINT_AUDIT_DBG
	
    memset(printDat, 0, sizeof(struct info_print));

	for(i=0; i<PRINT_AUDIT_NUM_MAX_JOBS; i++)
	{
		if(!pdat[i].flg_audit)	
		{
			continue;
		}

	    if(!pdat[i].flg_print_ok)
		{
            page_count = 0;   
            strcpy(pdat[i].num_copies, "0");
		    pdat[i].num_copies[1] = '\0';
		}
		else
		{		
			printAudit_getJobPageInfo(pdat[i].id, pdat[i].page_range, pdat[i].num_copies);

            snprintf(job_file_name, sizeof(job_file_name), "%s%s-%s-%d",job_file_tmp_basedir, 
                    pdat[i].printer, pdat[i].usr, pdat[i].id);

            /*
             * 通过读取第三方工具生成的中间文件来提取打印份数和页数；
             * 临时文件名称规则如下：
             * printername-user-jobid
             * 临时文件位于如下目录：
             * /tmp/printertmp/
             */
            ret = printAudit_extract_copies_number(job_file_name, &num_copies);
            
            if(0 == strcmp(pdat[i].num_copies, "1") && 0 == ret && 1 != num_copies)
            {
                snprintf(pdat[i].num_copies, sizeof(pdat[i].num_copies), "%d", num_copies);
	#if defined (PRINT_AUDIT_DBG) 
                snprintf(buf_log, sizeof(buf_log), "getAudItem:copies number is reset, now is:%d, %s\n",
						 num_copies, pdat[i].num_copies);
				printAudit_log_run_info(buf_log);
	#endif//PRINT_AUDIT_DBG 
            }

            page_count = printAudit_extract_page_number(job_file_name);
	#if defined (PRINT_AUDIT_DBG) 
            snprintf(buf_log, sizeof(buf_log), "extracted page number is :%d\n", page_count);
			printAudit_log_run_info(buf_log);
	#endif//PRINT_AUDIT_DBG 
            page_count =  page_count * num_copies;

            /*打印页数必须是正数*/
            if(page_count <= 0)
            {
                page_count = atoi(pdat[i].num_copies);
            }


            unlink(job_file_name);

		}

	#if defined (PRINT_AUDIT_DBG) 
        snprintf(buf_log, sizeof(buf_log), "getAudItem:page number is :%d\n", page_count);
		printAudit_log_run_info(buf_log);
	#endif//PRINT_AUDIT_DBG 
	  
        snprintf(str_page_count, sizeof(str_page_count), "%d", page_count);

        strncpy(printDat->filename, pdat[i].title, sizeof(printDat->filename)-1);
        strncpy(printDat->copies, pdat[i].num_copies, sizeof(printDat->copies)-1);
        strncpy(printDat->pages, str_page_count, sizeof(printDat->pages)-1);
        strncpy(printDat->usr, pdat[i].usr, sizeof(printDat->usr)-1);
        strncpy(printDat->print_name, pdat[i].printer, sizeof(printDat->print_name)-1);
        strncpy(printDat->print_time, pdat[i].time, sizeof(printDat->print_time)-1);
        sprintf(printDat->flg_print_ok, "%d", pdat[i].flg_print_ok);
        printDat->flg_print_ok[1] = '\0'; 
            
        if( 0 == strcmp( "0", printDat->flg_print_ok ) && 0 == pdat[i].flg_print_cancelled_by_policy)
        {
            printDat->flg_print_cancelled_by_usr = 1;
        }

		pdat[i].flg_used = 0;
		pdat[i].flg_audit = 0;
        pdat[i].flg_print_cancelled_by_policy = 0;

        return 1; 
	}
    
    return 0;
}

/**
 * 函数名:printAudit_matchJob()
 * 说明:该函数用于匹配输入的打印进任务名称;
 *    匹配成功返回1；匹配失败返回0；
 *
 * job_title:待匹配的打印任务名称；
 * file:打印任务名称匹配范围；
 */
static int printAudit_matchJob(char *job_title, std::vector<std::string> &file)
{
	char jobTileExt[10] = {0};
	char *p = NULL;
	std::vector<std::string>::iterator ite;
	int matched_flg = 0;

	if(NULL == job_title)	
	{
		return matched_flg;
	}

	p = strstr(job_title, ".");
	if(NULL  == p)
	{
		return matched_flg;
	}

	strncpy(jobTileExt, p, sizeof(jobTileExt) - 1); 

	for(ite = file.begin(); ite != file.end(); ite++)
	{
		if(0 == strcmp(jobTileExt, (*ite).c_str()))
		{
			matched_flg  = 1;
			break;
		}
	}

	return matched_flg ;
}

/**
 * 函数名:printAudit_writeAuditDat()
 * 说明:该函数向打印审计数据缓冲区写入审计数据;
 *    成功返回0；失败返回1；
 *
 * job:待写入的打印任务名称；
 * audit_dat:打印审计数据缓冲区指针任；
 * flgJobCancel:打印任务取消标记；
 */
static int printAudit_writeAuditDat(cups_job_t *job, struct print_audit_dat_t *audit_dat, char flgJobCancel)
{
	int i = 0;
	struct print_audit_dat_t *pdat = audit_dat; 

	for(i=0; i<PRINT_AUDIT_NUM_MAX_JOBS; i++)
	{
		if(pdat[i].flg_used && pdat[i].id == job->id &&
		   0 == strcmp(pdat[i].title, job->title))
		{
			return 0;
		}
	}
	
	for(i=0; i<PRINT_AUDIT_NUM_MAX_JOBS; i++)
	{
		if(!pdat[i].flg_used) 
		{
			pdat[i].id = job->id; 	
			strncpy(pdat[i].title, job->title, AUDIT_DAT_STR_LEN); 	
			pdat[i].flg_audit = 0;
			pdat[i].flg_used = 1;
			strncpy(pdat[i].usr, job->user, AUDIT_DAT_STR_LEN); 	
			strncpy(pdat[i].printer, job->dest, AUDIT_DAT_STR_LEN); 	
			pdat[i].flg_print_cancelled_by_policy = flgJobCancel;
			
			return 0;
		}
	}
	
	return 1 ;
}

/**
 * 函数名:printAudit_updateAuditDat()
 * 说明:该函数用于更新打印审计数据缓冲区中的数据;
 *    成功返回0；否则返回1；
 *
 * job:待更新的打印任务名称；
 * audit_dat:打印审计数据缓冲区指针任；
 */
static int printAudit_updateAuditDat(cups_job_t *job, struct print_audit_dat_t *audit_dat)
{
	int i = 0;
	struct print_audit_dat_t *pdat = audit_dat; 
	struct tm *timeJob_cm = NULL;
	char str_job_time_cm[AUDIT_DAT_STR_LEN + 1] = {0};
	int str_time_len = 0;

	/*
 	 *Get the time the job got completed, and delete the last 
 	 * char, '\n', in it.
 	 */
	timeJob_cm = localtime(&job->completed_time);
	strncpy(str_job_time_cm, asctime(timeJob_cm), AUDIT_DAT_STR_LEN);
	str_time_len = strlen(str_job_time_cm);
	if(1 <= str_time_len)
	{
		str_job_time_cm[str_time_len - 1] = '\0';
	}

	for(i=0; i<PRINT_AUDIT_NUM_MAX_JOBS; i++)
	{
		if(pdat[i].flg_used && !pdat[i].flg_audit &&
		   pdat[i].id == job->id &&
		   0 == strcmp(pdat[i].title, job->title)
		  ) 
		{
			pdat[i].flg_audit = 1;
			strncpy(pdat[i].time, str_job_time_cm, AUDIT_DAT_STR_LEN); 	
		 	if(IPP_JOB_CANCELED == job->state) 
			{
				pdat[i].flg_print_ok = 0;
			}
		 	else if(IPP_JOB_COMPLETED == job->state) 
			{
				pdat[i].flg_print_ok = 1;
				pdat[i].flg_print_cancelled_by_policy = 0;
			}

			return 0;
		}
	}
	
	return 1;
}

/**
 * 函数名:printAudit_getPrinter_allowFlg()
 * 说明:该函数判断打印机(由参数dst_printer指定)是否允许使用;
 * 		允许使用返回1；否则返回0；
 *
 * dst_printer:待判断的打印机名称；
 * pPrinter_info:本机的打印机信息;
 * plocalIfInfo:本机的网卡信息;
 * printer_ip_range:策略允许的打印机范围;
 */
static int printAudit_getPrinter_allowFlg(char *dst_printer, struct st_printer_info *pPrinter_info, struct st_if_info *plocalIfInfo, range_vector &printer_ip_range)
{
    unsigned int i = 0;
    unsigned int matched_idx = 0xff;
    unsigned int j = 0;
    struct st_if_info_item *pIf_Item_Info = NULL;
	
    if(NULL == dst_printer) 
    {
        return 0; 
    }
	
    if(0 == printer_ip_range.size())
    {
        return 1;
    }
    
    for(i = 0; i < PRINT_AUDIT_NUM_MAX_PRINTER; i++) 
    {
        if(0 != strlen(pPrinter_info[i].name) && 0 == strcmp(dst_printer, pPrinter_info[i].name) &&
          (0 != strlen(pPrinter_info[i].ip) || pPrinter_info[i].local_flg))
        {
            matched_idx = i; 
            break;
        }
    }

    if(PRINT_AUDIT_NUM_MAX_PRINTER < matched_idx)
    {
        return 0;
    }

    for(i = 0; i < printer_ip_range.size(); i++)
    {
        if(pPrinter_info[matched_idx].local_flg)
        {
            for(j = 0; j < plocalIfInfo->num_if; j++)
            {
                pIf_Item_Info = plocalIfInfo->if_item + j; 
                if(0 == IP_Range_Judged(pIf_Item_Info->ip, printer_ip_range[i].ip_begin, printer_ip_range[i].ip_end))
                {
                    return 1;
                }
            }
        }
        else
        {
            if(0 == IP_Range_Judged(pPrinter_info[matched_idx].ip, printer_ip_range[i].ip_begin, printer_ip_range[i].ip_end))
            {
                return 1;
            }
        }
    }

    return 0;
}

/*
 * 函数名:printAudit_getIfInfo()
 * 说明:该函数获取取本机的网卡信息
 * 		成功返回1；否则返回0；
 *
 * pIf_info:存储本机网卡信息的缓冲区；
 */
static int printAudit_getIfInfo(struct st_if_info **pIf_info)
{
	using namespace YCommonTool;
	std::list<std::string> niclist;
	std::string  ip;
	char buf_log[128] = {0};
	struct st_if_info_item *pIf_Item_Info = NULL;
 
	printAudit_log_run_info("printAudit_getIfInfo start.\n");

	if(NULL == pIf_info)
	{
		printAudit_log_run_info("printAudit_getIfInfo:null ptr.\n");
		return 1;
	}

	get_Nicinfo(niclist);

	(*pIf_info)->num_if = 0;

	std::list<std::string>::iterator  iter = niclist.begin();

	while(iter != niclist.end())
	{
		ip =  get_ip(*iter);

		if(NUM_MAX_INTERFACE < (*pIf_info)->num_if)
		{
			printAudit_log_run_info("printAudit_getIfInfo: reaches max if num.\n");
			return 0;	
		}

		pIf_Item_Info = (*pIf_info)->if_item + (*pIf_info)->num_if; 

		memset(pIf_Item_Info->ip , 0, sizeof(LEN_IP_ADDR + 1));
		strncpy(pIf_Item_Info->ip, ip.c_str(), LEN_IP_ADDR);

        snprintf(buf_log, sizeof(buf_log), "getIfInfo: idx, ip->%d,%s\n",
				(*pIf_info)->num_if, pIf_Item_Info->ip);
		printAudit_log_run_info(buf_log);

		(*pIf_info)->num_if ++ ;

		iter++ ;
	}

	printAudit_log_run_info("printAudit_getIfInfo end.\n");

	return 0;
}

/**
 * 函数名:printAudit_getPrinterInfo()
 * 说明:该函数获取本机的打印机配置
 * 		成功返回0；否则返回其他；
 *
 * pPrinter_info:本机的打印机信息缓冲区;
 * cap:pPrinter_info的大小;
 */
static int printAudit_getPrinterInfo(struct st_printer_info *printerInfo, int cap)
{
    #define BUF_LEN 512
    #define STR_PRINTER "<DefaultPrinter"
    #define STR_PRINTER1 "<Printer"
    #define STR_PRINTER_URI "DeviceURI"
    #define PRINTER_NAME_OFFSET 16 
    #define PRINTER_NAME_OFFSET1 9

    FILE *fp = NULL; 
    char buf[BUF_LEN + 1] = {0}; 
    int printer_count = 0;
    char *p = NULL;
	char log_buf[256] = {0};

    if(NULL == printerInfo)
    {
		printAudit_log_run_info("get_printer_info,null ptr input.");
        return -1;
    }
    
    fp = fopen(PRINTER_CONF_FILE, "r");
    if(NULL == fp)
    {
		printAudit_log_run_info("get_printer_info,open printers.conf err.");
        return -1;
    }

    while(fgets(buf, BUF_LEN, fp))
    {
        if(cap <= printer_count)
        {
            break;            
        }

        if(0 == strncmp(buf, STR_PRINTER, strlen(STR_PRINTER)))  
        {
            strncpy(printerInfo[printer_count].name, buf + PRINTER_NAME_OFFSET, PRINTER_NAME_LEN);
            if(strlen(buf + PRINTER_NAME_OFFSET) < PRINTER_NAME_LEN)
            {
                printerInfo[printer_count].name[strlen(buf + PRINTER_NAME_OFFSET) - 2] = '\0';
            }
            else
            {
                printerInfo[printer_count].name[PRINTER_NAME_LEN] = '\0';
            }
        }
        else if(0 == strncmp(buf, STR_PRINTER1, strlen(STR_PRINTER1)))
        {
            strncpy(printerInfo[printer_count].name, buf + PRINTER_NAME_OFFSET1, PRINTER_NAME_LEN);
            if(strlen(buf + PRINTER_NAME_OFFSET1) < PRINTER_NAME_LEN)
            {
                printerInfo[printer_count].name[strlen(buf + PRINTER_NAME_OFFSET1) - 2] = '\0';
            }
            else
            {
                printerInfo[printer_count].name[PRINTER_NAME_LEN] = '\0';
            }
        }
        
        if(0 == strncmp(buf, STR_PRINTER_URI, strlen(STR_PRINTER_URI)))
        {
            if(NULL != (p = strstr(buf, "usb")))/*local printer by usb*/
            {
                printerInfo[printer_count].ip[0] = '\0'; 
                printerInfo[printer_count].local_flg = 1; 

                snprintf(log_buf, sizeof(log_buf),
					 "printer %d is a local printer by usb, name:%s\n", printer_count,
                      printerInfo[printer_count].name);

				printAudit_log_run_info(log_buf);

                printer_count ++;
            }
            else if(NULL != (p = strstr(buf, "ipp")))/*network printer by ipp*/
            {
                char str_ip[15 + 1] = {0};
                char *ip_start = NULL;
                char *ip_end = NULL;

                /*p looks like:ipp://192.168.0.59:631/printers*/
                ip_start = p+6;
                if(NULL != ip_start)
                {
                    ip_end =  strstr(ip_start, ":");
                    if(NULL != ip_end)
                    {
                        strncpy(str_ip, ip_start, ip_end - ip_start);
                        strncpy(printerInfo[printer_count].ip, str_ip, LEN_IP_ADDR);
                        printerInfo[printer_count].ip[LEN_IP_ADDR] = '\0'; 
                        printerInfo[printer_count].local_flg = 0; 

                		snprintf(log_buf, sizeof(log_buf),
                        		"printer %d is a network printer, name:%s, ip:%s\n", printer_count,
                                printerInfo[printer_count].name, printerInfo[printer_count].ip);
						printAudit_log_run_info(log_buf);

                        printer_count ++;
                    }
                }
            }
            else
            {
                //...
            }
        }
    }

	fclose(fp);

    return 0;
}

/**
 * 函数名:printAudit_getJobPageInfo()
 * 说明:该函数获取打印任务的页码范围和份数
 *
 * jobId:任务id
 * pageRange:保存页码范围的指针;
 * copies:保存打印份数的指针;
 */
static void printAudit_getJobPageInfo(int jobId, char *pageRange, char *copies)
{
 	ipp_t  *request,               /* IPP Request */
           *response;              /* IPP Response */
 	ipp_attribute_t *attr;                /* Current attribute */
	ipp_jstate_t  jobstate;               /* job-state */
  int           jobid,                  /* job-id */
                jobsize,                /* job-k-octets */
#ifdef __osf__
                jobpriority,            /* job-priority */
#endif /* __osf__ */
                /*jobcount,*/               /* Number of jobs */
                jobcopies;              /* Number of copies */
	const char  *jobdest,               /* Pointer into job-printer-uri */
                *jobuser,               /* Pointer to job-originating-user-name */
                *jobname,               /* Pointer to job-name */
                *jobpage_range;               /* Pointer to job-name */

	static const char * const jobattrs[] =/* Job attributes we want to see */
    {
                  "copies",
		  		  "page-ranges",
		  		  "number-up",
                  "job-id",
                  "job-k-octets",
                  "job-name",
                  "job-originating-user-name",
                  "job-printer-uri",
                  "job-priority",
                  "job-state"
    };
    char resource[1024];         /* Resource string */
	
    int flg_page_range_find = 0;
    int flg_copies_find = 0;

    if(NULL == pageRange || NULL == copies)
    {
#if defined (PRINT_AUDIT_DBG) 
        printAudit_log_run_info("printAudit_getJobPageInfo: NULL ptr !");
#endif//PRINT_AUDIT_DBG

        return ;
    }

    request = ippNewRequest(IPP_GET_JOB_ATTRIBUTES);
    snprintf(resource, sizeof(resource), "ipp://localhost/jobs/%d", jobId);
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI, "job-uri",
                 NULL, resource);

    ippAddStrings(request, IPP_TAG_OPERATION, IPP_TAG_KEYWORD,
                "requested-attributes",
                (int)(sizeof(jobattrs) / sizeof(jobattrs[0])), NULL, jobattrs);

	if ((response = cupsDoRequest(CUPS_HTTP_DEFAULT, request, "/")) != NULL)
 	{
    		if (response->request.status.status_code > IPP_OK_CONFLICT)
    		{
#if 0
     			 _cupsLangPrintf(stderr, "%s: %s\n", command, cupsLastErrorString());
#endif
      			ippDelete(response);

				/*reset page info with the default value.*/
				copies[0] = '1';
				copies[1] = '\0';
				pageRange[0] = '1';
				pageRange[1] = '\0';	
				
      			return;
    		}
		 /*
 		 *  Loop through the job list and display them...
 		 * 
 		 */

    		for (attr = response->attrs; attr != NULL; attr = attr->next)
    		{
     			/*
 				 * Skip leading attributes until we hit a job...
 				 */			

     			 while (attr != NULL && attr->group_tag != IPP_TAG_JOB)
        			attr = attr->next;

      			if (attr == NULL)
        			break;
				
			    while (attr != NULL && attr->group_tag == IPP_TAG_JOB)
 			    {
        			if (!strcmp(attr->name, "job-id") &&
            				attr->value_tag == IPP_TAG_INTEGER)
					{
          				jobid = attr->values[0].integer; 	
					}

        			if (!strcmp(attr->name, "job-k-octets") &&
            				attr->value_tag == IPP_TAG_INTEGER)
					{
          				jobsize = attr->values[0].integer;						
					}

				#ifdef __osf__
        			if (!strcmp(attr->name, "job-priority") &&
            				attr->value_tag == IPP_TAG_INTEGER)
          				jobpriority = attr->values[0].integer;
				#endif /* __osf__ */

        			if (!strcmp(attr->name, "job-state") &&
            				attr->value_tag == IPP_TAG_ENUM)
					{
          				jobstate = (ipp_jstate_t)attr->values[0].integer;						
					}

        			if (!strcmp(attr->name, "job-printer-uri") &&
            				attr->value_tag == IPP_TAG_URI)
          				if ((jobdest = strrchr(attr->values[0].string.text, '/')) != NULL)
            					jobdest ++;


					 if (!strcmp(attr->name, "job-originating-user-name") &&
			            attr->value_tag == IPP_TAG_NAME)
					{
          				jobuser = attr->values[0].string.text;						
					}

        			if (!strcmp(attr->name, "job-name") &&
            				attr->value_tag == IPP_TAG_NAME)
					{
          				jobname = attr->values[0].string.text;						
					}

        			if (!strcmp(attr->name, "page-ranges") &&
            				attr->value_tag == IPP_TAG_NAME)
					{
          				jobpage_range = attr->values[0].string.text;
						flg_page_range_find = 1;						
						strncpy(pageRange, jobpage_range, AUDIT_DAT_STR_LEN-1);						
					}
        			if (!strcmp(attr->name, "number-up") &&
            				attr->value_tag == IPP_TAG_NAME)
					{
          				jobpage_range = attr->values[0].string.text;
						flg_page_range_find = 1;
						strncpy(pageRange, jobpage_range, AUDIT_DAT_STR_LEN-1);						
					}

        			if (!strcmp(attr->name, "copies") &&
            				attr->value_tag == IPP_TAG_INTEGER)
					{
						char str_jobCopies[10] = {0};
          				jobcopies = attr->values[0].integer;
						flg_copies_find = 1;
						sprintf(str_jobCopies, "%d", jobcopies);
						strncpy(copies, str_jobCopies, AUDIT_DAT_STR_LEN-1);
					}
					
        			attr = attr->next;

					if(NULL == attr)
					{
						break;
					}				
      			}/*while*/
			if(NULL == attr)
			{
				break;
			}
		}/*for*/

		if(!flg_copies_find)
		{
			copies[0] = '1';
			copies[1] = '\0';				 
		}

		if(!flg_page_range_find)
		{
			pageRange[0] = '1';
			pageRange[1] = '\0';				 
		}
        ippDelete(response);
	}/*if*/
}

/**
 * 函数名:printAudit_extract_page_number()
 * 说明:该函数从输入的文件中提取打印的页数;
 *      返回值为打印的页数；
 *
 * file_name:输入的文件名;
 */
static int printAudit_extract_page_number(const char *file_name)
{
    FILE *pf = NULL;
    char c = '\0';
    char flg_new_page[5];
    fpos_t pos;
    char buf[128] = {0};
    int page_count = 0; 
    
    flg_new_page[0] = 0x0b;
    flg_new_page[1] = 0x12;
    flg_new_page[2] = 0x12;
    flg_new_page[3] = 0x01;
    flg_new_page[4] = 0x00;

    pf = fopen(file_name, "r");
    if(NULL == pf) 
    {
        printAudit_log_run_info("extract_page_number:fopen err.");
        return -1;
    }
    
    fgetpos(pf, &pos);
    do
    {
        fsetpos(pf, &pos); 
        c = '\0';

        while(c != flg_new_page[0] && (0 == feof(pf)))
        {
           c = fgetc(pf);
        }

        fgetpos(pf, &pos);
        if(0 == feof(pf))
        {
            fseek(pf, -1, SEEK_CUR);
            fgets(buf, sizeof(flg_new_page), pf);
            if(0 == strcmp(buf, flg_new_page))
            {
                page_count ++;
            }
        }
    
    }while(0 == feof(pf));
    
    fclose(pf);

    if(page_count <= 0)
    {
        page_count = 1;
    }

    return page_count ;
}

/**
 * 函数名:printAudit_extract_copies_number()
 * 说明:该函数从输入的文件中提取打印的份数;
 *      成功返回0;失败返回其他值；
 * 打印份数位于分页标志向后偏移8个字节的位置，如下图所示；
 * 0B 12 12 01 00 3C 3C 00 00 copies-dat-byte0 copies-dat-byte1 
 *
 * file_name:输入的文件名;
 * pNum_copies:打印份数指针，待填充;
 */
static int printAudit_extract_copies_number(const char *file_name, short *pNum_copies)
{
    #define COPIES_OFFSET 8
    FILE *pf = NULL;
    char c = '\0';
    fpos_t pos;
    char buf[128] = {0};
    char flg_new_page[5];
    short dat_copies = 1;
	#if defined (PRINT_AUDIT_DBG) 
    char buf_log[128] = {0};
	#endif//PRINT_AUDIT_DBG

    flg_new_page[0] = 0x0b;
    flg_new_page[1] = 0x12;
    flg_new_page[2] = 0x12;
    flg_new_page[3] = 0x01;
    flg_new_page[4] = 0x00;

    if(NULL == file_name || NULL == pNum_copies)
    {
        return -1;
    }

    pf = fopen(file_name, "r");
    if(NULL == pf)
    {
        printAudit_log_run_info("extract_page_copies:fopen err.");
        return -1;
    }

    fgetpos(pf, &pos);
    do
    {
        fsetpos(pf, &pos); 
        c = '\0';
        while(c != flg_new_page[0] && (0 == feof(pf)))
        {
           c = fgetc(pf);
        }

        fgetpos(pf, &pos);
        if(0 == feof(pf))
        {
            fseek(pf, -1, SEEK_CUR);
            fgets(buf, sizeof(flg_new_page), pf);
            if(0 == strcmp(buf, flg_new_page))
            {
                fsetpos(pf, &pos);                

                /*go where the copies data lies. */
                fseek(pf, COPIES_OFFSET, SEEK_CUR);

                fread(&dat_copies, sizeof(dat_copies), 1, pf);

                break;
            }
        }
    }while(0 == feof(pf));
    
    fclose(pf);

    *pNum_copies = dat_copies;
    
	#if defined (PRINT_AUDIT_DBG) 
    snprintf(buf_log, sizeof(buf_log), "extract_page_copies_number:copies num is %d",
			 *pNum_copies);
	printAudit_log_run_info(buf_log);
	#endif//PRINT_AUDIT_DBG 

    return 0;
}

/**
 * 函数名:printAudit_log_run_info()
 * 说明:该函数将运行策略信息写入log文件;
 */
static void printAudit_log_run_info(const char *log_content)
{
	char log_info[2048] = {0};

	if(NULL == log_content)
	{
		return ;
	}
	
	snprintf(log_info, sizeof(log_info), "print_ctl:%s\n", log_content);

	g_GetlogInterface()->loglog(log_info);
}

/**
 * 函数名:printAudit_show_dlg()
 * 说明:该函数显示信息提示框，超时或者按确定后关闭;
 */
static void printAudit_show_dlg(const char *info)
{
	 char buffer[512] = "";
	 tag_GuiTips * pTips = (tag_GuiTips *)buffer;
	 pTips->sign = en_TipsGUI_btnOK | en_TipsGUI_timeOut; 
	 pTips->defaultret = en_TipsGUI_None;
	 pTips->pfunc = NULL;
	 pTips->param.timeout = 3;//以秒为单位
	 sprintf(pTips->szTitle,"确认");
	 snprintf(pTips->szTips, sizeof(pTips->szTips), "%s", info);
	 g_GetSendInterface()->sendto_Imc(VCF_CMD_GUI_TIPS, buffer, sizeof(tag_GuiTips));
}

#if 1 /*only for debug*/
static void del_all_space(char *src)
{
    char *p = src;
    while(*src)
    {
       if((*src != ' ')&&(*src != '\t'))
       {
          *p=*src;
          p++;
       }
       src++;
    }
    *p='\0';
}

static int Deal_IPRange(char *org_range,range_vector &ip_ran_list)
{
    char *pch = NULL;
    char *index = NULL;
    char buf[256]={0};
    char range[512]={0};
    ip_range ip_ran;

    memset(&ip_ran,'\0',sizeof(ip_range));
    strncpy(range,org_range,sizeof(range)-1);
    del_all_space(range);
    if(0==strcmp("",range))
    {
        return 0;
    }

    pch = strtok(range,";");
    if(NULL == pch)
    {
        strncpy(ip_ran.ip_begin,range,16);
        strncpy(ip_ran.ip_end,range,16);
        ip_ran_list.push_back(ip_ran);
        return 0;
    }

    while(pch != NULL)
    {
        strncpy(buf,pch,256);
        index = strstr(buf,"-");
        if(index != NULL)
        {
            *index='\0';
            strncpy(ip_ran.ip_begin,buf,16);
            strncpy(ip_ran.ip_end,index+1,16);
        }
        else
        {
            strncpy(ip_ran.ip_begin,buf,16);
            strncpy(ip_ran.ip_end,buf,16);
        }
        ip_ran_list.push_back(ip_ran);
        memset(&ip_ran,'\0',sizeof(ip_range));
        memset(buf,'\0',256);
        pch = strtok(NULL,";");
    }

    return 0;
}

static int IP_Range_Judged(char *ip,char *start_ip,char *end_ip)
{
    if(NULL == ip)
    {
        return 0;
    }

    struct in_addr start_in,end_in,in;
    start_in.s_addr = inet_addr(start_ip);
    end_in.s_addr = inet_addr(end_ip);
    in.s_addr = inet_addr(ip);
    if(ntohl(in.s_addr) >= ntohl( start_in.s_addr)\
            &&ntohl(in.s_addr) <= ntohl( end_in.s_addr))
    {
        //in range
        return 0;
    }
    else
    {
        //out of range
        return -1;
    }
}
#endif


/*-------------------------以下为网络共享审计与监控部分--------------------------*/
/*封装vsnprintf，方便记录日志*/
void share_log(const char* fmt, ...)
{
    char log[256]={0};
    va_list args;         //定义一个va_list类型的变量，用来储存单个参数
    va_start(args, fmt);  //使args指向可变参数的第一个参数
    vsnprintf(log,sizeof(log)-1,fmt,args);
    va_end(args);         //结束可变参数的获取
    g_GetlogInterface()->log_trace(log);
}

/*
*探测进程是否存在
*return -1 : detect fail
*             0: no exist
*             other: exist
*/
static int detect_process(const char * process_name)
{
    char buf[512]={0};
    char ps[128]={0};
    sprintf(ps, "pgrep %s", process_name);
    FILE *fp = popen(ps, "r");
    if(NULL == fp)
    {
        return -1;
    }
    fgets(buf, sizeof(buf) - 1, fp);
    pclose(fp);

    if(atoi(buf)==0)
    {
        return 0;
    }
    else
    {
        return atoi(buf);
    }
}


//探测端口，0探测成功，-1探测失败
static int detect_port(int port_num,list<int> &pid_list)
{
    char buf[512]={0};
    char lsof[128]={0};
    sprintf(lsof, "lsof -i:%d|grep UDP|awk '{print $2}'", port_num);
    FILE *fp = popen(lsof, "r");
    if(NULL == fp)
    {
        return -1;
    }
    while(NULL != fgets(buf, sizeof(buf) - 1, fp))
    {
        if(atoi(buf)!=0)
        {
            pid_list.push_back(atoi(buf));
        }
        memset(buf,'\0',sizeof(buf));
    }
    pclose(fp);
    return 0;
}


//通过kill进程，释放端口
static int realese_certain_ports(list<int> &mylist,int expid = 0)
{
    list<int>::iterator it;
    for (it=mylist.begin(); it != mylist.end();it++)
    {
        if(expid != *it)
        {
            kill(*it,SIGINT);
        }
    }
    return 0;
}


//1: in vector,0: out of vector
static int judge_vector_exist(string item,vector <string> mylist)
{
    vector <string>::iterator it;
    for(it = mylist.begin();it !=mylist.end();it++)
    {
        if(*it == item)
        {
            return 1;
        }
    }
    return 0;
}


//获取nfs共享方式的共享路径
int get_nfs_share_path(std::vector<std::string> &mylist)
{
    FILE *fp =NULL;
    char buf[1024]={0};
    char path[1024]={0};
    char cmd[1024]={0};

    snprintf(cmd,sizeof(cmd)-1,"exportfs|awk '{print $1}'");
    fp=popen(cmd,"r");
    if(NULL == fp)
    {
        return -1;
    }

    while(NULL != fgets(buf,sizeof(buf)-1,fp))
    {
        sscanf(buf, "%[^\n]", path);
        if(0 == access(path,F_OK))
        {
            mylist.push_back(path);
            g_share_path_mode.push_back("nfs");
        }
        memset(buf,'\0',sizeof(path));
        memset(buf,'\0',sizeof(buf));
    }
    pclose(fp);
    return 0;
}


//获取samba共享方式的中home目录的共享路径
int get_smb_home_path(vector <string> &mylist)
{
    FILE *fp =NULL;
    char buf[1024]={0};
    char usrname[1024]={0};
    char path[1024]={0};
    char cmd[1024]={0};

    memset(cmd,'\0',sizeof(cmd));
    snprintf(cmd,sizeof(cmd)-1,"pdbedit -L");
    fp=popen(cmd,"r");
    if(NULL == fp)
    {
        return -1;
    }
    while(NULL != fgets(buf,sizeof(buf)-1,fp))
    {
        sscanf(buf, "%[^:]", usrname);
        sprintf(path,"/home/%s",usrname);
        if(0 == access(path,F_OK))
        {
            mylist.push_back(path);
            g_share_path_mode.push_back("samba");
        }
        memset(usrname,'\0',sizeof(usrname));
        memset(path,'\0',sizeof(path));
        memset(buf,'\0',sizeof(buf));
    }
    pclose(fp);
    return 0;
}


//获取samba共享方式的共享路径
int get_smb_share_path(vector<string> &mylist)
{
    char conf_name[128]="/etc/samba/smb.conf";
    if(0 != access(conf_name,F_OK))
    {
        return 0;
    }

    IniFile file(conf_name);

    FILE *fp =NULL;
    char buf[1024]={0};
    char path[1024]={0};
    char cmd[1024]={0};

    snprintf(cmd,sizeof(cmd)-1,
            "testparm -s|grep path|grep -v '[;#]'|awk '{print $3}'");
    fp=popen(cmd,"r");
    if(NULL == fp)
    {
        return -1;
    }

    while(NULL != fgets(buf,sizeof(buf)-1,fp))
    {
        sscanf(buf, "%[^\n]", path);
        if(0 == access(path,F_OK))
        {
            if(0 != strcmp(path,file.ReadString("printers","path")))
            {
                mylist.push_back(path);
                g_share_path_mode.push_back("samba");
            }
        }
        memset(buf,'\0',sizeof(path));
        memset(buf,'\0',sizeof(buf));
    }
    pclose(fp);

    if((0 == strcasecmp("yes",file.ReadString("homes","yes")))
            ||(0 == strcasecmp("user",file.ReadString("global","security"))))
    {
        get_smb_home_path(mylist);
    }
    return 0;
}


//获取tftp共享方式的共享路径
int get_tftp_share_path(vector<string> &mylist,list<int> &pid_list)
{
    char conf_name[128]="/etc/xinetd.d/tftp";
    if(0 != access(conf_name,F_OK))
    {
        realese_certain_ports(pid_list,g_tftp_pid);
        if(g_tftp_pid == 0)
        {
            if(0 != access("/home/tftpboot",F_OK))
            {
                system("mkdir /home/tftpboot");
                share_log("mkdir /home/tftpboot");
            }
            system("./tftpd -p /home/tftpboot");
            share_log("pid_list size=%d",pid_list.size());
            char buffer[512] = "";
            tag_GuiTips * pTips = (tag_GuiTips *)buffer;
            pTips->sign = en_TipsGUI_btnOK|en_TipsGUI_timeOut;
            pTips->defaultret = en_TipsGUI_btnOK;
            pTips->pfunc = NULL;
            pTips->param.timeout = 20*1000;//以秒为单位
            sprintf(pTips->szTitle,"共享提示");
            snprintf(pTips->szTips, sizeof(pTips->szTips), "为保证您的计算机共享安全，请在/home/tftpboot下共享文件");
            g_GetSendInterface()->sendto_Imc(VCF_CMD_GUI_TIPS, buffer, sizeof(tag_GuiTips));
            g_tftp_pid = detect_process("tftpd");
            share_log("run tftp pid=%d",g_tftp_pid);
        }
        mylist.push_back("/home/tftpboot");
        g_share_path_mode.push_back("tftp");
    }
    else
    {
        FILE *fp =NULL;
        char buf[1024]={0};
        char path[1024]={0};
        char cmd[1024]={0};

        snprintf(cmd,sizeof(cmd)-1,
                "cat %s|grep server_args|awk '{print $4}'",conf_name);
        fp=popen(cmd,"r");
        if(NULL == fp)
        {
            return -1;
        }

        while(NULL != fgets(buf,sizeof(buf)-1,fp))
        {
            sscanf(buf, "%[^\n]", path);
            if(0 == access(path,F_OK))
            {
                mylist.push_back(path);
                g_share_path_mode.push_back("tftp");
            }
            memset(buf,'\0',sizeof(path));
            memset(buf,'\0',sizeof(buf));
        }
        pclose(fp);
    }
    return 0;
}


//获取所有共享文件的文件名
int get_share_file_list(char cmd[],std::vector<std::string> &mylist,std::string mode)
{
    FILE *fp =NULL;
    char buf[1024]={0};
    char path[1024]={0};

    fp=popen(cmd,"r");
    if(NULL == fp) {
        return -1;
    }

    while(NULL != fgets(buf,sizeof(buf)-1,fp)) {
        sscanf(buf, "%[^\n]", path);
        if(0 == access(path,F_OK)) {
            mylist.push_back(path);
            if(mode == "nfs")
            {
                g_share_file_list_mode.push_back("nfs");
            }
            if(mode == "samba")
            {
                g_share_file_list_mode.push_back("samba");
            }
            if(mode == "tftp")
            {
                g_share_file_list_mode.push_back("tftp");
            }
        }
        memset(buf,'\0',sizeof(path));
        memset(buf,'\0',sizeof(buf));
    }
    pclose(fp);
    return 0;
}


//禁止共享：选择禁止共享同时扩展名中内容为空时使用
void share_refuse_all(void)
{
    //禁用nfs
    if(0 < detect_process("nfsd"))
    {
        system("service nfs stop");
        share_log("service nfs stop");
    }

    //禁用samba
    if(0 < detect_process("smbd"))
    {
        system("service smb stop");
        share_log("service smb stop");
    }

    //禁用tftp
    list <int> pid_list;
    if(0==detect_port(69,pid_list))
    {
        int size = pid_list.size();
        if(size != 0)
        {
            realese_certain_ports(pid_list);
            share_log("realese port 69");
        }
    }
}


//禁止共享：禁止特点后缀文件名
void share_refuse_ext(std::vector<std::string> &refuse_share_type)
{
    char cmd[1024]={0};
    int i = 0;
    std::vector<std::string>::iterator p_fold,p_ext;
    for(p_fold=g_share_path.begin();p_fold != g_share_path.end();p_fold++)
    {
        for(p_ext=refuse_share_type.begin();p_ext!=refuse_share_type.end();p_ext++)
        {
            snprintf(cmd,sizeof(cmd)-1,"find %s -type f -name '*%s'",(*p_fold).c_str(),(*p_ext).c_str());
            get_share_file_list(cmd,refuse_share_file_list,g_share_path_mode[i]);
        }
        i++;
    }
}


//审计所有共享文件
void share_audit_all(void)
{
    char cmd[1024]={0};
    int i = 0;
    std::vector<std::string>::iterator p_fold;
    for(p_fold=g_share_path.begin();p_fold != g_share_path.end();p_fold++)
    {
        snprintf(cmd,sizeof(cmd)-1,"find %s -type f 2>/dev/null",(*p_fold).c_str());
        get_share_file_list(cmd,audit_share_file_list,g_share_path_mode[i]);
        i++;
    }
}


//审计特定后缀共享文件
void share_audit_ext(std::vector<std::string> &audit_share_type)
{
    char cmd[1024]={0};
    int i=0;
    vector<string>::iterator p_fold,p_ext;
    for(p_fold=g_share_path.begin();p_fold != g_share_path.end();p_fold++)
    {
        for(p_ext=audit_share_type.begin();p_ext!=audit_share_type.end();p_ext++)
        {
            snprintf(cmd,sizeof(cmd)-1,"find %s -type f -name '*%s'",(*p_fold).c_str(),(*p_ext).c_str());
            get_share_file_list(cmd,audit_share_file_list,g_share_path_mode[i]);
        }
        i++;
    }
}


static int share_main(CPolicy *pPolicy, void *pParam)
{
    CFileOpCtl *pShare = (CFileOpCtl *)pPolicy;
    g_share_path.clear();
    g_share_path_mode.clear();
    share_log("DisableNetFile=%s,refuse_share_type size=%d",pShare->DisableNetFile.c_str(),pShare->refuse_share_type.size());
    if(("0" != pShare->DisableNetFile) && (0 == pShare->refuse_share_type.size()))
    {
        share_refuse_all();
        share_log("disable all share files");
        return 0;
    }

    //nfs
    if(0 < detect_process("nfsd"))
    {
        get_nfs_share_path(g_share_path);
    }
    //samba
    if(0 < detect_process("smbd"))
    {
        get_smb_share_path(g_share_path);
    }
    //tftp
    list <int> pid_list;
    if(0==detect_port(69,pid_list))
    {
        int size = pid_list.size();
        cout<<"detect port pid_list size="<<size<<endl;
        if(size != 0)
        {
            get_tftp_share_path(g_share_path,pid_list);
        }
    }
    //others

    if(0 == g_share_path.size())
    {
        share_log("no sharing");
        return 0;
    }
    cout<<"g_share_path size="<<g_share_path.size()<<endl;
    int i = 0;
    for(i=0;i<(int)g_share_path.size();i++)
    {
        cout<<"path:"<<g_share_path[i]<<" mode:"<<g_share_path_mode[i]<<endl;
        share_log("path:%s,mode:%s",g_share_path[i].c_str(),g_share_path_mode[i].c_str());
    }

    string tmp,content;
    //全部禁止的情况已处理,以下仅处理禁止指定后缀的文件
    if("0" != pShare->DisableNetFile)
    {
        refuse_share_file_list.clear();
        g_share_file_list_mode.clear();
        share_refuse_ext(pShare->refuse_share_type);
        mode_t mode;
        struct stat buf;
        for(i =0 ; i < (int)refuse_share_file_list.size(); i++)
        {
            if(lstat(refuse_share_file_list[i].c_str(),&buf) != -1)
            {
                mode = buf.st_mode;
                if(mode & S_IROTH)
                {
                    mode &=~S_IROTH;
                    chmod(refuse_share_file_list[i].c_str(),mode);
                    tmp = "发现文件" + refuse_share_file_list[i] +"被共享,共享方式"+g_share_file_list_mode[i]+",已禁止";
                    content = pShare->Info_ReportToServer(1, 602, tmp,basename(refuse_share_file_list[i].c_str()));
                    pShare->Audit_Info_Deal(content);
                }
            }
        }
        return 0;
    }
    if("0" != pShare->AuditNetFile)
    {
        audit_share_file_list.clear();
        g_share_file_list_mode.clear();
        if(0 == pShare->audit_share_type.size())
        {
            share_audit_all();
        }
        else
        {
            share_audit_ext(pShare->audit_share_type);
        }
        cout<<"audit_share_file_list size="<<audit_share_file_list.size()<<endl;
        for(i =0 ; i < (int)audit_share_file_list.size(); i++)
        {
            if(0 == judge_vector_exist(audit_share_file_list[i],g_share_file_list))
            {
                tmp = "发现文件" + audit_share_file_list[i] +"被共享,共享方式"+g_share_file_list_mode[i];
                content = pShare->Info_ReportToServer(0, 602, tmp,basename(audit_share_file_list[i].c_str()));
                pShare->Audit_Info_Deal(content);
            }
        }
        g_share_file_list = audit_share_file_list;
        return 0;
    }
    return 0;
}


static void share_previous_recovery(void)
{
    mode_t mode;
    struct stat buf;
    int i = 0;
    for(i =0 ; i < (int)refuse_share_file_list.size(); i++)
    {
        if(lstat(refuse_share_file_list[i].c_str(),&buf) != -1)
        {
            mode = buf.st_mode;
            if(!(mode & S_IROTH))
            {
                mode |=S_IROTH;
                chmod(refuse_share_file_list[i].c_str(),mode);
            }
        }
    }
}
