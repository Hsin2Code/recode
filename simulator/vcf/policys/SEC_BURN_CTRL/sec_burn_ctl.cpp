/**
 * sec_burn_ctl.cpp
 *
 *  Created on: 2015-1-15
 *      Author: liu
 *  该文件包含了安全刻录控制所需的所有函数；
 */

#include <unistd.h>
#include <stdio.h>
#include <sstream>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>
#include <errno.h>
#include "sec_burn_ctl.h"
#include "../../../include/Markup.h"
#include "../../../include/MCInterface.h"
#include "../../VCFCmdDefine.h"
#include "../../vrvprotocol/VRVProtocol.hxx"
#include "../../common/Commonfunc.h"
#include "../../common/TIniFile.h"

using namespace std;

/**
 *本地宏定义
 */
#define SEC_BURN_CTL_DBG

#if defined(HW_X86)
//#undef HW_X86
#endif

/**
 *本地使用的全局变量
 */
static char g_burn_evt_data[32] = "cdrw.dat";
#if defined(HW_X86)
static char g_genisoimage_process_name[32]="genisoimage";
#endif//HW_X86
static char g_brasero_process_name[32] = "brasero";
static char g_burn_times_file_name[32] = "cdrw.ini";
static char *g_brasero_tmp_path;/*刻录软件brasero的临时工作目录*/
static char *g_burn_tmp_file_full_path;/*刻录软件brasero生成的临时文件名*/
static char *g_cd_dev_model;/*刻录机型号*/
static char *g_cd_property;/*光盘型号*/
static char *g_cd_dev_name;/*刻录机所用光驱设备名称*/
static unsigned int g_cur_policy_crc;/*当前策略的crc*/
static int g_cur_burn_times;/*当前刻录的次数*/
#if defined(HW_X86)
static char *g_burn_info_file_name_X86;
static enum_cdbrun_state g_burn_state ;
struct file_check_st g_file_check_md5;
#endif//HW_X86

/**
 * 本地使用的函数声明
 */
static int secBurnCtl_main(CSecBurnCtl *pPolicy, void *pParam);
static int secBurnCtl_get_allow_flg(CSecBurnCtl *pPolicy, int *pAllow_flg);
static void secBurnCtl_set_cd_dev_property(int can_burn_flag);
static void secBurnCtl_log_run_info(const char *log_content);
static int secBurnCtl_generate_list(string srcInfo, char delim, list <string> &mylist);
static int secBurnCtl_detect_process(const char *process_name);
#ifndef HW_X86
static int secBurnCtl_get_brun_process_tmp_path(void);
static int secBurnCtl_get_burn_file_info(CSecBurnCtl *pPolicy, char file_name[]);
static int secBurnCtl_get_device_name(char *device_name, int len);
static int handle_uri(const char *input_str, char *output_str);
static int translate(const char *input, char *output);
#endif//HW_X86
static int secBurnCtl_get_cdDevModel(const char *dev_name, char *cd_dev_model, int len);
static int secBurnCtl_get_cdProperty(const char *dev_name, char *cd_property, int len);
static int judge_list_exist(string item, list<string> &mylist);
static char *get_file_postfix(char *in_buf);
static int judge_exist_keywords(string item, list<string> &mylist);
static int kill_process(char process_name[]);
static int deal_file_size(unsigned int size, char buf[]);
static int secBurnCtl_report_evt(CSecBurnCtl *pPolicy, int is_burn_allowed);
static int secBurnCtl_creat_burn_content(CSecBurnCtl *pPolicy, string &content, char burnfile[], int is_allowed);
static int secBurnCtl_save_burn_evt(string info);
static void secBurnCtl_show_dlg(const char *info);
static void secBurnCtl_read_burn_times(CSecBurnCtl *pPolicy);
static unsigned int get_file_size(const char *path);
static string int2str(int &i);
#if defined(HW_X86)
static int secBurnCtl_get_burn_file_info_x86(CSecBurnCtl *pPolicy, char filename[]);
static int secBurnCtl_get_burn_info_file_name(char *brasero_tmp_file_path, char *burn_info_file, int len);
static int  secBurnCtl_get_burn_ret_x86(CSecBurnCtl *pPolicy);
static int secBurnCtl_get_device_name_x86(char *file_name, char *device_name, int len);
static int file_unchanged(const char *file_name);
static int secBurnCtl_detect_process_x86(void);
static int secBurnCtl_get_burn_file_name(char *brasero_tmp_file_path, char *burn_file, int len);
static int secBurnCtl_decide_check_x86(void);
#endif//HW_X86

/**
 * 类的构造方法
 */
CSecBurnCtl::CSecBurnCtl()
{
    enPolicytype type = POLICY_SEC_BURN;
	set_type(type);
	secBurnCtl_log_run_info("sec_burn_ctl constructor.");
}

/**
 * 类的析构函数
 */
CSecBurnCtl::~CSecBurnCtl()
{
	secBurnCtl_log_run_info("sec_burn_ctl destroy.");
}

/**
 *父类虚函数实现：copy函数
 */
void CSecBurnCtl::copy_to(CPolicy * pDest)
{
	secBurnCtl_log_run_info("copy_to_start.");

    ((CSecBurnCtl *)pDest)->xmlitem = xmlitem;
    ((CSecBurnCtl *)pDest)->blacklist = blacklist;
    ((CSecBurnCtl *)pDest)->whitelist = whitelist;
    ((CSecBurnCtl *)pDest)->wordlist = wordlist;

    /*读取刻录次数,这不是一个好位置,但目前只能如此.*/
    secBurnCtl_read_burn_times((CSecBurnCtl *)this);

   	CPolicy::copy_to(pDest);
	secBurnCtl_log_run_info("copy_to end.");
}

/**
 *父类虚函数实现：策略导入函数
 */
bool CSecBurnCtl::import_xml(const char *pxml)
{
	char buf_policy[512] = {0};

	secBurnCtl_log_run_info("import_xml start.");

    if(pxml == NULL)
    {
	    secBurnCtl_log_run_info("import xml:empty xml file.");
		return false ;
    }

    CMarkup  xml ;
    if(!xml.SetDoc(pxml))
	{
	    secBurnCtl_log_run_info("import xml:setDoc err.");
		return false ;
    }

    xmlitem.clear();

    if(xml.FindElem("vrvscript"))
    {
		xml.IntoElem();
		std::string tmp_str;

		while(xml.FindElem("item"))
		{
			tmp_str = xml.GetAttrib("CanBurnFlag");
			if(0 != tmp_str.length())
			{
                xmlitem["CanBurnFlag"] = tmp_str;
				snprintf(buf_policy, sizeof(buf_policy), "CanBurnFlag:%s", tmp_str.c_str());
				secBurnCtl_log_run_info(buf_policy);
			}

			tmp_str = xml.GetAttrib("ExtensionFilter");
			if(0 != tmp_str.length())
			{
                xmlitem["ExtensionFilter"] = tmp_str;
				snprintf(buf_policy, sizeof(buf_policy), "ExtensionFilter:%s", tmp_str.c_str());
				secBurnCtl_log_run_info(buf_policy);
			}

			tmp_str = xml.GetAttrib("BlacklistFileType");
			if(0 != tmp_str.length())
			{
                xmlitem["BlacklistFileType"] = tmp_str;
				snprintf(buf_policy, sizeof(buf_policy), "BlacklistFileType:%s", tmp_str.c_str());
				secBurnCtl_log_run_info(buf_policy);
			}

			tmp_str = xml.GetAttrib("KeywordFilter");
			if(0 != tmp_str.length())
			{
                xmlitem["KeywordFilter"] = tmp_str;
				snprintf(buf_policy, sizeof(buf_policy), "KeywordFilter:%s", tmp_str.c_str());
				secBurnCtl_log_run_info(buf_policy);
			}

			tmp_str = xml.GetAttrib("BurnNumber");
			if(0 != tmp_str.length())
			{
                xmlitem["BurnNumber"] = tmp_str;
				snprintf(buf_policy, sizeof(buf_policy), "BurnNumber:%s", tmp_str.c_str());
				secBurnCtl_log_run_info(buf_policy);
			}

			tmp_str = xml.GetAttrib("BurnWeekDay");
			if(0 != tmp_str.length())
			{
                xmlitem["BurnWeekDay"] = tmp_str;
				snprintf(buf_policy, sizeof(buf_policy), "BurnWeekDay:%s", tmp_str.c_str());
				secBurnCtl_log_run_info(buf_policy);
			}

			tmp_str = xml.GetAttrib("BurnBeginTime");
			if(0 != tmp_str.length())
			{
                xmlitem["BurnBeginTime"] = tmp_str;
				snprintf(buf_policy, sizeof(buf_policy), "BurnBeginTime:%s", tmp_str.c_str());
				secBurnCtl_log_run_info(buf_policy);
			}

			tmp_str = xml.GetAttrib("BurnEndTime");
			if(0 != tmp_str.length())
			{
                xmlitem["BurnEndTime"] = tmp_str;
				snprintf(buf_policy, sizeof(buf_policy), "BurnEndTime:%s", tmp_str.c_str());
				secBurnCtl_log_run_info(buf_policy);
			}

			tmp_str = xml.GetAttrib("BurnProjectName");
			if(0 != tmp_str.length())
			{
                xmlitem["BurnProjectName"] = tmp_str;
				snprintf(buf_policy, sizeof(buf_policy), "BurnProjectName:%s", tmp_str.c_str());
				secBurnCtl_log_run_info(buf_policy);
			}

			tmp_str = xml.GetAttrib("LicenseCode");
			if(0 != tmp_str.length())
			{
                xmlitem["LicenseCode"] = tmp_str;
				snprintf(buf_policy, sizeof(buf_policy), "LicenseCode:%s", tmp_str.c_str());
				secBurnCtl_log_run_info(buf_policy);
			}

			tmp_str = xml.GetAttrib("UpRegionService");
			if(0 != tmp_str.length())
			{
                xmlitem["UpRegionService"] = tmp_str;
				snprintf(buf_policy, sizeof(buf_policy), "UpRegionService:%s", tmp_str.c_str());
				secBurnCtl_log_run_info(buf_policy);
			}

			tmp_str = xml.GetAttrib("WriteLocalFile");
			if(0 != tmp_str.length())
			{
                xmlitem["WriteLocalFile"] = tmp_str;
				snprintf(buf_policy, sizeof(buf_policy), "WriteLocalFile:%s", tmp_str.c_str());
				secBurnCtl_log_run_info(buf_policy);
			}

		}
		xml.OutOfElem();
    }

    secBurnCtl_generate_list(xmlitem["ExtensionFilter"], '.', whitelist);
    secBurnCtl_generate_list(xmlitem["BlacklistFileType"], '.', blacklist);
    secBurnCtl_generate_list(xmlitem["KeywordFilter"], ';', wordlist);

	secBurnCtl_log_run_info("import_xml end.");
    return CPolicy::import_xmlobj(xml);
}

/**
 * 函数名:sec_burn_ctl_init()
 * 说明:供外部调用的安全刻录控制策略的init函数
 *  	成功返回true，失败返回false；
 */
bool sec_burn_ctl_init(void)
{
	secBurnCtl_log_run_info("sec_burn_ctl_init start.");

    g_brasero_tmp_path = (char *)calloc(1, (LEN_FILE_NAME + 1)* sizeof(char));
    if(NULL == g_brasero_tmp_path)
    {
	    secBurnCtl_log_run_info("sec_burn_ctl_init:calloc err.");
        return false;
    }

    strncpy(g_brasero_tmp_path, "/tmp", LEN_FILE_NAME);    

    g_burn_tmp_file_full_path = (char *)calloc(1, (LEN_FILE_NAME + 1)*sizeof(char));
    if(NULL == g_burn_tmp_file_full_path)
    {
	    secBurnCtl_log_run_info("sec_burn_ctl_init:calloc err.");
        sec_burn_ctl_uninit();
        return false;
    }
    strncpy(g_burn_tmp_file_full_path, "/tmp/brasero_tmp_*", LEN_FILE_NAME);

    g_cd_dev_model = (char *)calloc(1, (LEN_STR_CD_DEV_MODEL + 1)*sizeof(char));
    if(NULL == g_cd_dev_model)
    {
	    secBurnCtl_log_run_info("sec_burn_ctl_init:calloc err.");
        sec_burn_ctl_uninit();
        return false;
    }

    g_cd_property = (char *)calloc(1, (LEN_STR_CD_PROPERTY + 1)*sizeof(char));
    if(NULL == g_cd_property)
    {
	    secBurnCtl_log_run_info("sec_burn_ctl_init:calloc err.");
        sec_burn_ctl_uninit();
        return false;
    }
    strncpy(g_cd_property, "optical_dvd_rw", LEN_STR_CD_PROPERTY); 
	
    g_cd_dev_name= (char *)calloc(1, (LEN_STR_CD_DEV_NAME + 1)*sizeof(char));
    if(NULL == g_cd_dev_name)
    {
	    secBurnCtl_log_run_info("sec_burn_ctl_init:calloc err.");
        sec_burn_ctl_uninit();
        return false;
    }

    /*读取刻录次数*/
    //secBurnCtl_read_burn_times(CSecBurnCtl *pPolicy);

#if defined(HW_X86)
    g_burn_info_file_name_X86 = (char *)calloc(1, (LEN_FILE_NAME + 1)*sizeof(char));
    if(NULL == g_burn_info_file_name_X86)
    {
        secBurnCtl_log_run_info("sec_burn_ctl_init:calloc err.");
        sec_burn_ctl_uninit();
        return false;
    }

    g_burn_state = CDBURN_STAT_INIT;

    memset(&g_file_check_md5, 0, sizeof(struct file_check_st));
#endif//HW_X86
    secBurnCtl_log_run_info("sec_burn_ctl_init end.");

    return true;
}

/**
 * 函数名:sec_burn_ctl_worker()
 * 说明:供外部调用的安全刻录控制策略的worker函数,完成安全刻录控制;
 *  	成功返回true，失败返回false；
 */
bool sec_burn_ctl_worker(CPolicy *pPolicy, void *pParam)
{
    if(POLICY_SEC_BURN != pPolicy->get_type())
    {
        return false;
    }
    (void)secBurnCtl_main((CSecBurnCtl*)pPolicy, pParam);
    return true;
}

/**
 * 函数名:sec_burn_ctl_uninit()
 * 说明:供外部调用的安全刻录策略的uninit函数,完成策略停止时的资源清理;
 */
void sec_burn_ctl_uninit()
{
	secBurnCtl_log_run_info("sec_burn_ctl_uninit start.");

	if(NULL != g_brasero_tmp_path)
	{
		secBurnCtl_log_run_info("sec_burn_ctl_uninit freeing g_brasero_tmp_path.");
		free(g_brasero_tmp_path);
		g_brasero_tmp_path = NULL;
	}

	if(NULL != g_burn_tmp_file_full_path)
	{
		secBurnCtl_log_run_info("sec_burn_ctl_uninit freeing g_burn_tmp_file_full_path.");
		free(g_burn_tmp_file_full_path);
		g_burn_tmp_file_full_path = NULL;
	}

	if(NULL != g_cd_dev_model)
	{
		secBurnCtl_log_run_info("sec_burn_ctl_uninit freeing g_cd_dev_model.");
		free(g_cd_dev_model);
		g_cd_dev_model = NULL;
	}

	if(NULL != g_cd_property)
	{
		secBurnCtl_log_run_info("sec_burn_ctl_uninit freeing g_cd_property.");
		free(g_cd_property);
		g_cd_property = NULL;
	}

	if(NULL != g_cd_dev_name)
	{
		secBurnCtl_log_run_info("sec_burn_ctl_uninit freeing g_cd_dev_name.");
		free(g_cd_dev_name);
		g_cd_dev_name= NULL;
	}

#if defined(HW_X86)
	if(NULL != g_burn_info_file_name_X86)
	{
		secBurnCtl_log_run_info("sec_burn_ctl_uninit freeing g_burn_info_file_name_X86.");
		free(g_burn_info_file_name_X86);
		g_burn_info_file_name_X86 = NULL;
	}
#endif//HW_X86

	IniFile cdrwini(g_burn_times_file_name);
	cdrwini.WriteString("SE_BURN", "BURN_TIMES", "0");
	cdrwini.Update();

	secBurnCtl_log_run_info("sec_burn_ctl_uninit end.");
}

/**
 * 函数名:secBurnCtl_main()
 * 说明:安全刻录部分的功能实现函数,完成刻录审计/控制功能;
 *  	成功返回0，失败返回其他值；
 *
 * pPolicy:输入参数，安全刻录控制类对象的指针;
 * pParam:输入参数;
 */
static int secBurnCtl_main(CSecBurnCtl *pPolicy, void *pParam)
{
    int can_burn_flag = 0;
    int ret = 0;
#ifndef HW_X86
    char tmp_path[512] = {0};
#endif//HW_X86
    char device_name[128] = { 0 };
    char cmd_rm[256] = {0};
    char cdDev_model_local[256] = {0};
    char cd_property_local[256] = {0};
    int can_burn_postfix = 0;
    int cannot_burn_postfix = 0;
    int cannot_burn_words = 0;
    char buf_log[256] = {0};
#if defined(HW_X86)
    char burn_info_file_name[256] = {0};
    char burn_file_name[512] = {0};
#endif//HW_X86

    ret = secBurnCtl_get_allow_flg(pPolicy, &can_burn_flag);
    if(0 != ret)
    {
        can_burn_flag = 0;
    }

    secBurnCtl_set_cd_dev_property(can_burn_flag);
        
    if(!can_burn_flag)
    {
        return 0;
    }
    
    pPolicy->burn_ret = CDBURN_INIT;

#if defined(HW_X86)
    if(0 == secBurnCtl_decide_check_x86())
#else
    if(secBurnCtl_detect_process(g_brasero_process_name) <= 0)
#endif//HW_X86
    {
        if(0 != strlen(g_burn_tmp_file_full_path))
        {
            memset(cmd_rm, 0, sizeof(cmd_rm));
            snprintf(cmd_rm, sizeof(cmd_rm), "/bin/rm  -fr  %s", g_burn_tmp_file_full_path);
            system(cmd_rm);
        }

        return 0;
    }

#ifndef HW_X86
    if(0 != secBurnCtl_get_brun_process_tmp_path())
    {
        return 0;
    }
    snprintf(tmp_path, sizeof(tmp_path), "%s/brasero_tmp_*", g_brasero_tmp_path);
    memset(g_burn_tmp_file_full_path, 0, LEN_FILE_NAME + 1);
    strncpy(g_burn_tmp_file_full_path, tmp_path, LEN_FILE_NAME);
#endif//HW_X86
    
#if defined(HW_X86)
    secBurnCtl_get_burn_file_name(g_burn_tmp_file_full_path, burn_file_name, sizeof(burn_file_name));
    if(strlen(burn_file_name) <= 0)
    {
        return 0;
    }
	snprintf(buf_log, sizeof(buf_log), "get brasero burn file name:%s", burn_file_name);
	secBurnCtl_log_run_info(buf_log);
    secBurnCtl_get_burn_file_info_x86(pPolicy, burn_file_name);
#else
    (void)secBurnCtl_get_burn_file_info(pPolicy, g_burn_tmp_file_full_path);
#endif//HW_X86

    /*获取刻录光驱设备名称*/ 
#if defined(HW_X86)
    g_burn_state = CDBURN_STAT_INIT;
    ret = secBurnCtl_get_burn_info_file_name(g_burn_tmp_file_full_path, burn_info_file_name, sizeof(burn_info_file_name));
    if(0 != ret)
    {
        return 0;
    }

    if( 0 != strcmp(burn_info_file_name, g_burn_info_file_name_X86)) 
    {
        snprintf(g_burn_info_file_name_X86, LEN_FILE_NAME + 1, "%s", burn_info_file_name);
	    snprintf(buf_log, sizeof(buf_log), "g_burn_info_file_name_X86 is changed to:%s", g_burn_info_file_name_X86);
	    secBurnCtl_log_run_info(buf_log);
    }
    
    strncpy(g_file_check_md5.file_name, g_burn_info_file_name_X86, LEN_FILE_NAME);

    ret = secBurnCtl_get_device_name_x86(g_burn_info_file_name_X86, device_name, sizeof(device_name));
    if (0 != ret)
    {
        if(g_burn_state < CDBURN_STAT_GEN_ISO_IMAGE)
        {
            return 0;
        }
    }
#else
    ret = secBurnCtl_get_device_name(device_name, sizeof(device_name));
    if (0 != ret)
    {
        return 0;
    }
#endif//HW_X86

	if(0 != strcmp(g_cd_dev_name, device_name))
    {
        strncpy(g_cd_dev_name, device_name, LEN_STR_CD_DEV_NAME);
    }
    
    if(0 == secBurnCtl_get_cdDevModel(g_cd_dev_name, cdDev_model_local, sizeof(cdDev_model_local)))
    {
        if(0 != strcmp(g_cd_dev_model, cdDev_model_local))
        {
            memset(g_cd_dev_model, 0, LEN_STR_CD_DEV_MODEL + 1);
            strncpy(g_cd_dev_model, cdDev_model_local, LEN_STR_CD_DEV_MODEL); 
			snprintf(buf_log, sizeof(buf_log), "cd dev model changed to :%s", g_cd_dev_model);
			secBurnCtl_log_run_info(buf_log);
        }
    }

    if(0 == secBurnCtl_get_cdProperty(g_cd_dev_name, cd_property_local, sizeof(cd_property_local)))
    {
        if(0 != strcmp(g_cd_property, cd_property_local))
        {
            memset(g_cd_property, 0, LEN_STR_CD_PROPERTY + 1);
            strncpy(g_cd_property, cd_property_local, LEN_STR_CD_PROPERTY); 
			snprintf(buf_log, sizeof(buf_log), "cd property changed to :%s", g_cd_property);
			secBurnCtl_log_run_info(buf_log);
        }
    }

    
    list<string>::iterator it_name;
    for (it_name = pPolicy->filelist.begin(); it_name != pPolicy->filelist.end(); it_name++)
    {
        can_burn_postfix = judge_list_exist(get_file_postfix((char*)(*it_name).c_str()), pPolicy->whitelist);
        cannot_burn_postfix = judge_list_exist(get_file_postfix((char*)(*it_name).c_str()), pPolicy->blacklist);
        // 文件名关键字过滤
        cannot_burn_words = judge_exist_keywords((char*)(*it_name).c_str(), pPolicy->wordlist);
        
        // 不允许刻录的情况
        if (((0 == can_burn_postfix) && ("" != pPolicy->xmlitem["ExtensionFilter"]))
            || (1 == cannot_burn_postfix) || (1 == cannot_burn_words))
        {
            int  can_burn_flag = 0;
            secBurnCtl_set_cd_dev_property(can_burn_flag);

            secBurnCtl_log_run_info("burn is not allowed:in case postfix/prefix/keywords.\n");

            string cmd = "fuser -km ";
            cmd = cmd + device_name;
            system(cmd.c_str());
            kill_process(g_brasero_process_name);

            secBurnCtl_show_dlg("您刻录的文件中包含违规文件，刻录失败");

            if (0 >= secBurnCtl_detect_process(g_brasero_process_name))
            {
                system("killall -9 -g brasero");
            }

            cmd = "eject ";
            cmd = cmd + device_name;
            system(cmd.c_str());

            cmd = "/bin/rm -rf ";
            cmd = cmd + g_burn_tmp_file_full_path;
            system(cmd.c_str());

            // 发送禁止刻录日志
            (void)secBurnCtl_report_evt(pPolicy, 0);

            return 1;
        }
    }

#if defined(HW_X86)
    (void)secBurnCtl_get_burn_ret_x86(pPolicy);
    if(CDBURN_INIT == pPolicy->burn_ret)
    {
        static int burn_process_wait_time = 0; 
        struct stat f_info = {0};

        if(secBurnCtl_detect_process(g_genisoimage_process_name) <= 0)
        {
            if(CDBURN_STAT_GEN_ISO_IMAGE != g_burn_state)
            {
                pPolicy->burn_ret = CDBURN_CANCELLED;
            }
			snprintf(buf_log, sizeof(buf_log), "genisoimage end:stat:%d", g_burn_state);
			secBurnCtl_log_run_info(buf_log);
        }
        
        ret = stat(g_burn_info_file_name_X86, &f_info);
        if(0 != ret)
        {
            if(ENOENT == errno)
            {
                burn_process_wait_time  = 0;   
                pPolicy->burn_ret = CDBURN_CANCELLED;
			    snprintf(buf_log, sizeof(buf_log), ":%s does not exist, brun ret is set to can el", g_burn_info_file_name_X86);
			    secBurnCtl_log_run_info(buf_log);
            }
        }
        else
        {
            if(file_unchanged(g_burn_info_file_name_X86))  
            {
                if(burn_process_wait_time < 60)
                {
                    burn_process_wait_time ++;    
			        snprintf(buf_log, sizeof(buf_log), "unchanged count:%d,stat:%d", burn_process_wait_time, g_burn_state);
			        secBurnCtl_log_run_info(buf_log);
                }
                else
                {
                    burn_process_wait_time  = 0;   
                    pPolicy->burn_ret = CDBURN_CANCELLED;
			        secBurnCtl_log_run_info("burn-info-file unchanged,burn ret is set to cancel");
                }
            }
        }
    }
#endif//HW_X86

    // 发送允许刻录日志需已将信息写入所需文件
    if (0 != pPolicy->pathlist.size() && CDBURN_INIT != pPolicy->burn_ret)
    {
        (void)secBurnCtl_report_evt(pPolicy, 1);

        // 这里已通过刻录审查，添加刻录次数
        if (0 != atoi(pPolicy->xmlitem["BurnNumber"].c_str()))
        {
            g_cur_burn_times ++;
            IniFile cdrwini(g_burn_times_file_name);
            cdrwini.WriteString("SE_BURN", "BURN_TIMES", int2str(g_cur_burn_times).c_str());
            cdrwini.Update();

			snprintf(buf_log, sizeof(buf_log), "burn times increased to:%d, allowed burn times is %s", g_cur_burn_times, pPolicy->xmlitem["BurnNumber"].c_str());
			secBurnCtl_log_run_info(buf_log);
        }
		
        /*delete these brasero tmp files every time we finished reporting burn event */
        memset(cmd_rm, 0, sizeof(cmd_rm));
        snprintf(cmd_rm, sizeof(cmd_rm), "/bin/rm -fr %s", g_burn_tmp_file_full_path);
        system(cmd_rm);
    }

    return 0; 
}

/**
 * 函数名:secBurnCtl_get_allow_flg()
 * 说明:根据策略设置，判断刻录策略允许标志,刻录时间/刻录次数是否合法,并设置刻录允许标志;
 *  	成功返回0，否则返回其他值；
 *
 * pPolicy:输入参数，安全刻录控制类对象的指针;
 * pAllow_flg:待更新的刻录允许标志;
 */
static int secBurnCtl_get_allow_flg(CSecBurnCtl *pPolicy, int *pAllow_flg)
{
    time_t timep;
    struct tm *ptm = NULL;
    char ltime[32] = {0};
    int i = 0;
    int val_week_day = 0;
    int bweek[8];
    int allow_flg = 1;

    if(NULL == pPolicy || NULL == pAllow_flg)
    {
        return -1;
    }

    time(&timep);
    ptm = localtime(&timep);
    snprintf(ltime, sizeof(ltime), "%02d:%02d", ptm->tm_hour, ptm->tm_min);

    if (0 == atoi(pPolicy->xmlitem["CanBurnFlag"].c_str()))
    {
        allow_flg = 0;
    }
    
    if ((0 != pPolicy->xmlitem["BurnBeginTime"].length() && 0 > strcmp(ltime, pPolicy->xmlitem["BurnBeginTime"].c_str()))
       || (0 != pPolicy->xmlitem["BurnEndTime"].length() && 0 < strcmp(ltime, pPolicy->xmlitem["BurnEndTime"].c_str())))
    {
        allow_flg = 0;
    }

    // 刻录次数已经达到最大限制不允许刻录
    if ((0 != atoi(pPolicy->xmlitem["BurnNumber"].c_str()))
         && (g_cur_burn_times >= atoi(pPolicy->xmlitem["BurnNumber"].c_str())))
    {
        allow_flg = 0;
    }

    val_week_day = atoi(pPolicy->xmlitem["BurnWeekDay"].c_str());
    for (i = 1; i < 8; i++)
    {
        bweek[i] = val_week_day % 2;
        val_week_day = val_week_day / 2;
    }
    bweek[0] = bweek[7];

    // 不在允许刻录的星期内不允许刻录
    if (1 != bweek[ptm->tm_wday])
    {
        allow_flg = 0;
    }

    *pAllow_flg = allow_flg;

    return 0;
}

/**
 * 函数名:secBurnCtl_set_cd_dev_property()
 * 说明:该函数根据刻录允许标志设置光驱设备的读写属性
 * can_burn_flag:允许刻录标志
 */
static void secBurnCtl_set_cd_dev_property(int can_burn_flag)
{
    if (1 == can_burn_flag)
    {
        system("chmod 660 /dev/sr*");
    }
    else
    {
        system("chmod 440 /dev/sr*");
    }
}

/**
 * 函数名:secBurnCtl_generate_list()
 * 说明:该函数根据原始信息和分割符生成对应的链表
 *     成功返回0；错误返回其他值；
 *srcInfo:输入的原始信息
 *delim:分割符
 *mylist:待生成的链表
 */
static int secBurnCtl_generate_list(string srcInfo, char delim, list <string> &mylist)
{
    string temp;
    stringstream ss(srcInfo);
    string sub_str;
    mylist.clear();

    if(0 == srcInfo.length())
    {
        return -1;
    }

    while (0 < getline(ss, sub_str, delim))
    {
        if (sub_str != "")
        {
            mylist.push_back(sub_str);
        }
    }
    return 0;
}

/**
 * 函数名:secBurnCtl_log_run_info()
 * 说明:该函数将策略运行信息写入log文件;
 */
static void secBurnCtl_log_run_info(const char *log_content)
{
	char log_info[2048] = {0};

	if(NULL == log_content)
	{
		return ;
	}
	
	snprintf(log_info, sizeof(log_info), "sec_burn_ctl:%s\n", log_content);

	g_GetlogInterface()->loglog(log_info);
}

/**
 * 函数名:secBurnCtl_detect_process()
 * 说明:该函数探测指定进程是否存在
 *      成功返回进程的id；失败返回-1；
 * process_name：用以检测的进程名
 */
int secBurnCtl_detect_process(const char *process_name)
{
    char ps[128] = { 0 };
    char buf[512] = { 0 };

    sprintf(ps, "ps -e | grep \'%s\' | awk \'{ print $1 }\'", process_name);
    FILE *fp = popen(ps, "r");
    if (NULL == fp)
    {
        return -1;
    }

    fgets(buf, sizeof(buf)-1, fp);
    pclose(fp);

    return atoi(buf);
}

#ifndef HW_X86
/**
 * 函数名:secBurnCtl_get_brun_process_tmp_path()
 * 说明:该函数获取刻录软件的临时工作目录
 *      成功返回0；失败返回其他；
 */
static int secBurnCtl_get_brun_process_tmp_path(void)
{
    char *p = NULL;
    char filename[256] = { 0 };

    FILE *fp = popen("lsof -Pnl +M -c brasero | awk \'{ print $9 }\' | grep \'brasero_tmp_\' ", "r");
    if (NULL != fp)
    {
        fgets(filename, 256, fp);
        pclose(fp);
    }
    else
    {
        return -1;
    }

    p = strrchr(filename, '/');
    if (NULL == p)
    {
        return -2;
    }
    *p = '\0';

    memset(g_brasero_tmp_path, 0, LEN_FILE_NAME + 1);
    strncpy(g_brasero_tmp_path, filename, LEN_FILE_NAME);

    return 0;
}

/**
 * 函数名:secBurnCtl_get_burn_file_info()
 * 说明:该函数获取所刻录文件的相关信息
 *      成功返回0；失败返回其他；
 * pPolicy:输入参数，安全刻录控制类对象的指针;
 * file_name:刻录的文件名
 */
static int secBurnCtl_get_burn_file_info(CSecBurnCtl *pPolicy, char file_name[])
{
    char buf[512] = { 0 };
    char path[512] = { 0 };
    char exc_path[512] = { 0 };
    char *index = NULL;
    char str_burn_cancel_flg[] = "Session cancelled";
    char str_burn_ok_flg[] = "Session successfully";
    FILE *fp = NULL;

    pPolicy->filelist.clear();
    pPolicy->pathlist.clear();

    string cmd = "cat ";
    cmd = cmd + file_name;

    fp = popen(cmd.c_str(), "r");
    if (NULL == fp)
    {
        return -1;
    }

    while (NULL != fgets(buf, sizeof(buf)-1, fp))
    {
        if (NULL != (index = strstr(buf, "URI = file://")))
        {
            sscanf(index + strlen("URI = file://"), "%[^\n]", path);//匹配非\n的任意字符
           
            sprintf(exc_path, "%s/brasero_tmp_", g_brasero_tmp_path);
            if (NULL == strstr(path, exc_path))// 排除掉生成临时文件
            {
                char final_path[1024] = { 0 };

                handle_uri(path, final_path);
                pPolicy->pathlist.push_back(final_path);
                pPolicy->filelist.push_back(basename(path));
            }
            memset(path, '\0', sizeof(path));
        }

        /*extract burn result info*/
        if(NULL != (strstr(buf, str_burn_cancel_flg))) 
        {
            pPolicy->burn_ret = CDBURN_CANCELLED;
            secBurnCtl_log_run_info("burn is cancelled by user");
        }

        if(NULL != (strstr(buf, str_burn_ok_flg))) 
        {
            pPolicy->burn_ret = CDBURN_OK;
            secBurnCtl_log_run_info("burn is ok");
        }
        
        memset(buf, '\0', sizeof(buf));
    }
    pclose(fp);

    return 0;
}
#endif//HW_X86

/**
 * 函数名:secBurnCtl_get_device_name()
 * 说明:该函数获取所刻录设备的名称
 *      成功返回0；失败返回其他；
 * pPolicy:输入参数，安全刻录控制类对象的指针;
 * device_name:带填充，刻录使用的光驱设备名
 * len:device_name缓冲区的大小；
 */
#if defined(HW_X86)
static int secBurnCtl_get_device_name_x86(char *file_name, char *device_name, int len)
#else
static int secBurnCtl_get_device_name(char *device_name, int len)
#endif//HW_X86
{
    char *index = NULL;
    char dev_name[256] = { 0 };
    char buf[256] = { 0 };
    char cmd[256] = { 0 };
    FILE  *fp = NULL; 

#if defined(HW_X86)
    snprintf(cmd, sizeof(cmd), "cat %s | grep 'Drive' | grep 'init result'", file_name);
#else
    snprintf(cmd, sizeof(cmd), "cat %s/brasero_tmp_* | grep 'Drive' | grep 'init result'", g_brasero_tmp_path);
#endif//HW_X86

    fp = popen(cmd, "r");
    if (NULL == fp)
    {
        return -1;
    }

    while (NULL != fgets(buf, sizeof(buf)-1, fp))
    {
        if (NULL != (index = strstr(buf, "/dev/sr")))
        {
            sscanf(index, "%s", dev_name);
            if(0 != strlen(dev_name))
            {
                dev_name[strlen(dev_name) - 1] = '\0';
                break;
            }
        }
        memset(buf, '\0', sizeof(buf));
    }
    pclose(fp);

    if (0 != strcmp(dev_name, ""))
    {
        strncpy(device_name, dev_name, len - 1);

        return 0;
    }

    return 1;
}

/**
 * 函数名:secBurnCtl_get_cdDevModel()
 * 说明:该函数获取刻录机型号
 * dev_name:刻录机使用的光驱设备名.
 * cd_dev_model:带填充，刻录机型号.
 * len:cd_dev_model缓冲区的大小；
 */
static int secBurnCtl_get_cdDevModel(const char *dev_name, char *cd_dev_model, int len)
{
    char cmd[128] = { 0 };
    char buf[512] = { 0 };
    char tmp_buf[256] = {0};
    char tmp_dev_model[256] = {0};

    if(NULL == dev_name || NULL == cd_dev_model || 0 == len)
    {
        return -1;
    }

    snprintf(cmd,  sizeof(cmd), "udisks --show-info %s | grep %s", dev_name, "  model:");
    FILE *fp = popen(cmd, "r");
    if (NULL == fp)
    {
        snprintf(cd_dev_model, len, "\"unknow device\"");
        return -1;
    }

    fgets(buf, sizeof(buf)-1, fp);
    pclose(fp);

    if(strlen(buf) <= 0)
    {
        snprintf(cd_dev_model, len, "\"unknow device\"");
        return -1;
    }
    
    /*
     * udisks cmd gives result looks like:
     *  model:    DVD-RW DVR-XD11
     *
     */
    sscanf(buf, "%s %s", tmp_buf, tmp_dev_model);

    if(strlen(tmp_dev_model) <= 0)
    {
        snprintf(cd_dev_model, len, "\"unknow device\"");
        return -1;
    }
    
    if(NULL == strstr(buf, tmp_dev_model))
    {
        snprintf(cd_dev_model, len, "\"unknow device\"");
        return -1;
    }

    snprintf(cd_dev_model, len, "%s", strstr(buf, tmp_dev_model));
    cd_dev_model[strlen(cd_dev_model) - 1] = '\0';

    return 0;
}

/**
 * 函数名:secBurnCtl_get_cdProperty()
 * 说明:该函数获取光盘属性
 * dev_name:刻录机使用的光驱设备名.
 * cd_property:带填充，光盘属性.
 * len:cd_property缓冲区的大小；
 */
static int secBurnCtl_get_cdProperty(const char *dev_name, char *cd_property, int len)
{
    char cmd[128] = { 0 };
    char buf[512] = { 0 };
    char tmp_buf[256] = {0};
    char tmp_cd_property[256] = {0};

    if(NULL == dev_name || NULL == cd_property || 0 == len)
    {
        return -1;
    }

    snprintf(cmd,  sizeof(cmd), "udisks --show-info %s | grep %s", dev_name, "'  media:'");
    FILE *fp = popen(cmd, "r");
    if (NULL == fp)
    {
        snprintf(cd_property, len, "\"unknow cd property\"");
        return -1;
    }

    fgets(buf, sizeof(buf)-1, fp);
    pclose(fp);
	
    if(strlen(buf) <= 0)
    {
        snprintf(cd_property, len, "\"unknow cd property\"");
        return -1;
    }
    
    /*
     * udisks cmd gives result looks like:
     *  media:   optical_cd_rw
     *
     */
    sscanf(buf, "%s %s", tmp_buf, tmp_cd_property);

    if(strlen(tmp_cd_property) <= 0)
    {
        snprintf(cd_property, len, "\"unknow cd property\"");
        return -1;
    }
    
    snprintf(cd_property, len, "%s", tmp_cd_property);

    return 0;
}

/**
 * 函数名:judge_list_exist()
 * 说明:该函数判断指定字符串是否在list中
 *    存在返回1;否则返回0；
 *
 * item:指定的字符串
 * mylist:字符串 list
 */
int judge_list_exist(string item, list<string> &mylist)
{
    list<string>::iterator it;
    for (it = mylist.begin(); it != mylist.end(); it++)
    {
        if (*it == item)
        {
            return 1;
        }
    }
    return 0;
}

/**
 * 函数名:get_file_postfix()
 * 说明:该函数获取并返回以字段字符串为名字的文件后缀名
 *
 * in_buf:输入的字符串
 */
char *get_file_postfix(char *in_buf)
{
    char *p = in_buf;
    while (*p != '\0')
    {
        if (*p == '.')
        {
            break;
        }
        p++;
    }
    //不包括"."
    p = p + 1;
    return p;
}

/**
 * 函数名:judge_exist_keywords()
 * 说明:该函数判断指定字符是否是列表中项的子串
 *    存在返回1;否则返回0；
 *
 * item:指定的字符串
 * mylist:字符串list
 */
int judge_exist_keywords(string item, list<string> &mylist)
{
    list<string>::iterator it;
    for (it = mylist.begin(); it != mylist.end(); it++)
    {
        if (item.find(*it) != string::npos)
        {
            return 1;
        }
    }
    return 0;
}

/**
 * 函数名:kill_process()
 * 说明:该函数通过shell命令kill指定进程；
 *    成功返回0;否则返回其他；
 *
 * process_name:要kill的进程名字
 */
int kill_process(char process_name[])
{
    char buf[128] = { 0 };
    string cmd = "pgrep -n ";
    cmd = cmd + process_name;
    FILE *fp = popen(cmd.c_str(), "r");
    if (NULL == fp)
    {
        return -1;
    }
    fgets(buf, sizeof(buf), fp);
    kill(atoi(buf), SIGINT);
    pclose(fp);
    return 0;
}

/**
 * 函数名:secBurnCtl_report_evt()
 * 说明:该函数将审计信息发送到服务器或者写入本地日志
 *      成功返回0；失败返回其他；
 * pPolicy:输入参数，安全刻录控制类对象的指针;
 * is_burn_allowed:本次刻录是否允许；
 */
static int secBurnCtl_report_evt(CSecBurnCtl *pPolicy, int is_burn_allowed)
{
    int i = 0;
    string pkt_data;
    string loc_data;
    std::list<string>::iterator it_path;
	tag_Policylog * plog = NULL;
	char buf_run_info[128] = {0};
    int ret = 0;

    for (it_path = pPolicy->pathlist.begin(); it_path != pPolicy->pathlist.end(); it_path++)
    {
        // 信息上报到服务器
        string content;
        secBurnCtl_creat_burn_content(pPolicy, content, (char*)((*it_path).c_str()), is_burn_allowed);
        if (1 == atoi(pPolicy->xmlitem["UpRegionService"].c_str()))
        {
            pkt_data = pkt_data + "Body" + int2str(i) + "=" + content + STRITEM_TAG_END;
            i++;
        }
        // 信息保存到本地
        if (1 == atoi(pPolicy->xmlitem["WriteLocalFile"].c_str()))
        {
            loc_data = loc_data + content + "\n";
        }
    }

    //要上报的信息上报到服务器
    if (1 == atoi(pPolicy->xmlitem["UpRegionService"].c_str()))
    {
        pkt_data = pkt_data + "BodyCount=" + int2str(i) + STRITEM_TAG_END;

		secBurnCtl_log_run_info(pkt_data.c_str());

		plog = (tag_Policylog *)malloc(sizeof(tag_Policylog) + pkt_data.length() + 1);
		if(NULL == plog)
		{
	        secBurnCtl_log_run_info("rpt to server:malloc err.");
			return -1 ;
		}

		memset(plog, 0, sizeof(tag_Policylog) + pkt_data.length() + 1);
		plog->type = AGENT_RPTAUDITLOG;		
		plog->what = AUDITLOG_REQUEST;
		strncpy(plog->log, pkt_data.c_str(), pkt_data.length());

		ret = report_policy_log(plog, 0);

		snprintf(buf_run_info, sizeof(buf_run_info), "rpt to server ret:%d", ret);
		secBurnCtl_log_run_info(buf_run_info);

		free(plog);
    }

    //要上报的信息保存到本地
    if (1 == atoi(pPolicy->xmlitem["WriteLocalFile"].c_str()))
    {
        secBurnCtl_save_burn_evt(loc_data);
    }

    return 0;
}

/**
 * 函数名:secBurnCtl_creat_burn_content()
 * 说明:该函数用来生成具体的审计日志信息
 *      成功返回0；失败返回其他；
 * pPolicy:输入参数，安全刻录控制类对象的指针;
 * content:输入参数，带填充，存放生成的审计信息;
 * burnfile:所刻录的文件;
 * is_burn_allowed:本次刻录是否允许；
 */
static int secBurnCtl_creat_burn_content(CSecBurnCtl *pPolicy, string &content, char burnfile[], int is_allowed)
{
    char buf[1024] = { 0 };
    char strtime[128] = { 0 };
    char strsize[128] = { 0 };
    string usrname;
    char ch_risk[8] = { 0 };
    char ch_action[8] = { 0 };
    char burn_result[256] = { 0 };

	YCommonTool::get_local_time(strtime);

    deal_file_size(get_file_size(burnfile), strsize);

    get_desk_user(usrname);
    if("" == usrname)
    {
        usrname.assign("root");
    }

    if (0 == is_allowed)    // 禁止
    {       
        sprintf(ch_action, "%d", Illegal_Behavior);   
        sprintf(ch_risk, "%d", Event_Alarm);
        strcpy(burn_result, "刻录失败");
    }
    else
    {
        sprintf(ch_action, "%d", General_Behavior);
        sprintf(ch_risk, "%d", Event_Message);

        if(CDBURN_OK == pPolicy->burn_ret) 
        {
            strcpy(burn_result, "刻录成功");
        }
        else if(CDBURN_CANCELLED == pPolicy->burn_ret)
        {
            sprintf(ch_action, "%d", Abnormal_Behavior);           
            strcpy(burn_result, "刻录操作被用户取消");
        }
    }

    snprintf(buf, sizeof(buf), "time=%s<>cid=15<>kind=1501<>policyid=%d<>policyname=%s<>KeyUserName=%s<>classaction=%s<>riskrank=%s<>context=[刻录机型号:%s,光盘属性:%s,刻录文件:%s,文件大小:%s,刻录结果: %s]",
        strtime, pPolicy->get_id(), pPolicy->get_name().c_str(), usrname.c_str(), ch_action, ch_risk,g_cd_dev_model, g_cd_property, burnfile, strsize, burn_result);

    content = buf;

	secBurnCtl_log_run_info(buf);

	secBurnCtl_log_run_info("build rpt info end.");

    return 0;
}

/**
 * 函数名:deal_file_size()
 * 说明:该函数将文件大小处理成合适的表达方式
 *      成功返回0；失败返回其他；
 * buf:待填充，存放格式化后的输出数据；
 * size:待处理的文件大小；
 */
int deal_file_size(unsigned int size, char buf[])
{
    float tmp;
    if (size >= (1024 * 1024 * 1024))
    {
        tmp = size / (1024.0*1024.0*1024.0);
        sprintf(buf, "%.2fGB", tmp);
    }
    else if (size >= (1024 * 1024))
    {
        tmp = size / (1024.0*1024.0);
        sprintf(buf, "%.2fMB", tmp);
    }
    else if (size >= 1024)
    {
        tmp = size / (1024.0);
        sprintf(buf, "%.2fKB", tmp);
    }
    else
    {
        sprintf(buf, "%d字节", size);
    }
    return 0;
}

/**
 * 函数名:get_file_size()
 * 说明:该函数获取文件大小
 *      返回文件大小；
 * path:文件名
 */
unsigned int get_file_size(const char *path)
{
    unsigned int filesize = 0;
    struct stat statbuff;

    if (stat(path, &statbuff) < 0)
    {
        return filesize;
    }
    else
    {
        filesize = statbuff.st_size;
    }

    return filesize;
}

#ifndef HW_X86
/**
 * 函数名:handle_uri()
 * 说明:该函数获完成对文件名的编码处理
 * input_str:输入文件路径
 * output_str:输出文件路径
 */
static int handle_uri(const char *input_str, char *output_str)
{
    //"/home/vrv-59%E4%B8%8B%E8%BD%BDvrv-59/vrv-59%E4%B8%8B%E8%BD%BD/%E4%B8%8B%E8%BD%BDvrv-59/%E4%B8%8B%E8%BD%BD/abc.doc";
    char src[1024] = { 0 };

    char *tok_str = NULL;
    char *check_str = NULL;
    char final_path[1024] = { 0 };

    strcpy(src, input_str);
    tok_str = strtok(src, "/");
    do
    {
        strcat(final_path, "/");

        check_str = strstr(tok_str, "%");
        if (check_str != NULL) // 处理字符转码工作
        {
            // 判断是否真有unicode中文
            if (check_str[0] == '%' || check_str[3] == '%' || check_str[6] == '%')
            {
                char output[1024] = { 0 };

                // 待转译字符掐头去尾
                if (tok_str[0] != '%' || tok_str[strlen(tok_str) - 3] != '%')
                {
                    if (tok_str[strlen(tok_str) - 3] == '%')    // 仅掐头，头先拷贝过去，再将屁股拷贝
                    {
                        char str_translate[1024] = { 0 };
                        strcpy(str_translate, check_str);
                        *check_str = '\0';
                        strcat(final_path, tok_str);
                        translate(str_translate, output);
                        strcat(final_path, output);
                    }
                    else if (tok_str[0] == '%')  // 仅去尾，先转译头，再分别拷贝
                    {
                        char str_translate[1024] = { 0 };
                        check_str = strrchr(tok_str, '%');
                        check_str += 3;
                        strcpy(str_translate, check_str);
                        *check_str = '\0';

                        translate(tok_str, output);
                        strcat(final_path, output);
                        strcat(final_path, str_translate);
                    }
                    else  // 掐头去尾
                    {
                        char *p = NULL;
                        char str_head[1024] = { 0 };
                        char str_tail[1024] = { 0 };
                        char str_translate[1024] = { 0 };

                        strcpy(str_head, tok_str);
                        p = strstr(str_head, "%");
                        *p = '\0';

                        strcpy(str_tail, tok_str);
                        p = strrchr(str_tail, '%');
                        p += 2;
                        *p = '\0';

                        p = strstr(tok_str, "%");
                        strcpy(str_translate, p);
                        p = strrchr(str_translate, '%');
                        p += 3;
                        *p = '\0';
                        translate(str_translate, output);

                        strcat(final_path, str_head);
                        strcat(final_path, output);
                        strcat(final_path, p);
                    }
                }
                else
                {
                    translate(tok_str, output);
                    strcat(final_path, output);
                }
            }
            else
            {
                strcat(final_path, tok_str);
            }
        }
        else
        {
            strcat(final_path, tok_str);
        }

        tok_str = strtok(NULL, "/");

    } while (NULL != tok_str);

    strcpy(output_str, final_path);

    return 0;
}

/**
 * 函数名:translate()
 * 说明:该函数获完成特殊字符的编码
 * input:输入文件路径
 * output:输出文件路径
 */
static int translate(const char *input, char *output)
{
    unsigned int i = 0;
    unsigned int j = 0;
    char dst[1024] = { 0 };
    unsigned char before[1024] = { 0 };

    // 去除掉所有%
    memset(dst, 0, sizeof(dst));
    for (i = 0, j = 0; i < strlen(input); i++)
    {
        if (input[i] != '%')
        {
            dst[j] = input[i];
            j++;
        }
    }

    // 将字符串转为数值
    memset(before, 0, sizeof(before));
    for (i = 0, j = 0; i<strlen(dst); i++)
    {
        if (dst[i] >= '0' && dst[i] <= '9')
        {
            if (i % 2 == 0)
            {
                before[i / 2] += (dst[i] - '0') * 16;
            }
            else
            {
                before[i / 2] += (dst[i] - '0');
            }
        }
        else if (dst[i] >= 'A' && dst[i] <= 'F')
        {
            if (i % 2 == 0)
            {
                before[i / 2] += (dst[i] - 'A' + 10) * 16;
            }
            else
            {
                before[i / 2] += (dst[i] - 'A' + 10);
            }
        }
    }
    strcpy(output, (const char*)before);

    return 0;
}
#endif//HW_X86

/**
 * 函数名:secBurnCtl_save_burn_evt()
 * 说明:该函数将要上报的刻录事件记录到本地文件
 * info:要记录的内容
 */
static int secBurnCtl_save_burn_evt(string info)
{
    FILE *fp = fopen(g_burn_evt_data, "a+");
    if (NULL == fp)
    {
        return -1;
    }

    fputs(info.c_str(), fp);
    fclose(fp);
    return 0;
}

/**
 * 函数名:secBurnCtl_show_dlg()
 * 说明:该函数显示信息提示框，超时或者按确定后关闭;
 */
static void secBurnCtl_show_dlg(const char *info)
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

/**
 * 函数名:secBurnCtl_read_burn_times()
 * 说明:该函数从本地文件读取刻录次数
 */
static void secBurnCtl_read_burn_times(CSecBurnCtl *pPolicy)
{
    string old_crc;
    string burn_times;
    char buf_log[256] = {0};

    IniFile cdrwini(g_burn_times_file_name);
    old_crc = cdrwini.ReadString("SE_BURN", "P_CRC");
    g_cur_policy_crc =  pPolicy->get_crc();

    if(strtoul(old_crc.c_str(), NULL, 10) == g_cur_policy_crc)
    {
        burn_times = cdrwini.ReadString("SE_BURN", "BURN_TIMES");
        g_cur_burn_times = atoi(burn_times.c_str());
        
        snprintf(buf_log, sizeof(buf_log), "brun times read:%s", burn_times.c_str());
	    secBurnCtl_log_run_info(buf_log);
    }
    else
    {
        char str_crc[65] = {0};
        char str_burn_times[32] = {0};

        g_cur_burn_times = 0;
        snprintf(str_burn_times, sizeof(str_burn_times), "%d", g_cur_burn_times);
        cdrwini.WriteString("SE_BURN", "BURN_TIMES", str_burn_times);
        
        snprintf(str_crc, sizeof(str_crc), "%u", g_cur_policy_crc);
        cdrwini.WriteString("SE_BURN", "P_CRC", str_crc);
        cdrwini.Update();

        snprintf(buf_log, sizeof(buf_log), "crc write to file:%s", str_crc);
	    secBurnCtl_log_run_info(buf_log);
    }
}

static string int2str(int &i)
{
    string s;
    stringstream str(s);
    str << i;
    
    return str.str();
}

#if defined(HW_X86)
static int secBurnCtl_get_burn_file_info_x86(CSecBurnCtl *pPolicy, char filename[])
{
    char buf[512]={0};
    char name[512]={0};
    char path[512]={0};

    if(0 == strcmp(filename,""))
    {
        return -1;
    }

    pPolicy->filelist.clear();
    pPolicy->pathlist.clear();

    string cmd = "cat ";
    cmd  = cmd + filename;
    FILE  *fp = popen(cmd.c_str(),"r");
    if(NULL == fp)
    {
        return -1;
    }

    while(NULL != fgets(buf,sizeof(buf)-1,fp))
    {
        sscanf(buf,"%[^=] %[^\n]",name,path);
        if(NULL==strstr(path,"/tmp/brasero_tmp_"))
        {
            printf("filelist:%s\n",name +1 );
            printf("pathlist:%s\n",path +1 );
            pPolicy->filelist.push_back(name+1);
            pPolicy->pathlist.push_back(path+1);
        }
        memset(name,'\0',sizeof(name));
        memset(path,'\0',sizeof(path));
        memset(buf,'\0',sizeof(buf));
    }
    pclose(fp);
    return 0;
}

static int secBurnCtl_get_burn_info_file_name(char *brasero_tmp_file_path, char *burn_info_file, int len)
{
    char buf[512] = {0};
    char cmd[512] = {0};
    FILE *pf_popen = NULL;
    struct stat f_info = {0};
    int ret = 0;
    int idx = 0;
    char buf_file[512] = {0};
    FILE *pf_fopen = NULL;
    char burn_info_file_tmp[256] = {0};
    int flg_found = 0;

    if(NULL == brasero_tmp_file_path || NULL == burn_info_file || 0 == len)
    {
	    secBurnCtl_log_run_info("secBurnCtl_get_burn_info_file_name:input ptr is NULL.");
        return -1;
    }

    snprintf(cmd, sizeof(cmd), "ls -1 %s", brasero_tmp_file_path); 
    pf_popen = popen(cmd, "r");
    if (NULL == pf_popen)
    {
	    secBurnCtl_log_run_info("secBurnCtl_get_burn_info_file_name:popen error.");
        return -1;
    }
    
    while(NULL != fgets(buf, sizeof(buf), pf_popen))
    {
        idx ++;    
        if(strlen(buf) <= 1)
        {
            continue;
        }
        buf[strlen(buf) - 1] = '\0';

        ret = stat(buf, &f_info);
        if(0 != ret)
        {
            continue;
        }

        if(S_ISREG(f_info.st_mode))
        {
            pf_fopen = fopen(buf, "r");     
            if(NULL == pf_fopen)
            {
                continue;
            }

            while(NULL != fgets(buf_file, sizeof(buf_file), pf_fopen))
            {
                if(strstr(buf_file, "Checking session consistency"))                
                {
                    printf("file found,idx:%d,name:%s\n", idx, buf);
                    snprintf(burn_info_file_tmp, sizeof(burn_info_file_tmp), "%s", buf); 
                    flg_found = 1; 
                    break;
                }
            }
                
            fclose(pf_fopen);
             
            if(flg_found)
            {
                break;
            }
        }
    }

    pclose(pf_popen);

    if(flg_found && 1 < strlen(burn_info_file_tmp))
    {
        snprintf(burn_info_file, len, "%s", burn_info_file_tmp); 
        return 0;
    }
    
    return -1;
}

static int  secBurnCtl_get_burn_ret_x86(CSecBurnCtl *pPolicy)
{
    char buf[512] = { 0 };
    char str_burn_ok_flg[] = "BraseroLibburn Finished successfully";
    char str_check_sum_file_flg[] = "BraseroChecksumFiles Finished track successfully";
    char str_gen_image_flg[] = "BraseroGenisoimage Finished track successfully";
    char str_check_sum_image_flg[] = "BraseroChecksumImage Finished track successfully";
    char str_burn_cancel_flg[] = "Session cancelled";
    //char str_sync_cache_flg[] = "BraseroLibburn syncing cache";
    char str_sync_cache_ok_flg[] = "BraseroLibburn Async SYNCHRONIZE CACHE succeeded";
    FILE *fp = NULL;
    
    string cmd = "cat ";
    cmd = cmd + g_burn_info_file_name_X86;

    fp = popen(cmd.c_str(), "r");
    if (NULL == fp)
    {
        return -1;
    }

    while (NULL != fgets(buf, sizeof(buf)-1, fp))
    {
        if(NULL != (strstr(buf, str_check_sum_file_flg))) 
        {
            g_burn_state = CDBURN_STAT_CHECKSUM_FILE;
            secBurnCtl_log_run_info("burn sate changes to CDBURN_STAT_CHECKSUM_FILE.");
        }

        if(NULL != (strstr(buf, str_gen_image_flg))) 
        {
            g_burn_state = CDBURN_STAT_GEN_ISO_IMAGE;
            secBurnCtl_log_run_info("burn sate changes to CDBURN_STAT_GEN_ISO_IMAGE.");
        }

        if(NULL != (strstr(buf, str_check_sum_image_flg))) 
        {
            g_burn_state = CDBURN_STAT_CHECKSUM_IMAGE;
            secBurnCtl_log_run_info("burn sate changes to CDBURN_STAT_CHECKSUM_IMAGE.");
        }

        if(NULL != (strstr(buf, str_burn_ok_flg))) 
        {
            g_burn_state = CDBURN_STAT_LIB_BURN;
            pPolicy->burn_ret = CDBURN_OK;
            secBurnCtl_log_run_info("burn is ok");
        }

        if(NULL != (strstr(buf, str_burn_cancel_flg))) 
        {
            pPolicy->burn_ret = CDBURN_CANCELLED;
            secBurnCtl_log_run_info("burn is cancelled.");
        }

        if(NULL != (strstr(buf, str_sync_cache_ok_flg))) 
        {
            pPolicy->burn_ret = CDBURN_OK;
            secBurnCtl_log_run_info("sync cache ok ,burn is ok");
        }
        
        memset(buf, '\0', sizeof(buf));
    }
    pclose(fp);

    return 0;
}

static int file_unchanged(const char *file_name)  
{
    char cmd[256] = {0};
    char buf[512] = {0};
    FILE *pf = NULL;
    int ret = 1;
    char md5_new_val[512] = {0};

    snprintf(cmd, sizeof(cmd), "md5sum %s", file_name);

    pf = popen(cmd, "r");
    if(NULL == pf)
    {
        return ret;
    }

    fgets(buf, sizeof(buf), pf);
    if(0 != strlen(buf))
    {
        memset(md5_new_val, 0, sizeof(md5_new_val));
        sscanf(buf, "%s", md5_new_val);
        
        if(0 == strcmp(file_name, g_file_check_md5.file_name) &&
           0 != strcmp(md5_new_val, g_file_check_md5.md5_val))
        {
            snprintf(g_file_check_md5.md5_val, LEN_STR_MD5 + 1, "%s", md5_new_val);
            
            ret = 0; 
        }
    }
    
    pclose(pf);

    return ret;
}

static int secBurnCtl_detect_process_x86(void)
{
    char filename[256] = { 0 };

    FILE *fp = popen("lsof -Pnl +M -c brasero | awk \'{ print $9 }\' | grep \'brasero_tmp_\' ", "r");
    if (NULL != fp)
    {
        fgets(filename, 256, fp);
        pclose(fp);
    }
    else
    {
        return -1;
    }

    if(0 < strlen(filename))
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

static int secBurnCtl_get_burn_file_name(char *brasero_tmp_file_path, char *burn_file_name, int len)
{
    char buf[512] = {0};
    char cmd[512] = {0};
    FILE *pf_popen = NULL;
    struct stat f_info = {0};
    int ret = 0;
    int idx = 0;
    char buf_file[512] = {0};
    FILE *pf_fopen = NULL;
    char burn_file_tmp[256] = {0};
    int flg_found = 0;

    if(NULL == brasero_tmp_file_path || NULL == burn_file_name || 0 == len)
    {
	    secBurnCtl_log_run_info("secBurnCtl_get_burn_file_name:input ptr is NULL.");
        return -1;
    }

    snprintf(cmd, sizeof(cmd), "ls -1 %s", brasero_tmp_file_path); 
    pf_popen = popen(cmd, "r");
    if (NULL == pf_popen)
    {
	    secBurnCtl_log_run_info("secBurnCtl_get_burn_file_name:popen error.");
        return -1;
    }
    
    while(NULL != fgets(buf, sizeof(buf), pf_popen))
    {
        idx ++;    
        if(strlen(buf) <= 1)
        {
            continue;
        }
        buf[strlen(buf) - 1] = '\0';
        ret = stat(buf, &f_info);
        if(0 != ret)
        {
            continue;
        }

        if(S_ISREG(f_info.st_mode))
        {
            pf_fopen = fopen(buf, "r");     
            if(NULL == pf_fopen)
            {
                continue;
            }

            while(NULL != fgets(buf_file, sizeof(buf_file), pf_fopen))
            {
                if(strstr(buf_file, ".checksum.md5="))                
                {
                    snprintf(burn_file_tmp, sizeof(burn_file_tmp), "%s", buf); 
                    flg_found = 1; 
                    break;
                }
            }
                
            fclose(pf_fopen);
             
            if(flg_found)
            {
                break;
            }
        }
    }

    pclose(pf_popen);

    if(flg_found && 1 < strlen(burn_file_tmp))
    {
        snprintf(burn_file_name, len, "%s", burn_file_tmp); 
        return 0;
    }
    
    return -1;
}


static int secBurnCtl_decide_check_x86(void)
{
    char cmd[128] = {0};
    char buf[512] = {0};
    FILE *pf_popen = NULL;
    int ret = 1;

    if(secBurnCtl_detect_process_x86() <= 0)
    {
        return 0;
    }

    snprintf(cmd, sizeof(cmd), "ls %s 2>/dev/null", g_burn_tmp_file_full_path); 
    pf_popen = popen(cmd, "r");
    if (NULL == pf_popen)
    {
	    secBurnCtl_log_run_info("secBurnCtl_decide_check_x86:popen error.");
        return 0;
    }

    fgets(buf, sizeof(buf), pf_popen);
    if(strlen(buf) <= 0)
    {
        ret = 0;
    }
    
    pclose(pf_popen);

    return ret; 
}
#endif//HW_X86

