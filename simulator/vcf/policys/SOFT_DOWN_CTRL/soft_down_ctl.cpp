
/**
 * soft_down_ctl.cpp
 *
 *  Created on: 2015-02-02
 *  Author: liu
 *
 *
 *  该文件包含了文件分发策略所需的所有函数；
 *
 */

using namespace std;

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
#include <dirent.h>
#include <iostream>
#include <errno.h>
#include "soft_down_ctl.h"
#include "../../../include/Markup.h"
#include "../../../include/MCInterface.h"
#include "../../VCFCmdDefine.h"
#include "../../vrvprotocol/VRVProtocol.hxx"
#include "../../common/Commonfunc.h"
#include "../../vrvprotocol/VrvProtocol.h"


/*本地宏定义*/
#ifndef EDPSERVER_PORT				
#define	EDPSERVER_PORT				88		//服务器监听端口
#endif//EDPSERVER_PORT				

#ifndef AGENT_DOWNLOADFILE			
#define	AGENT_DOWNLOADFILE			97		//请求下载文件
#endif//AGENT_DOWNLOADFILE			

#ifndef AGENT_DOWNLOADFINISH	
#define	AGENT_DOWNLOADFINISH		98		//文件下载结束
#endif//AGENT_DOWNLOADFINISH

#ifndef AGENT_GETDOWNLOADLIST		
#define	AGENT_GETDOWNLOADLIST		99
#endif//AGENT_GETDOWNLOADLIST

#define		DOWN_PATCH			0x01
#define		DOWN_SOFT			0x02
#define		DOWN_USERBIND		0x03

#ifndef VRV_TAG
#define	VRV_TAG		0x5652		//初始化pkt_head.mtag项
#endif//VRV_TAG

#ifndef VRV_FLAG	
#define	VRV_FLAG	0x56525620		//VRV1.0=0X56525620
#endif//VRV_FLAG	

#define		MAX_LEN		(1024 * 1024)		//限定每次下载文件长度为512

#define		FILE_TYPE_RPM			1		//rpm软件包
#define		FILE_TYPE_DEB			2		//deb软件包
#define		FILE_TYPE_CLT_UPDATE	3		//客户端升级包

#define FILE_POLICY_CRC	"/var/log/crc.txt"
#define CLIENT_UPDATE_FILE_PATH "/opt/edp_vrv/bin/updatefile/package"
#define CLIENT_UPDATE_PROGRAM_NAME "/opt/edp_vrv/bin/update"
#define FILE_DL_FILE_INFO "/var/log/softdown.txt"

typedef struct
{
    unsigned int m_flag;		//VRV版本
    unsigned short m_type;		//功能号，0表示成功，1表示失败
    unsigned short m_what;		//信息内容
    unsigned int m_pwd;		//加密秘钥或者加密版本
    unsigned int pkt_crc;		//CRC校验码
    unsigned int pkt_len;		//数据报总长度：包头+数据包
    unsigned short m_tag;		//默认置w为0x5652
    unsigned short m_size;		//包头长度，默认值为28
    unsigned int m_address;		//地址，预留选项，该版本无此功能
} pkt_head;

/*本地全局变量*/
static int g_policy_change = 0;
static int g_flg_repeat_run = 0;

/*外部函数声明*/
extern int code_convert(const char *from_charset,const char *to_charset,char *inbuf,int inlen,char *outbuf,int & outlen);

/*本地使用的函数声明*/
static void softDownCtl_log_run_info(const char *log_content);
static void softDownCtl_show_dlg(const char *info);
static void softDownCtl_rpt_evt_to_server(string logContent);
static void replaceAll(char * src, char oldChar, char newChar);
static void softDownCtl_set_policy_change_flg(int flg);
static void softDownCtl_set_repeat_run_flg(int flg);
static string softDownCtl_build_log_info(CSoftDownCtl *pMe, char *mode, char *state);
static void softDownCtl_retry_download_install(CSoftDownCtl *pMe);
static int softDownCtl_install(CSoftDownCtl *pMe, int file_type);

static void download_install_delete(CSoftDownCtl *pMe);
static int download_file(CSoftDownCtl *pMe);
static void softDownCtl_clt_update(CSoftDownCtl *pMe);
static enum crc_stat_e softDownCtl_get_crc_status(const char *crc_val);
static int delete_target_path (const char *targetpath );
//static int get_process(void);
//static int get_env_status (char *install_process_check);
static int install_check_up(char *filename,char *install_process_check);
static int softDownCtl_dl_file_not_exist(const char *filename);

/**
 * 类的构造方法
 */
CSoftDownCtl::CSoftDownCtl()
{
    enPolicytype type = SOFT_DOWN_CTRL;
	set_type(type);
	softDownCtl_log_run_info("constructor.");
}

/**
 * 类的析构函数
 */
CSoftDownCtl::~CSoftDownCtl()
{
    char buf_log[512] = {0};

    softDownCtl_log_run_info("destroy.");

    if(g_flg_repeat_run)
    {
        snprintf(buf_log, sizeof(buf_log), "destroy removing %s", FILE_POLICY_CRC);
        softDownCtl_log_run_info(buf_log);

        delete_target_path(FILE_POLICY_CRC);
    }
}

/**
 *父类虚函数实现：copy函数
 */
void CSoftDownCtl::copy_to(CPolicy * pDest)
{
	softDownCtl_log_run_info("copy_to_start.");

	memcpy(&(((CSoftDownCtl*)pDest)->m_policy), &m_policy, sizeof(struct policy_st));

   	CPolicy::copy_to(pDest);

    softDownCtl_set_policy_change_flg(1);
    softDownCtl_set_repeat_run_flg(m_policy.repeatdo);

	softDownCtl_log_run_info("copy_to end.");
}

/**
 *父类虚函数实现：策略导入函数
 */
bool CSoftDownCtl::import_xml(const char *pxml)
{
    char buf_policy[512] = {0};

    softDownCtl_log_run_info("import_xml start.");

    if(pxml == NULL)
    {
        softDownCtl_log_run_info("import_xml:pxml is null.");
        return false ;
    }

    CMarkup  xml ;
    if(!xml.SetDoc(pxml))
    {
        softDownCtl_log_run_info("import_xml:SetDoc failed.");
        return false ;
    }

    memset(&m_policy, 0, sizeof(struct policy_st));

    if(xml.FindElem("vrvscript"))
    {
        xml.IntoElem();
        std::string tmp_str;

        while(xml.FindElem("item"))
        {
            tmp_str = xml.GetAttrib("RunHidden");
            if(0 != tmp_str.length())//获取RunHidden属性值
            {
                m_policy.runhidden = (option)atoi(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "run_hidden:%d", m_policy.runhidden);
                softDownCtl_log_run_info(buf_policy);
            }

            tmp_str = xml.GetAttrib("IsSystem");
            if(0 != tmp_str.length())//获取IsSystem属性值
            {
                m_policy.issystem = (option)atoi(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "issystem:%d", m_policy.issystem);
                softDownCtl_log_run_info(buf_policy);
            }

            tmp_str = xml.GetAttrib("Run");
            if(0 != tmp_str.length())//获取Run属性值
            {
                m_policy.run = (option)atoi(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "run:%d", m_policy.run);
                softDownCtl_log_run_info(buf_policy);
            }

            tmp_str = xml.GetAttrib("Prompt");
            if(0 != tmp_str.length())//获取prompt 属性值
            {
                m_policy.prompt = (option)atoi(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "prompt:%d", m_policy.prompt);
                softDownCtl_log_run_info(buf_policy);
            }

            tmp_str = xml.GetAttrib("DeleteSource");
            if(0 != tmp_str.length())//获取DeleteSource 属性值
            {
                m_policy.deletesource = (option)atoi(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "DeleteSource:%d", m_policy.deletesource);
                softDownCtl_log_run_info(buf_policy);
            }

            tmp_str = xml.GetAttrib("RepeatDO");
            if(0 != tmp_str.length())//获取RepeatDO 属性值
            {
                m_policy.repeatdo = (option)atoi(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "RepeatDO:%d", m_policy.repeatdo);
                softDownCtl_log_run_info(buf_policy);
            }

            tmp_str = xml.GetAttrib("AutoSync");
            if(0 != tmp_str.length())//获取AutoSync属性值
            {
                m_policy.autosync = (option)atoi(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), ":AutoSync:%d", m_policy.autosync);
                softDownCtl_log_run_info(buf_policy);
            }

            tmp_str = xml.GetAttrib("FileCRC");
            if(0 != tmp_str.length())//获取FileCRC属性值
            {
                m_policy.filecrc = (option)atoi(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "FileCRC:%d", m_policy.filecrc);
                softDownCtl_log_run_info(buf_policy);
            }

            tmp_str = xml.GetAttrib("InstallOkTime");
            if(0 != tmp_str.length())//获取InstallOkTime属性值
            {
                m_policy.installoktime = atoi(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "InstallOkTime:%d", m_policy.installoktime);
                softDownCtl_log_run_info(buf_policy);
            }
            else
            {
                m_policy.installoktime = 15;
                softDownCtl_log_run_info("installOkTime:using default val:15");
            }

            tmp_str = xml.GetAttrib("ReDownIntervalTime");
            if(0 != tmp_str.length())//获取ReDownIntervalTime属性值
            {
                m_policy.redownintervaltime = atoi(tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "ReDownIntervalTime:%d", m_policy.redownintervaltime);
                softDownCtl_log_run_info(buf_policy);
            }
            else
            {
                m_policy.redownintervaltime = 60;
                softDownCtl_log_run_info("ReDownIntervalTime:using default val:60");
            }

            tmp_str = xml.GetAttrib("FileName");
            if(0 != tmp_str.length())//获取FileName属性值
            {
                snprintf(m_policy.filename, LEN_FILE_NAME+1, "%s", tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "FileName:%s", m_policy.filename);
                softDownCtl_log_run_info(buf_policy);
            }

            tmp_str = xml.GetAttrib("TargetPath");
            if(0 != tmp_str.length())//获取TargetPath属性值
            {
                snprintf(m_policy.targetpath, LEN_FILE_NAME+1, "%s", tmp_str.c_str());
                replaceAll(m_policy.targetpath,'\\','/');
                snprintf(buf_policy, sizeof(buf_policy), "TargetPath:%s", m_policy.targetpath);
                softDownCtl_log_run_info(buf_policy);
                if(m_policy.targetpath[0] != '/')
                {
                    snprintf(m_policy.targetpath, LEN_FILE_NAME+1, "/tmp/tmp");
                    softDownCtl_log_run_info("TargetPath:using default val:/tmp/tmp");
                }
            }
            else
            {
                snprintf(m_policy.targetpath, LEN_FILE_NAME+1, "/tmp/tmp");
                softDownCtl_log_run_info("TargetPath:using default val:/tmp/tmp");
            }

            tmp_str = xml.GetAttrib("CmdArgv");
            if(0 != tmp_str.length())//获取CmdArgv属性值
            {
                snprintf(m_policy.cmdargv , LEN_PARAM+1, "%s", tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "CmdArgv:%s", m_policy.cmdargv);
                softDownCtl_log_run_info(buf_policy);
            }

            tmp_str = xml.GetAttrib("RunMsg");
            if(0 != tmp_str.length())//获取RunMsg属性值
            {
                snprintf(m_policy.runmsg, LEN_TIP_MSG+1, "%s", tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "RunMsg:%s", m_policy.runmsg);
                softDownCtl_log_run_info(buf_policy);
            }

            tmp_str = xml.GetAttrib("InstallOkFileVersion");
            if(0 != tmp_str.length())//获取InstallOkFileVersion属性值
            {
                snprintf(m_policy.installokfileversion, LEN_STR_INSTALL_CHK_ITEM+1, "%s", tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "InstallOkFileVersion:%s", m_policy.installokfileversion);
                softDownCtl_log_run_info(buf_policy);
            }

            tmp_str = xml.GetAttrib("InstallOkFile");
            if(0 != tmp_str.length())//获取InstallOkFile属性值
            {
                snprintf(m_policy.installokfile, LEN_STR_INSTALL_CHK_ITEM+1, "%s", tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "InstallOkFile:%s", m_policy.installokfile);
                softDownCtl_log_run_info(buf_policy);
            }

            tmp_str = xml.GetAttrib("InstallOkProcess");
            if(0 != tmp_str.length())//获取InstallOkProcess属性值
            {
                snprintf(m_policy.installokprocess, LEN_STR_INSTALL_CHK_ITEM+1, "%s", tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "InstallOkProcess:%s", m_policy.installokprocess );
                softDownCtl_log_run_info(buf_policy);
            }

            tmp_str = xml.GetAttrib("LastUPFileAttr");
            if(0 != tmp_str.length())//获取LastUPFileAttr属性值
            {
                snprintf(m_policy.lastupfileattr, LEN_STR_INSTALL_CHK_ITEM+1, "%s", tmp_str.c_str());
                snprintf(buf_policy, sizeof(buf_policy), "LastUPFileAttr:%s", m_policy.lastupfileattr);
                softDownCtl_log_run_info(buf_policy);
            }
        }
        xml.OutOfElem();
    }

    softDownCtl_log_run_info("import_xml end.");
    return CPolicy::import_xmlobj(xml);
}

/**
 * 函数名:softDownCtl_log_run_info()
 * 说明:该函数将运行策略信息写入log文件;
 */
static void softDownCtl_log_run_info(const char *log_content)
{
	char log_info[2048] = {0};

	if(NULL == log_content)
	{
		return ;
	}
	
	snprintf(log_info, sizeof(log_info), "soft_down_ctl:%s\n", log_content);

	g_GetlogInterface()->loglog(log_info);
}

/**
 * 函数名:softDownCtl_show_dlg()
 * 说明:该函数显示信息提示框，超时或者按确定后关闭;
 */
static void softDownCtl_show_dlg(const char *info)
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
    pTips->defaultret = en_TipsGUI_None;
    pTips->pfunc = NULL;
    pTips->param.timeout = 3;//以秒为单位
    sprintf(pTips->szTitle,"确认");
    snprintf(pTips->szTips, sizeof(pTips->szTips), "%s", buf_convert_info);

    g_GetSendInterface()->sendto_Imc(VCF_CMD_GUI_TIPS, buffer, sizeof(tag_GuiTips));
}

/**
 * 函数名:soft_down_ctl_init()
 * 说明:供外部调用的普通文件分发策略的init函数;
 *  	成功返回true，失败返回false；
 */
bool soft_down_ctl_init(void)
{
    char cmd[512] = {0};
    char buf_log[512] = {0};
    struct stat f_info;
    int ret = 0;

    softDownCtl_log_run_info("init start");

    memset(&f_info, 0, sizeof(f_info));
    if(0 != lstat(CLIENT_UPDATE_FILE_PATH, &f_info))
    {
        snprintf(cmd, sizeof(cmd), "mkdir -p -v %s", CLIENT_UPDATE_FILE_PATH);
        ret = system(cmd);

        snprintf(buf_log, sizeof(buf_log), "%s does not exist, created with ret:%d.", CLIENT_UPDATE_FILE_PATH, ret);
        softDownCtl_log_run_info(buf_log);
    }

    softDownCtl_log_run_info("init end");

    return true;
}

static int getSO_ERROR(int fd) {
    int err = 1;
    socklen_t len = sizeof err;
    if (-1 == getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &len))
        g_GetlogInterface()->log_trace("error when get socket error\n");
    if (err)
        errno = err;              // set errno to the socket SO_ERROR
    return err;
}

static void closeSocket(int fd) {
    if (fd >= 0) {
        // first clear any errors, which can cause close to fail
        getSO_ERROR(fd); 
        // secondly, terminate the 'reliable' delivery
        if (shutdown(fd, SHUT_RDWR) < 0) {
            // SGI causes EINVAL
            if (errno != ENOTCONN && errno != EINVAL) {
                g_GetlogInterface()->log_trace("close socket error when shutdown\n");
            }
        }
        if (::close(fd) < 0) {
            g_GetlogInterface()->log_trace("inner close socket error\n");
        } 
    }
}


/**
 * 函数名:soft_down_ctl_worker()
 * 说明:供外部调用的普通文件分发策略的worker函数;
 *  	成功返回true，失败返回false；
 */
bool soft_down_ctl_worker(CPolicy *pPolicy, void *pParam)
{
    enum crc_stat_e crc_status = CRC_NOT_CHANGE; 
    char new_crc[256] = {0};
    CSoftDownCtl *pMe = (CSoftDownCtl*)pPolicy;

    if(NULL == pMe || SOFT_DOWN_CTRL != pPolicy->get_type())
    {
        softDownCtl_log_run_info("pme is null or policy type invalid.");
        return false;
    }

    snprintf(new_crc, sizeof(new_crc), "%u", pPolicy->get_crc());

    if(g_policy_change) 
    {
        softDownCtl_set_policy_change_flg(0);

        crc_status = softDownCtl_get_crc_status(new_crc);
        if(CRC_CHANGED == crc_status)
        {
            softDownCtl_log_run_info("before call download_install_delete");
            pMe->flg_dl_file_success = 0;
            pMe->retry_dl_time_count = 0;
            download_install_delete(pMe);
        }
    }
    else
    {
        if(pMe->dl_file_info.stat_ok)
        {
            if(!pMe->flg_dl_file_success && pMe->flg_dl_src_file_exist)
            {
                softDownCtl_retry_download_install(pMe);
            }
        }
    }

    return true;
}

/**
 * 函数名:soft_down_ctl_uninit()
 * 说明:供外部调用的普通文件分发策略的uninit函数,完成策略停止时的资源清理;
 */
void soft_down_ctl_uninit(void)
{
    softDownCtl_log_run_info("uninit");
}

static void replaceAll(char * src,char oldChar,char newChar)
{
    while(*src!='\0')
    {
        if(*src==oldChar) 
        {
            *src=newChar;
        }
        src++;
    }
}

static void softDownCtl_set_policy_change_flg(int flg)
{
    g_policy_change = flg;
}

static void softDownCtl_set_repeat_run_flg(int flg)
{
    char buf_log[512] = {0};

    snprintf(buf_log, sizeof(buf_log), "repeattodo:%d", flg);
    softDownCtl_log_run_info(buf_log);

    g_flg_repeat_run = flg;
}

/**
 *  Name:  delete_target_path
 *  Description:  调用shell中的"rm -rf "命令，递归删除 targetpath所指向目录及其目录下的
 *  							文件
 *
 */
static int delete_target_path (const char *targetpath )
{
    char delete_path[1024]={'\0'};
    char buf_log[512] = {0};
    int ret = 0;

    strcpy(delete_path,"rm -rf ");
    strcat(delete_path,targetpath);
    ret = system(delete_path);

    snprintf(buf_log, sizeof(buf_log), "removing %s ret:%d", targetpath, ret);
    softDownCtl_log_run_info(buf_log);

    return EXIT_SUCCESS;
}	

/**
 *  Name:  repatedo_crc_change
 *  Description:  判断本次crc校验码是否和上次一直。如果第一次执行下载程序，则将文件crc
 *  							校验码存放在/var/log/crc.txt中。如果不是第一次执行，则比较本次crc和上次crc，相
 *  							同返回8，不同返回9。
 *
 */
static enum crc_stat_e softDownCtl_get_crc_status(const char *crc_val)
{
		FILE *fd=NULL;	//存放/var/log/crc.txt的文件描述符
		char receive_ptr[1024]={'\0'};	//存放本次接收crc校验码
		char read_ptr[1024]={'\0'};	//存放上次crc校验码
		string read_string;
        enum crc_stat_e ret = CRC_NOT_CHANGE;

		strcpy(receive_ptr, crc_val);
		if(access(FILE_POLICY_CRC, F_OK)==0)
		{

            /*-----------------------------------------------------------------------------
             *  功能：从/var/log/crc.txt中读取上次文件校验码，并将新的文件校验码存放在crc.txt中，将
             *  			两次文件校验码相互比较，相一致返回8，不一致返回9。
             *-----------------------------------------------------------------------------*/
            fd=fopen(FILE_POLICY_CRC, "rb");
            if(NULL == fd)
            {
                return ret;
            }

            if(NULL == fgets(read_ptr,1023,fd))
            {
                softDownCtl_log_run_info("get-crc-status: fgets err.");
                fclose(fd);
                return ret;
            }
            fclose(fd);

            fd=fopen(FILE_POLICY_CRC, "wb");
            if(NULL == fd)
            {
                return ret;
            }

            fwrite(receive_ptr,strlen(receive_ptr),1,fd);
            fclose(fd);

            if(strcmp(read_ptr,receive_ptr)==0)
            {
                ret = CRC_NOT_CHANGE;
                softDownCtl_log_run_info("crc unchanged.");
            }
            else
            {
                ret = CRC_CHANGED;
                softDownCtl_log_run_info("crc changed.");
            }
		}
		else
		{
            fd=fopen(FILE_POLICY_CRC, "wb");
            if(NULL == fd)
            {
                return ret;
            }

            fwrite(receive_ptr,strlen(receive_ptr),1,fd);
            fclose(fd);
            ret = CRC_CHANGED;
            softDownCtl_log_run_info("crc file does not exist, crc changed.");
		}

        return ret;
}			

static int is_digit_str(const char *str)
{
    while(*str!='\0')
    {
        if(!isdigit(*str))
        {
            return 0;
        }
        str++;
    }
    return 1;
}

#if 0
static int get_process(void)
{
    DIR *directory_ptr = NULL;	//指向目录的指针	
    struct dirent *entry = NULL;	//指向dirent结构体的指针
    char path_buf[1024] = {0};	//存放进程路径
    int count = 0;	//存放readlink函数返回值
    char tmp[256] = {0};

    FILE *fp_ptr=fopen("/var/log/output.txt","w");
    if(NULL == fp_ptr)
    {
        return EXIT_FAILURE;
    }

    if((directory_ptr=opendir("/proc"))==NULL)
    {
        cout<<"open directory /proc failed!"<<endl;
        fclose(fp_ptr);
        return EXIT_FAILURE;
    }
    else
    {
        /*-----------------------------------------------------------------------------
		 *  功能：读取/proc目录下的数字目录（即进程所在目录），读取/proc/pid/exe获得进程
		 *  			软链接，存放在path_buf中，将path_buf中的内容输出到/var/log/output.txt中
         *-----------------------------------------------------------------------------*/
        while((entry=readdir(directory_ptr))!=NULL)
        {
            if(is_digit_str(entry->d_name))
            {
                fprintf(fp_ptr,"%s%s",entry->d_name,"*");
                strcpy(tmp,"/proc/");
                strcat(tmp,entry->d_name);
                strcat(tmp,"/exe");
                count=readlink(tmp,path_buf,1023);
                if(count<0)
                {
                    strcpy(path_buf,"--");
                }
                else
                {
                    path_buf[count]='\0';
                }
                fprintf(fp_ptr,"%s%s",path_buf,"\n");
            }
        }
        fclose(fp_ptr);
        closedir(directory_ptr);
    }
    return EXIT_SUCCESS;
}
#endif

#if 0
/**
 *  Name:  int get_env_status(char *install_process_check)
 *  Description:  判断进程是否运行，首先调用get_process()函数获得系统进程，并存放在
 *	/var/log/output.txt文件中。通过正则表达式过滤查找，读取$?环境变量判断是否查找成
 * 	功（0为查找成功，1为查找失败）。并返回环境变量$?的值，0表示查找的进程
 * 	正在运行，1表示查找的进程未运行。
 *
 */
static int get_env_status(char *install_process_check)
{
    char cmd[1024]={'\0'};	//存放进程查找shell命令
    char env_status;	//存放环境变量的值
    FILE *fd=NULL;	//文件描述符
    char log_buf[128] = {0};
    int ret = 0;

    if(get_process()==0)
    {
        sprintf(cmd,"grep %s /var/log/output.txt >/dev/null;echo $? > /var/log/output.txt",
                install_process_check);
        ret = system(cmd);
        snprintf(log_buf, sizeof(log_buf), "get_env_status:grep ret:%d", ret);
        softDownCtl_log_run_info(log_buf);

        fd=fopen("/var/log/output.txt","rb");
        if(NULL == fd)
        {
            softDownCtl_log_run_info("get_env_status,fopen err.");
            return 1;         
        }
                
        if(1 != fread(&env_status,sizeof(char),1,fd))
        {
            softDownCtl_log_run_info("get_env_status,fread err.");
            fclose(fd);
            return 1;         
        }

        fclose(fd);
        unlink("/var/log/output.txt");
        return atoi(&env_status);
    }
    else
    {
         perror("get process name");
         softDownCtl_log_run_info("get_env_status err.");
         return 1;         
    }
}		
#endif


//status: 0:off,1:on,-1:unknown
static int get_process_count(const char* processname, vector<pid_t> &pid_list)
{
    pid_t pid;
    FILE *fp;
    DIR *dir;
    struct dirent *next;
    char cmdline[PATH_MAX];
    char path[PATH_MAX];
    char *base_pname = (char*)basename(processname);
    if(strlen(base_pname) <= 0)  return -1;
    dir = opendir("/proc");
    if (!dir) {
        softDownCtl_log_run_info("opendir error");
        return -1;
    }
    while ((next = readdir(dir)) != NULL)
    {
        /* skip non-number */
        if (!isdigit(*next->d_name))
            continue;

        pid = strtol(next->d_name, NULL, 0);
        sprintf(path, "/proc/%u/status", pid);
        fp = fopen(path, "r");
        if(fp == NULL)
        {
            softDownCtl_log_run_info("open proc status error");
            continue;
        }
        memset(cmdline, 0, sizeof(cmdline));
        if(fgets(cmdline, PATH_MAX - 1, fp) == NULL)
        {
            fclose(fp);
            continue;
        }
        fclose(fp);
        if(NULL!=strstr(cmdline,base_pname))
        {
            pid_list.push_back(pid);
        }
    }
    closedir(dir) ;
    return pid_list.size();
}

/**
 *  Name:  install_check_up
 *  Description:  判断安装是否成功，如果filename所指向的文件和install_check_up所指向的进
 *  							程有一个存在，则安装成功，返回0。否则安装失败，返回-1。
 *
 */
static int install_check_up(char *filename,char *install_process_check)
{
    int ret_file_chk = -1;    //access函数返回值，0表示文件存在，-1表示文件不存在
    int ret_process_chk = -1; //get_env_status函数返回值，0表示进程正在运行，1表示进程未运行

    if(0 != strcmp("",filename))
    {
        ret_file_chk =access(filename,F_OK);
    }
    if(0 != strcmp("",install_process_check))
    {
        std::vector<pid_t> pid_lists;
        ret_process_chk = get_process_count(install_process_check, pid_lists);
    }
    if((0 == ret_file_chk)||(ret_process_chk > 0))
    {
        return 0;
    }

    return -1;
}

/*--------------------------------------------------------------------
 * 函数名：rpm_deb
 * 作者：王冲
 * 时间：3013/08/09
 * 描述：判断下载文件的类型（RPM，DEB）
 * 参数：无
 * 返回值：1 rpm型， 2 deb型,3 client update file.
*---------------------------------------------------------------------*/
static int rpm_deb( char *file_name)
{
    char *buf = NULL;

    /*功能：判断下载的文件为RPM型或deb型*/
    buf = strrchr(file_name, '.');
    if(NULL == buf)
    {
        softDownCtl_log_run_info("downloaded file is of unnormal type.");
        return 0;
    }
    else
    {
        if (strcasecmp(buf, ".RPM") == 0)
        {
            softDownCtl_log_run_info("downloaded file is of rpm type.");
            return FILE_TYPE_RPM;
        }
        if (strcasecmp(buf, ".DEB") == 0)
        {
            softDownCtl_log_run_info("downloaded file is of deb type.");
            return FILE_TYPE_DEB;
        }
        if (strcasecmp(buf, ".edpup") == 0)
        {
            softDownCtl_log_run_info("downloaded file is client update file.");
            return FILE_TYPE_CLT_UPDATE;
        }
    }

    return 0;
}

static void softDownCtl_retry_download_install(CSoftDownCtl *pMe)
{
    if(NULL == pMe)
    {
        return;
    }

    pMe->retry_dl_time_count ++;

    if(pMe->m_policy.redownintervaltime <= pMe->retry_dl_time_count)
    {
        pMe->retry_dl_time_count = 0;
        softDownCtl_log_run_info("retry download begin.");
        download_install_delete(pMe);
    }
}

/*--------------------------------------------------------------------
 * 函数名：download_install_delete
 * 作者：王冲
 * 时间：2013/08/09
 * 描述：下载文件安装文件，在安装成功后删除源文件
 * 参数：无
 * 返回值：flag
*---------------------------------------------------------------------*/
static void download_install_delete(CSoftDownCtl *pMe)
{
    char buf_log[512] = {0};
   
    pMe->m_policy.dl_file_type = rpm_deb(pMe->m_policy.filename);
    
    snprintf(buf_log, sizeof(buf_log), "file type(1:rpm,2:deb,3:clt-up):%d", pMe->m_policy.dl_file_type);
    softDownCtl_log_run_info(buf_log);

    if (download_file(pMe) == 0)
    {
        /*文件下载成功，设置成功标志*/
        pMe->flg_dl_file_success = 1;

        if(FILE_TYPE_CLT_UPDATE == pMe->m_policy.dl_file_type)
        {
            softDownCtl_log_run_info("downloaded file is for client update,calling update process.");
            softDownCtl_clt_update(pMe);
            return;
        }

        if(pMe->m_policy.run==RIGHT)
        {
            if (softDownCtl_install(pMe, pMe->m_policy.dl_file_type) == 0)
            {
                if(pMe->m_policy.deletesource==RIGHT)
                {
                    if (pMe->flg_delete_dir)
                    {
                        delete_target_path(pMe->m_policy.targetpath);
                    }
                    else
                    {
                        delete_target_path(pMe->dl_file_info.full_name);
                    }
                }
            }
        }
    }
}

/**
 *  函数名：get_dl_file_full_name
 *  作者：张峰堃
 *  时间：2012/06/04
 *  描述：获取安装文件的完整路径名
 *  返回值：成功返回0；否则返回其他
 */
static int get_dl_file_full_name(CSoftDownCtl *pMe)
{
    char *name = NULL;
    char *base_name  = NULL;
    char buf_log[512] = {0};
    char policy_filename[256] = {0};

    if(NULL == pMe)
    {
        return -1;
    }

    memset(&(pMe->dl_file_info), 0, sizeof(struct dl_file_info_st));

    snprintf(policy_filename, sizeof(policy_filename), "%s", pMe->m_policy.filename);

    replaceAll(policy_filename,'\\','/');

    name = strrchr(policy_filename, '/');		
    if(NULL != name)
    {
	    base_name = strtok(name, "/");	
        if(NULL != base_name)
        {
            snprintf(buf_log, sizeof(buf_log), "get dl-file-info,name, base_name:%s,%s",name, base_name);
            softDownCtl_log_run_info(buf_log);
            if(FILE_TYPE_CLT_UPDATE == pMe->m_policy.dl_file_type)
            {
                snprintf(pMe->dl_file_info.full_name, LEN_FILE_NAME + 1, "%s/%s", CLIENT_UPDATE_FILE_PATH, base_name );

            }
            else
            {
                snprintf(pMe->dl_file_info.full_name, LEN_FILE_NAME + 1, "%s/%s", pMe->m_policy.targetpath, base_name);
            }
            pMe->dl_file_info.stat_ok = 1;

            snprintf(buf_log, sizeof(buf_log), "get dl-file-info ok:%s", pMe->dl_file_info.full_name);
            softDownCtl_log_run_info(buf_log);
            return 0;
        }
    }
    
    softDownCtl_log_run_info("get dl-file-info fail");
    return -1;
}

/**
 *	函数名：send_pkt
 *	作者：张峰堃
 *	时间：2012/06/04
 *	描述：第一次调用send函数和服务器建立握手连接，第二次调用send函数发送sendbuf缓冲区中的数据
 *	参数：sockfd(文件描述符）,sendbuf(发送缓冲区),sendsize(发送长度),type(数据类型，宏定义AGENT_DOWNLOADFILE和AGENT_DOWNFINISH可选)
 *	返回值：发送成功返回0，发送失败返回-1
 */
static int send_pkt(int sockfd, char *sendbuf,unsigned int sendsize, int type, unsigned int pwd)
{
    int pktheadlength = sizeof(pkt_head);
    int len_send = 0;
    pkt_head pkthead;

    memset(&pkthead, 0, pktheadlength);

    pkthead.m_flag = VRV_FLAG;		//VRV1.0=0x56525620
    pkthead.m_type = type;		//类型，宏定义AGENT_DOWNLOADFILE和AGENT_DOWNFINISH可选
    pkthead.m_what = 0;		//包头，无数据内容
    //pkthead.m_pwd = 0;		//包头，无加密
    pkthead.m_pwd = pwd;      //包头，已加密 modified by donghx 2014.03.25
    pkthead.pkt_crc = 0;		//包头，无数据crc校验
    pkthead.m_tag = VRV_TAG;		//默认值，0x5652
    pkthead.m_size = pktheadlength;		//包头长度
    pkthead.m_address = 0;		//预留选项
    pkthead.pkt_len = pktheadlength + sendsize;		//包头+数据包长度

    /*-----------------------------------------------------------------------------
     *  功能：发送包头，建立握手连接
     *-----------------------------------------------------------------------------*/
    len_send = send(sockfd, &pkthead, pktheadlength, MSG_WAITALL);
    if(len_send != pktheadlength)
    {
        softDownCtl_log_run_info("send_pkt head err.");
        return -1;
    }

    /*-----------------------------------------------------------------------------
     *  功能：发送sendbuf中的数据
     *-----------------------------------------------------------------------------*/
    len_send = send(sockfd, sendbuf, sendsize, MSG_WAITALL);
    if((unsigned int)len_send != sendsize)
    {
        softDownCtl_log_run_info("send_pkt dat err.");
        return -1;
    }

    return 0;
}

/**
 *  函数名：recv_pkt
 *  作者：张峰堃
 *  时间：2012/06/04
 *  描述：接收数据，如果接收数据小于1M，直接存放在文件描述符fd所指向的文件，
 *        大于1M时，采取边读边写的方式下载文件（每次读写1M)
 *  参数：sockfd(接收socket),filename(用于保存接收文件）,offset(偏移量，扩展包和
 *  	    普通包的差值)
 *  返回值：接收成功返回0,失败返回-1
 */
static int  recv_pkt(int sockfd,const char *filename, int offset, unsigned int pwd) {
    int pktheadlength = 0;;
    pkt_head pkthead;
    char buf_log[512] = {0};
    char recvdata[MAX_LEN] = {0};
    int recv_len = 0;

    if(NULL == filename) {
        softDownCtl_log_run_info("input ptr is null, recv_pkt err.");
        return -1;
    }

    pktheadlength = sizeof(pkt_head) - offset;		//普通数据包头长度：扩展包头长度-偏移量

    if ((recv_len = recv(sockfd, &pkthead, pktheadlength, MSG_WAITALL)) == pktheadlength) {
        snprintf(buf_log, sizeof(buf_log), 
                "recv_pkt,recv head ok:recv-len, headlen->%d, %d",recv_len, pktheadlength);
        softDownCtl_log_run_info(buf_log);
        softDownCtl_log_run_info("recv_pkt,recv pkthead ok.");
    } else {
        snprintf(buf_log, sizeof(buf_log), "recv_pkt,recv head err:recv-len, headlen->%d, %d",recv_len, pktheadlength);

        int err = 1;
        socklen_t len = sizeof err;
        if (-1 == getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (char *)&err, &len)) {
            g_GetlogInterface()->log_trace("error when get socket error\n");
        }
        if (err) {
            errno = err;              // set errno to the socket SO_ERROR
        }
        char buf_[128] = {0};
        sprintf(buf_, "%s-%s %d", "error in recv head----> ", strerror(errno), errno);
        softDownCtl_log_run_info(buf_);

        softDownCtl_log_run_info(buf_log);
        return -1;
    }

    int datalength = pkthead.pkt_len - pktheadlength;
    int fd = open(filename, O_RDWR| O_CREAT| O_APPEND, 0664);
    if(fd == -1) {
        snprintf(buf_log, sizeof(buf_log), "recv_pkt, open %s err,code:%d", filename, errno);
        softDownCtl_log_run_info(buf_log);
        return -1;
    }

    snprintf(buf_log, sizeof(buf_log), "recv_pkt,datalen:%d",datalength);
    softDownCtl_log_run_info(buf_log);

    int d_size = datalength >= MAX_LEN ? MAX_LEN : datalength;
    while (datalength > 0) {
        int _inner_ret = -1;
        if((_inner_ret = recv(sockfd, recvdata, d_size, MSG_WAITALL)) != -1) {
            if (offset == 0 && pwd != 0) {
                if (!Decrypt_V1(pwd, (LPVOID)recvdata, (LPVOID)recvdata, _inner_ret, 0)) {
                    softDownCtl_log_run_info("recv_pkt,len>Max_len, decrypt err.");
                    close(fd);
                    return -1;
                } 
            }
            if(_inner_ret != write(fd, recvdata, _inner_ret)) {
                softDownCtl_log_run_info("recv_pkt,len>Max_len,decrypt,write dat err.");
                close(fd);
                return -1;
            }
            datalength -= _inner_ret;
        } else {
            char buf_[128] = {0};
            sprintf(buf_, "%s->%d inner_ret : %d", "recv_msg len:", datalength, _inner_ret);
            softDownCtl_log_run_info(buf_);

            softDownCtl_log_run_info("recv_pkt,len>Max_len, err1.");
            close(fd);
            return -1;
        }
    }
	close(fd);
    return 0;
}

static int download_file(CSoftDownCtl *pMe)
{
    string log_content;
    char mode[] = "0";
    char state[] = "0";
    char buf_log[512] = {0};
    
    if(0 != get_dl_file_full_name(pMe))
    {
        softDownCtl_log_run_info("get-dl-file-full-name err,downloadfile failed.");
        return -1;
    }

    if(access(pMe->dl_file_info.full_name ,F_OK) == 0)
	{
        mode[0] = '0';
        state[0] = '0';

        log_content = softDownCtl_build_log_info(pMe, mode, state);
        softDownCtl_rpt_evt_to_server(log_content);

        softDownCtl_log_run_info("downloadfile already exists, downloadfile fail.");

        return -1;
    }

    /*-----------------------------------------------------------------------------
     *  功能：获取服务器ip信息，存放于ip_buf缓冲区中
     *-----------------------------------------------------------------------------*/
    string str_server_ip;
	g_GetlcfgInterface()->get_lconfig(lcfg_srvip , str_server_ip);

    snprintf(buf_log, sizeof(buf_log), "downloadfile, svrip:%s", str_server_ip.c_str());
    softDownCtl_log_run_info(buf_log);

    /*-----------------------------------------------------------------------------
     *  功能：建立socket连接，连接服务器
     *-----------------------------------------------------------------------------*/
    int sockfd = 0;
    struct sockaddr_in serveraddr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        softDownCtl_log_run_info("downloadfile, create socket err.");
        return -1;
    }
    softDownCtl_log_run_info("downloadfile, create socket ok.");

    struct timeval tv;
    tv.tv_sec = 30; 
    tv.tv_usec = 0;

    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

#if 0
    struct linger s_linger;
    s_linger.l_onoff = 1;
    s_linger.l_linger = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &s_linger, sizeof(s_linger));
#endif

    bzero(&serveraddr, sizeof(serveraddr));

    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(EDPSERVER_PORT);
    serveraddr.sin_addr.s_addr = inet_addr(str_server_ip.c_str());

    if (connect(sockfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0)
    {
        softDownCtl_log_run_info("downloadfile, connect err.");
        //close(sockfd);    
        closeSocket(sockfd);
        return -1;
    }
    softDownCtl_log_run_info("downloadfile, connect ok.");

    char str_encrypt[1204] = {0};
    char filename[256+1]= {0};
    char filetype[256] = {0};

    string str_local_reg_ip;
	g_GetlcfgInterface()->get_lconfig(lcfg_regip , str_local_reg_ip);

    snprintf(buf_log, sizeof(buf_log), "downloadfile, local-ip:%s", str_local_reg_ip.c_str());
    softDownCtl_log_run_info(buf_log);

    strcpy(str_encrypt,"ActiveIPAddress=");
    strcat(str_encrypt, str_local_reg_ip.c_str());

    strcat(str_encrypt, STRITEM_TAG_END);
    sprintf(filetype, "Type=2%s", STRITEM_TAG_END);
    strncat(str_encrypt, filetype, sizeof(str_encrypt) - strlen(str_encrypt) - 1);
    sprintf(filename, "FILENAME=%s%s", pMe->m_policy.filename, STRITEM_TAG_END);
    strncat(str_encrypt, filename, sizeof(str_encrypt) - strlen(str_encrypt) - 1);
    strncat(str_encrypt, "Filepos=0", sizeof(str_encrypt) - strlen(str_encrypt) - 1);
    strncat(str_encrypt, STRITEM_TAG_END, sizeof(str_encrypt) - strlen(str_encrypt) - 1);

    int b_enc_length = strlen(str_encrypt);
    snprintf(buf_log, sizeof(buf_log), "downloadfile, str-encrypt:%s", str_encrypt);
    softDownCtl_log_run_info(buf_log);

    if (1 == get_pwd(sockfd, pMe->m_pwd))
    {
        snprintf(buf_log, sizeof(buf_log), "downloadfile,pwd: %u", pMe->m_pwd);
        softDownCtl_log_run_info(buf_log);

        if(0 != pMe->m_pwd)
        {
            if(!Encrypt_V1(pMe->m_pwd, (LPVOID)str_encrypt, (LPVOID)str_encrypt, strlen(str_encrypt), 0))
            {
                softDownCtl_log_run_info("downloadfile,decrypt pwd err.");
                //close(sockfd);
                closeSocket(sockfd);
                return -1;
            }
        }
        else
        {
            softDownCtl_log_run_info("downloadfile,pwd is zero, no need to encrypt.");
        }
    }
    else
    {
        softDownCtl_log_run_info("downloadfile, get_pwd err.");
        //close(sockfd);
        closeSocket(sockfd);
        return -1;
    }
    softDownCtl_log_run_info("downloadfile, get_pwd ok.");

    /*-----------------------------------------------------------------------------
     *  功能：发送包头，请求下载文件
     *-----------------------------------------------------------------------------*/

    if (send_pkt(sockfd, str_encrypt, b_enc_length, AGENT_DOWNLOADFILE, pMe->m_pwd) == 0)
    {
        softDownCtl_log_run_info("downloadfile,send download req ok.");
    }
    else
    {
        softDownCtl_log_run_info("downloadfile,send download req err.");
        //close(sockfd);
        closeSocket(sockfd);
        return -1;
    }

    /*-----------------------------------------------------------------------------
     *  功能：接收文件下载信息，存放在softdowm.txt中
     *-----------------------------------------------------------------------------*/
    struct stat f_info;
    if(0 == lstat(FILE_DL_FILE_INFO, &f_info))
    {
        unlink(FILE_DL_FILE_INFO);
        softDownCtl_log_run_info("downloadfile,old dl-file-info removed.");
    }

    if (recv_pkt(sockfd, FILE_DL_FILE_INFO , 0, pMe->m_pwd) == 0)
    {
        pMe->flg_dl_src_file_exist = 1;

        softDownCtl_log_run_info("downloadfile,recv download file info ok.");
        if(softDownCtl_dl_file_not_exist(FILE_DL_FILE_INFO))
        {
            char src_tip_buf[256] = {0};
            char dst_tip_buf[256] = {0};
            int dst_len = sizeof(dst_tip_buf);

            pMe->flg_dl_src_file_exist = 0;

            /*上报服务器*/
            mode[0] = '0';
            state[0] = '0';

            log_content = softDownCtl_build_log_info(pMe, mode, state);
            softDownCtl_rpt_evt_to_server(log_content);

            /*给出提示*/
            snprintf(src_tip_buf, sizeof(src_tip_buf), "您下载的文件:%s 不存在.", pMe->m_policy.filename);
            code_convert("utf-8", "gb2312", src_tip_buf, strlen(src_tip_buf), dst_tip_buf, dst_len);
            softDownCtl_show_dlg(dst_tip_buf);

            softDownCtl_log_run_info("downloadfile,src-file does not exist.");

    	    //close(sockfd);
            closeSocket(sockfd);
            return -1;
        }
    }
    else
    {
        softDownCtl_log_run_info("downloadfile,recv download file info err.");
    	//close(sockfd);
        closeSocket(sockfd);
        return -1;
    }

    /*-----------------------------------------------------------------------------
     *  功能：首先根据xml中解析出的客户端接收文件路径，创建对应文件夹。然后接收软
     *  件包，存放在SOFTNAME中
     *-----------------------------------------------------------------------------*/
    if(access(pMe->m_policy.targetpath,F_OK)==0)
    {
	    pMe->flg_delete_dir = 0;
        softDownCtl_log_run_info("downloadfile,target dir already exists.");
    }
    else
    {
        char cmdbuf[256];
        memset(cmdbuf, 0, sizeof(cmdbuf));
        sprintf(cmdbuf, "mkdir -p %s", pMe->m_policy.targetpath);
        system(cmdbuf);
        struct stat st;
        if(stat(pMe->m_policy.targetpath, &st) == -1) 
        {
            softDownCtl_log_run_info("downloadfile,target dir does not exist,create err.");
            return -1;
        }
        if((st.st_mode & S_IFMT) == S_IFDIR)
        {
	        pMe->flg_delete_dir = 1;
            softDownCtl_log_run_info("downloadfile,target dir does not exist,create ok.");
        }
        else
        {
            //close(sockfd);
            closeSocket(sockfd);
            softDownCtl_log_run_info("downloadfile,target dir does not exist,failed to create.");
            return -1;
        }
    }

    if (recv_pkt(sockfd,pMe->dl_file_info.full_name, 8, pMe->m_pwd) == 0)
    {
        mode[0] = '0';
        state[0] = '1';

        log_content = softDownCtl_build_log_info(pMe, mode, state);
        softDownCtl_rpt_evt_to_server(log_content);
	}
	else
	{	
        mode[0] = '0';
        state[0] = '0';

        log_content = softDownCtl_build_log_info(pMe, mode, state);
        softDownCtl_rpt_evt_to_server(log_content);

        softDownCtl_log_run_info("downloadfile ,recv file err.");

        if (pMe->flg_delete_dir)
        {
            delete_target_path(pMe->m_policy.targetpath); 
        }

        //close(sockfd);
        closeSocket(sockfd);
        return -1;
	}	

    softDownCtl_log_run_info("downloadfile ,recv file success.");
	//close(sockfd);
    closeSocket(sockfd);
    return 0;
}

/*-----------------------------------------------------------------------------
 *  函数名：install
 *  作者：张峰堃
 *  时间：2012/06/06
 *  描述：安装软件包
 *  参数：policy *（参数一），os(参数二：0为deb软件包，1为rpm软件包）
 *  返回值：0为下载成功，1为下载失败
 *-----------------------------------------------------------------------------*/
static int softDownCtl_install(CSoftDownCtl *pMe, int file_type)
{
    int time_count = 0;
    int install_status;
    char cmd_buf[256] = {0};	
    char mode[32]= "1";
    char state[32]= {0};
    string log_content;
    char log_buf[128] = {0};
    int ret = 0;

    softDownCtl_log_run_info("installing downloaded file start.");

    memset(cmd_buf, 0, sizeof(cmd_buf));
    /*-----------------------------------------------------------------------------
     *  功能：根据不同内型软件包，存放软件包名称和相关安装命令
     *-----------------------------------------------------------------------------*/
    switch (file_type)
    {
        case FILE_TYPE_DEB:
            snprintf(cmd_buf, sizeof(cmd_buf), "dpkg -i %s", pMe->dl_file_info.full_name);
            break;
        case FILE_TYPE_RPM:
            snprintf(cmd_buf, sizeof(cmd_buf), "rpm -Uvh --replacefiles %s", pMe->dl_file_info.full_name);
            break;
        default:
            snprintf(cmd_buf, sizeof(cmd_buf), "rpm -Uvh --replacefiles %s", pMe->dl_file_info.full_name);
            break;
    }
    
    if (pMe->m_policy.prompt == RIGHT) 
    {			
        softDownCtl_show_dlg(pMe->m_policy.runmsg);
    }

    ret = system(cmd_buf);
    snprintf(log_buf, sizeof(log_buf), "install downloaded file, ret:%d", ret);
    softDownCtl_log_run_info(log_buf);

    /*-----------------------------------------------------------------------------
     *  功能：若检测时间不为空，且检测文件或者检测进程选项有一个不为空，则进行安装
     *  			信息检测。只要安装文件或者运行进程有一个存在，则表明安装成功。否则判断
     *  			为安装失败。检测结果放入install_status中，1表示安装成功。-1表示安装失败。
     *-----------------------------------------------------------------------------*/
    if((pMe->m_policy.installoktime!=0)&&	
       ((0 != strcmp(pMe->m_policy.installokfile,""))||(0 != strcmp(pMe->m_policy.installokprocess,""))))
    {
        softDownCtl_log_run_info("checking installation...");
        if(pMe->m_policy.installoktime < 15)
        {
            pMe->m_policy.installoktime = 15;
        }

        time_count = 0;
        while(time_count < pMe->m_policy.installoktime)
        {
            time_count ++;
            sleep(1);
        }
					
        install_status = install_check_up(pMe->m_policy.installokfile,pMe->m_policy.installokprocess);
        if(0 == install_status)
        {
            state[0] = '1';
            softDownCtl_log_run_info("installing file success.");
        }
        else
        {
            state[0] = '0';
            softDownCtl_log_run_info("installing file err.");
        }

        log_content = softDownCtl_build_log_info(pMe, mode, state);
        softDownCtl_rpt_evt_to_server(log_content);
    }

    softDownCtl_log_run_info("installing downloaded file end.");
    return EXIT_SUCCESS;
}

static string softDownCtl_build_log_info(CSoftDownCtl *pMe, char *mode, char *state)
{
#define STR_MODE_DOWNLOAD "0"
#define STR_MODE_INSTALL "1"
#define STR_STATE_SUCESS "1"
#define STR_STATE_FAIL "0"
    string str_mode;
    string str_reply;
    string str_state;
    string str_time;
    string str_policy_id;
    char ch_policy_id[64] = {0};
    string file_name;
    string str_action;
    string str_risk;
    char str_audit_time[256]= {0};
    char ch_action[8] = { '\0' };
    char ch_risk[8] = { '\0' };
    string str_policy_name="文件分发";

    if(NULL == pMe || NULL == mode || NULL == state)
    {
        return "";
    }

    str_mode.assign(mode); 
    str_mode.append(STRITEM_TAG_END);

    snprintf(ch_policy_id, sizeof(ch_policy_id), "%d", pMe->get_id());
    str_policy_id.assign(ch_policy_id);

    file_name.assign(pMe->m_policy.filename);

	YCommonTool::get_local_time(str_audit_time);
    str_time.assign(str_audit_time);
    str_time.append(STRITEM_TAG_END);

    str_state.assign(state); 
    str_state.append(STRITEM_TAG_END);

    sprintf(ch_action, "%d", Abnormal_Behavior);
    str_action.assign(ch_action);

    sprintf(ch_risk, "%d", Event_Caution);
    str_risk.assign(ch_risk);

    str_reply.clear();
    str_reply+=STRITEM_TAG_END;
    str_reply+="Mode="+str_mode;
    str_reply+="P_ID="+ str_policy_id + STRITEM_TAG_END;
    str_reply+="PolicyName="+pMe->get_name()+STRITEM_TAG_END;

    str_reply+="FileName="+file_name+STRITEM_TAG_END;
    if(0 == strcmp(STR_MODE_DOWNLOAD, mode))
    {
	    softDownCtl_log_run_info("build download report info.");
        str_reply+="DownLoadTime="+str_time;
        str_reply+="DownLoadState="+str_state;
    }
    else if(0 == strcmp(STR_MODE_INSTALL, mode))
    {
	    softDownCtl_log_run_info("build install report info.");
        str_reply+="RunTime="+str_time;
        str_reply+="RunState="+str_state;
    }
    else
    {
	    softDownCtl_log_run_info("build other report info.");
        //not handled...
    }

    str_reply+= "classaction=" + str_action + STRITEM_TAG_END;
    str_reply+= "riskrank=" + str_risk + STRITEM_TAG_END;

	softDownCtl_log_run_info(str_reply.c_str());

	softDownCtl_log_run_info("build report info end.");

    return str_reply;
}

static void softDownCtl_rpt_evt_to_server(string logContent)
{
	tag_Policylog * plog = NULL;
	int ret = 0;
	char buf_run_info[128] = {0};

	/*审计信息上报服务器*/
	plog = (tag_Policylog *)malloc(sizeof(tag_Policylog) + logContent.length() + 1);
	if(NULL == plog)
	{
		softDownCtl_log_run_info("rpt to server:malloc err.");
		return ;
	}

	memset(plog, 0, sizeof(tag_Policylog) + logContent.length() + 1);
	plog->type = AGENT_RPTSOFTSTATUS;
	plog->what = 0;
	strncpy(plog->log, logContent.c_str(), logContent.length());

	ret = report_policy_log(plog, 0);
	snprintf(buf_run_info, sizeof(buf_run_info), "rpt to server ret:%d", ret);
	softDownCtl_log_run_info(buf_run_info);

	free(plog);
}

static void softDownCtl_clt_update(CSoftDownCtl *pMe)
{
    struct stat f_info; 
    char buf_log[512] = {0};
    char base_name[512] = {0};
    char cmd_buf[512] = {0};
    int ret = 0;

    if(NULL == pMe)
    {
	    softDownCtl_log_run_info("clt-update, pme is null.");
        return;
    }

    memset(&f_info, 0, sizeof(f_info));
    
    if(0 != lstat(pMe->dl_file_info.full_name, &f_info))
    {
        snprintf(buf_log, sizeof(buf_log), "%s does not exist.clt-upate failed.", pMe->dl_file_info.full_name);
	    softDownCtl_log_run_info(buf_log);
        return;
    }

    snprintf(base_name, sizeof(base_name), "%s", basename(pMe->dl_file_info.full_name));
    if(strlen(base_name) <= 0)
    {
        snprintf(buf_log, sizeof(buf_log), "clt-upate,extract basename from %s failed.", pMe->dl_file_info.full_name);
	    softDownCtl_log_run_info(buf_log);
        return;
    }

    memset(&f_info, 0, sizeof(f_info));
    if(0 != lstat(CLIENT_UPDATE_PROGRAM_NAME, &f_info))
    {
        snprintf(buf_log, sizeof(buf_log), "%s does not exist.clt-upate failed.", CLIENT_UPDATE_PROGRAM_NAME);
	    softDownCtl_log_run_info(buf_log);
        return;
    }

    snprintf(cmd_buf, sizeof(cmd_buf), "chmod +x %s", CLIENT_UPDATE_PROGRAM_NAME);
    ret = system(cmd_buf);
    snprintf(buf_log, sizeof(buf_log), "chmod +x %s: ret:%d",CLIENT_UPDATE_PROGRAM_NAME, ret);
	softDownCtl_log_run_info(buf_log);
    
    snprintf(cmd_buf, sizeof(cmd_buf), "%s %s &", CLIENT_UPDATE_PROGRAM_NAME, base_name);
    ret = system(cmd_buf);
    snprintf(buf_log, sizeof(buf_log), "exec %s: ret:%d",CLIENT_UPDATE_PROGRAM_NAME, ret);
	softDownCtl_log_run_info(buf_log);

	softDownCtl_log_run_info("call clt-update cmd end.");
}

static int softDownCtl_dl_file_not_exist(const char *filename)
{
    FILE *pf = NULL;
    char buf_log[512] = {0};
    char flg_file_size[] = "FILESIZE=-1";
    char flg_file_crc[] = "CRC=-1";
    char file_size[128] = {0};
    char file_crc[128] = {0};

    if(NULL == filename)
    {
        softDownCtl_log_run_info("check file existance:null ptr");
        return 0;
    }

    pf = fopen(filename, "r");
    if(NULL == pf)
    {
        snprintf(buf_log, sizeof(buf_log), "check file existance:file open err:code:%d",errno);
	    softDownCtl_log_run_info(buf_log);
        return 0;
    }

    if(NULL != fgets(file_size, sizeof(file_size), pf) && 0 != strlen(file_size)) 
    {
        snprintf(buf_log, sizeof(buf_log), "check file existance:file_size:%s",file_size);
	    softDownCtl_log_run_info(buf_log);

        if(NULL != fgets(file_crc, sizeof(file_crc), pf) && 0 != strlen(file_crc)) 
        {
            snprintf(buf_log, sizeof(buf_log), "check file existance:file_crc:%s", file_crc);
	        softDownCtl_log_run_info(buf_log);
        }

        if(0 == strncasecmp(file_size, flg_file_size, strlen(flg_file_size)) ||
           0 == strncasecmp(file_crc, flg_file_crc, strlen(flg_file_crc)))
        {
            fclose(pf);
            return 1;
        }
    }

    fclose(pf);

    return 0;
}
