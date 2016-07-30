#include "dev_install_ctrl.h"

#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/utsname.h>
#include "../../vrvprotocol/VRVProtocol.hxx"
#include "../../vrvprotocol/VRVProtocolEx.hxx"
#include "../../common/Commonfunc.h"
#include "../../vrcport_tool.h"
#include "../../VCFCmdDefine.h"
#include "../../../include/MCInterface.h"

using namespace std;

#define UEVENT_BUFFER_SIZE 2048
#define HARD_CTRL_INFO_PATH "/var/log/hard_info"

static unsigned int old_crcvalue;
static CDevInstallCtrl *g_pPolicyDevInstallCtrl=NULL;

static vector<PFORBIDDEN> vecModeSerialPort;
static vector<PFORBIDDEN> vecModeParallelPort;
static bool IsSPortForbidden;
static bool IsPPortForbidden;
static vector<string> not_handle;
static vector<string> enable; 
static vector<string> exclude;
static vector<string> usbhid;
static vector<string> enable_udisk;
static vector<usb_dev> mobile_hdd_list;
static bool IsReportUDiskOther;
static bool IsReportUDisk;
static bool IsReportBlueTooth;
static bool IsReportFloppy;

static void dev_install_log_run_info(const char *log_content);

void Report_Hardctrl_info(string str, int kind)
{
    string SysUserName;

    //YCommonTool::get_ttyloginUser("tty1", SysUserName);
    get_desk_user(SysUserName);
    if("" == SysUserName)
    {
        SysUserName="root";
    }
    char szTime[21]="";
    YCommonTool::get_local_time(szTime);

    char buffer[2048]={0};
    tag_Policylog *plog = (tag_Policylog *)buffer ;
    plog->type = AGENT_RPTAUDITLOG;
    plog->what = AUDITLOG_REQUEST;
    char *pTmp = plog->log ;
    sprintf(pTmp,"Body0=time=%s<>kind=%d<>policyid=%d<>policyname=%s<>KeyUserName=%s<>classaction=%d<>riskrank=%d<>context=%s%s%s%s"
    ,szTime
    ,kind
    ,g_pPolicyDevInstallCtrl->get_id()
    ,g_pPolicyDevInstallCtrl->get_name().c_str()
    ,SysUserName.c_str()
    ,Illegal_Behavior
    ,Event_Critical
    ,str.c_str()
    ,STRITEM_TAG_END
    ,"BodyCount=1"
    ,STRITEM_TAG_END);

    if("1" == g_pPolicyDevInstallCtrl->UpRegionService)
    {
        report_policy_log(plog);
    }
    if("1" == g_pPolicyDevInstallCtrl->WriteLocalFile)
    {
        if(-1 == access(HARD_CTRL_INFO_PATH,F_OK))
        {
            creat(HARD_CTRL_INFO_PATH,O_RDWR);
        }

        FILE *fp = NULL;
        string info = pTmp;//less audit_header//wdm
        if(NULL != (fp =fopen(HARD_CTRL_INFO_PATH,"a+")))
        {
            char *dst = new char[info.size()*2+1];
            if(dst==NULL)
	      	{
	      	    fclose(fp);
	      	    return;
	      	}
            strncpy(dst,info.c_str(),info.size());
            fwrite(dst,info.length(),1,fp);
            delete []dst;
            fclose(fp);
        }

    }
}

///-----------------------------------s&p port start-------------------------------------------
int enableDevice(const char* dev){
    if(dev == NULL)
        return -1;
    FILE *fd = NULL;
    char cmd[1024] = {0};
    char line[1024] = {0};
    char path[1024] = {0};
    int ret = 0;
    sprintf(cmd, "ls -l /dev/%s* | awk \'{print $10}\'",dev);
    fd = popen(cmd, "r");
    if(NULL != fd)
    {
        while(fgets(line, sizeof(line)-1, fd))
	{
	    memset(path, 0, sizeof(path));
	    strncpy(path, line, strlen(line)-1);
	    std::string named_srx = path;
	    if(std::string::npos != named_srx.find("_")) {
	        sprintf(cmd, "mv %s %s", named_srx.c_str(), 
			named_srx.substr(0, named_srx.find("_")).c_str());
	        system(cmd);
		printf("cmd %s\n", cmd);
		ret = 1;
	    }
	}
        pclose(fd);
	fd = NULL;
    }
    return ret;
}
int disableDevice(const char* dev) {
    if(dev == NULL) {
        return -1;
    }
    FILE *fd = NULL;
    char cmd[1024] = {0};
    char line[1024] = {0};
    char path[1024] = {0};
    int ret = 0;
    sprintf(cmd, "ls -l /dev/%s* | awk \'{print $10}\'",dev);
    fd = popen(cmd, "r");
    if(NULL != fd)
    {
        while(fgets(line, sizeof(line)-1, fd))
	{
	    memset(path, 0, sizeof(path));
	    strncpy(path, line, strlen(line) - 1);
	    std::string org_srx = path;
	    if(org_srx.find("_") != std::string::npos) {
	        printf("%s\n", " already named continue");
	        continue;
	    }
	    std::string srx = path;
	    srx.append("_");
	    sprintf(cmd, "mv %s %s", org_srx.c_str(), srx.c_str());
	    system(cmd);
	    printf("%s %s\n", " cmdbuf: ", cmd);
	    ret = 1;
	}
	pclose(fd);
	fd = NULL;
    }
    return ret;
}

int enableSerialPort() {
    if( enableDevice("ttyS") || enableDevice("cua") || enableDevice("ttyUSB")) {
        string content;
	content = "串行口设备被禁用";
	Report_Hardctrl_info(content,900);
    }
    return 0;
}
int disableSerialPort() {
    if( disableDevice("ttyS") || disableDevice("cua") || disableDevice("ttyUSB")) {
        string content;
	content = "串行口设备被启用";
	Report_Hardctrl_info(content,901);
    }
    return 0;
}

int enableParallelPort() {
    if( enableDevice("lp") || enableDevice("parport") ) {
        string content;
	content = "并行口设备被禁用";
	Report_Hardctrl_info(content,900);
    }
    return 0;
}
int disableParallelPort() {
    if( disableDevice("lp") || disableDevice("parport") ) {
        string content;
	content = "并行口设备被启用";
	Report_Hardctrl_info(content,901);
    }
    return 0;
}


void DeleteVecModeSerialPort()
{
    vector<PFORBIDDEN>::iterator iterttys = vecModeSerialPort.begin();
    PFORBIDDEN pfobd = NULL;
    for (; iterttys != vecModeSerialPort.end(); iterttys++)
    {
        pfobd = *iterttys;
        if (pfobd != NULL)
        {
            delete pfobd;
            pfobd = NULL;
        }
    }
    vecModeSerialPort.clear();
}

void DeleteVecModeParallelPort()
{
    vector<PFORBIDDEN>::iterator iterttys = vecModeParallelPort.begin();
    PFORBIDDEN pfobd = NULL;
    for (; iterttys != vecModeParallelPort.end(); iterttys++)
    {
        pfobd = *iterttys;
        if (pfobd != NULL)
        {
            delete pfobd;
            pfobd = NULL;
        }
    }
    vecModeParallelPort.clear();
}

int StartSerialPort()
{
    char Cmd[512] = {0};
    vector<PFORBIDDEN>::iterator iterttys = vecModeSerialPort.begin();
    PFORBIDDEN pfobd = NULL;
    for (; iterttys != vecModeSerialPort.end(); iterttys++)
    {
        pfobd = *iterttys;
        if (pfobd == NULL)
        {
            return -1;
        }
        snprintf(Cmd,512,"mv %s %s",pfobd->newFileName,pfobd->srcFileName);
        system(Cmd);
    }
    DeleteVecModeSerialPort();
    IsSPortForbidden = false;
    return 0;
}

int StartParallelPort()
{
    char Cmd[512] = {0};
    vector<PFORBIDDEN>::iterator iterttys = vecModeParallelPort.begin();
    PFORBIDDEN pfobd = NULL;
    for (; iterttys != vecModeParallelPort.end(); iterttys++)
    {
        pfobd = *iterttys;
        if (pfobd == NULL)
        {
            return -1;
        }
        snprintf(Cmd,512,"mv %s %s",pfobd->newFileName,pfobd->srcFileName);
        system(Cmd);
    }
    DeleteVecModeParallelPort();
    IsPPortForbidden = false;
    return 0;
}

int ForbiddenSPort(char *pPathFormat)
{
    char PathName[256] = {0};
    char newPathName[256] = {0};
    int i = 0;
    char Cmd[512]= {0};
    while(1)
    {
        snprintf(PathName,256,"%s%d",pPathFormat,i);
        if(access(PathName,F_OK) != 0)
        {
            break;
        }

        PFORBIDDEN fobd = new FORBIDDEN;
        if(fobd == NULL)
        {
            StartSerialPort();  //出错后恢复到之前的状态
            return -1;
        }
        strncpy(fobd->srcFileName,PathName,256);
        snprintf(newPathName,256,"%s%d_bac",pPathFormat,i);
        strncpy(fobd->newFileName,newPathName,256);
        //fobd->iMode = GetModeOfFile(&buf);
        //设置串口设备文件属性
        snprintf(Cmd,512,"mv %s %s",PathName,newPathName);
        system(Cmd);
        vecModeSerialPort.push_back(fobd);
        i++;
    }
    return 0;
}

int ForbiddenPPort(char *pPathFormat)
{
    char PathName[256] = {0};
    char newPathName[256] = {0};
    int i = 0;
    char Cmd[512]= {0};

    while(1)
    {
        snprintf(PathName,256,"%s%d",pPathFormat,i);
        if(access(PathName,F_OK) != 0)
        {
            break;
        }
        PFORBIDDEN fobd = new FORBIDDEN;
        if(fobd == NULL)
        {
            StartParallelPort();  //出错后恢复到之前的状态
            return -1;
        }
        strncpy(fobd->srcFileName,PathName,256);
        snprintf(newPathName,256,"%s%d_bac",pPathFormat,i);
        strncpy(fobd->newFileName,newPathName,256);
        //fobd->iMode = GetModeOfFile(&buf);
        //设置并口设备文件属性
        snprintf(Cmd,512,"mv %s %s",PathName,newPathName);
        system(Cmd);
        vecModeParallelPort.push_back(fobd);
        i++;
    }
    return 0;
}

int ForbiddenSerialPort()
{
    char buf[256] = {0};
    strncpy(buf,"/dev/ttyS",256);
    int ret = ForbiddenSPort(buf);
    if (ret != 0)
    {
        return ret;
    }
    strncpy(buf,"/dev/cua",256);
    ret = ForbiddenSPort(buf);
    if (ret != 0)
    {
        return ret;
    }
    IsSPortForbidden = true;
    return 0;
}

int ForbiddenParallelPort()
{
    char buf[256] = {0};
    strncpy(buf,"/dev/lp",256);
    int ret = ForbiddenPPort(buf);
    if (ret != 0)
    {
        return ret;
    }
    strncpy(buf,"/dev/parport",256);
    ret = ForbiddenPPort(buf);
    if (ret != 0)
    {
        return ret;
    }
    IsPPortForbidden = true;
    return 0;
}

void SPort_PPort_DoWork(string strSport, string strPPort)
{
    if(strSport == "false") {
        disableSerialPort();
    }
    else if (strSport == "true") {
        enableSerialPort();
    }
    else {
        ;
    }

    if (strPPort == "false") {
        disableParallelPort();
    }
    else if (strPPort == "true") {
        enableParallelPort();
    }
    else {
        ;
    }
}

///-----------------------------------s&p port   end-----------------------------------------

///-----------------------------------usb other device ctrl start--------------------------------
void Unload_mod(const char *mod_path, const char *usb_id)
{

    FILE *fp=NULL;
    char unbind_path[256] = { '\0' } ;

    snprintf(unbind_path, sizeof(unbind_path) - 1, "%s/unbind", mod_path);
    if ((fp = fopen(unbind_path, "wb")) != NULL)
    {
        fwrite(usb_id, strlen(usb_id), 1, fp);
        fclose(fp);
    }
}

int Disable_dev()
{
    DIR *usb_dp = NULL;
    DIR *mod_dp = NULL;
    struct dirent *usb_dirp = NULL;
    struct dirent *mod_dirp = NULL;
    char name[256] = { '\0' };
    const char *sysdir = "/sys/bus/usb/drivers/";

    if ((usb_dp = opendir(sysdir)) == NULL)
    {
        perror("Can't open /sys/bus/usb/drivers/ directory!\n");
        return 1;
    }
    while ((usb_dirp = readdir(usb_dp)) != NULL)
    {
        int found = 0;

        ///排除.和..目录
        if (!(strcmp(usb_dirp->d_name, ".") && strcmp(usb_dirp->d_name, "..")))
        {
            continue;
        }

        ///排除usb, hub, usbfs, usb-storage目录
        if (!(strcmp(usb_dirp->d_name, "usb") && strcmp(usb_dirp->d_name, "hub") &&
	      strcmp(usb_dirp->d_name, "usbfs") && strcmp(usb_dirp->d_name, "usb-storage") &&
	      strcmp(usb_dirp->d_name, "usbhid") && strcmp(usb_dirp->d_name, "btusb")))
        {
            continue;
        }

        ///比较排除列表,若在排除列表里则found
        for (vector<string>::iterator excl = exclude.begin(); excl != exclude.end(); excl++)
        {
            if (*excl == usb_dirp->d_name)
            {
                found = 1;
                break;
            }
        }

        ///如果模块需要例外，则continue
        if (found)
        {
            continue;
        }

        char subdir[256+32] = "/sys/bus/usb/drivers/";                   // sizeof(dirp->d_name) == 256,加长subdir空间,防止溢出

        ///构造模块目录路径
        strncat(subdir, usb_dirp->d_name, sizeof(subdir) - strlen(subdir) - 1);
        if ((mod_dp = opendir(subdir)) != NULL)
        {
            while ((mod_dirp = readdir(mod_dp)) != NULL)
            {
                ///排除.和..目录
                if (!(strcmp(mod_dirp->d_name, ".") && strcmp(mod_dirp->d_name, "..")))
                {
                    continue;
                }

                if (!(strcmp(mod_dirp->d_name, "bind") && strcmp(mod_dirp->d_name, "unbind")
                        && strcmp(mod_dirp->d_name, "module") && strcmp(mod_dirp->d_name, "uevent")
                        && strcmp(mod_dirp->d_name, "new_id") && strcmp(mod_dirp->d_name, "remove_id")))
                {
                    continue;
                }

                ///比较获得的名字是否为bus id
                strncpy(name, mod_dirp->d_name, sizeof(name) - 1);
                if ((name[0] >= '0') && (name[0] <= '9'))
                {
                    ///卸载之前先保存模块名称和bus_id到Enable列表
                    enable.push_back(string(usb_dirp->d_name) + "_" + string(mod_dirp->d_name));

                    ///对列表排序去重
                    sort(enable.begin(), enable.end());                                    //排序
                    enable.erase(unique(enable.begin(), enable.end()), enable.end());      //去重

                    ///卸载设备
                    Unload_mod(subdir, mod_dirp->d_name);
                    IsReportUDiskOther = true;
                    break;
                }
            }
            closedir(mod_dp);
        }
    }
    closedir(usb_dp);
    return 0;
}

int Enable_usbhid()
{
    FILE *fp = NULL;
    const char *usbhid_bindpth = "/sys/bus/usb/drivers/usbhid/bind";

    if (access(usbhid_bindpth, F_OK))
    {
        return 1;
    }

    ///usbhid unbinds中内容
    if ((fp = fopen(usbhid_bindpth, "wb")) != NULL)
    {
        for (vector<string>::iterator bus_id = usbhid.begin(); bus_id != usbhid.end(); bus_id++)
        {
            fwrite(bus_id->c_str(), bus_id->length(), 1, fp);
	    fflush(fp);
            usbhid.erase(bus_id);
            bus_id--;       ///被删除元素之后的内容会自动往前移，导致迭代漏项，应在删除一项后itor--，使之从已经前移的下一个元素起继续遍历
	    IsReportUDiskOther = true;
        }
        fclose(fp);
	//system("/usr/sbin/lsusb");  
	system("lspci | grep \'USB\'");          /// 探测USB接口, 使启用生效
    }
    return 0;
}

int Enable_dev()
{
    const char *sysdir = "/sys/bus/usb/drivers";
    char *devname = NULL;                                       ///存储设备模块名
    char *bus_id = NULL;                                      ///存储bind string, Example:  2-0:1-0
    char subdir[256+32] = { '\0' };                             /// sizeof(dirp->d_name) == 256,加长subdir空间,防止溢出
    FILE *fp=NULL;

    for (vector<string>::iterator ena = enable.begin(); ena != enable.end(); ena++)
    {
        string usbdev = *ena;

        ///提取在enable容器中保存的设备驱动名称和bus_id
        devname = strtok((char *)usbdev.c_str(), "_");
        bus_id = strtok(NULL, "_");
        snprintf(subdir, sizeof(subdir) - 1, "%s/%s/bind", sysdir, devname);
        if ((fp = fopen(subdir, "wb")) != NULL)
        {
            fwrite(bus_id, strlen(bus_id), 1, fp);
            fclose(fp);
	    IsReportUDiskOther = true;
        }
        enable.erase(ena);
        ena--;       ///被删除元素之后的内容会自动往前移，导致迭代漏项，应在删除一项后itor--，使之从已经前移的下一个元素起继续遍历
        system("/usr/sbin/lsusb");              ///探测USB接口，使启用生效
    }
    Enable_usbhid();            ///启用USBHID设备
    return 0;
}

#if 0
int Get_content_of_usb_storage(vector<string> &exclude)
{

    DIR *dp;
    char *module_name;
    struct dirent *dirp;
    struct utsname unamebuf;

    if (uname(&unamebuf) < 0)
    {
        perror("Can't get the version of kernel!\n");
        return 1;
    }

    ///获得storage文件夹内容
    char storage[512] = { '\0' };
    snprintf(storage, sizeof(storage) - 1, "/lib/modules/%s/kernel/drivers/usb/storage/", unamebuf.release);//what

    if ((dp = opendir(storage)) == NULL)
    {
        perror("Can't open /lib/modules/***/kernel/drivers/usb/storage directory!\n");
        return 1;
    }
    while ((dirp = readdir(dp)) != NULL)
    {
        ///排除.和..目录
        if (!(strcmp(dirp->d_name, ".") && strcmp(dirp->d_name, "..")))
            continue;

        module_name = strtok(dirp->d_name, ".");      ///去掉模块后缀.ko, notice: strtok not thread safe.
        exclude.push_back(string(module_name));
    }

    closedir(dp);
    return 0;

}
#endif

int Enable_not_handle_dev()
{
    const char *sysdir = "/sys/bus/usb/drivers";
    char *devname = NULL;                                       ///存储设备模块名
    char *bus_id = NULL;                                      ///存储bind string, Example:  2-0:1-0
    char subdir[256+32] = { '\0' };                             /// sizeof(dirp->d_name) == 256,加长subdir空间,防止溢出
    FILE *fp = NULL;

    for (vector<string>::iterator handle = not_handle.begin(); handle != not_handle.end(); handle++)
    {
        string usbdev = *handle;
        ///提取在not_handle容器中保存的设备驱动名称和bus_id
        devname = strtok((char *)usbdev.c_str(), "_");
        bus_id = strtok(NULL, "_");

        snprintf(subdir, sizeof(subdir) - 1, "%s/%s/bind", sysdir, devname);
        if ((fp = fopen(subdir, "wb")) != NULL)
        {
            fwrite(bus_id, strlen(bus_id), 1, fp);
            fclose(fp);
        }
        not_handle.erase(handle);
        handle--;       ///被删除元素之后的内容会自动往前移，导致迭代漏项，应在删除一项后itor--，使之从已经前移的下一个元素起继续遍历
        system("/usr/sbin/lsusb");              ///探测USB接口，使启用生效
    }
    return 0;
}

int Disable_usbhid()
{
    DIR *usbhid_dp = NULL;                                      /// /sys/bus/usb/drivers/ 的目录指针
    struct dirent *usbhid_dirp = NULL;                          /// 存储/sys/bus/usb/drivers 目录内容, 即模块名称
    char name[256] = { '\0' };
    const char *usbhid_dir = "/sys/bus/usb/drivers/usbhid/";

    if ((usbhid_dp = opendir(usbhid_dir)) == NULL)
    {
        // perror("Can't open /sys/bus/usb/drivers/usbhid directory!\n");
        return 1;
    }
    while ((usbhid_dirp = readdir(usbhid_dp)) != NULL)
    {
        ///排除.和..目录
        if (!(strcmp(usbhid_dirp->d_name, ".") && strcmp(usbhid_dirp->d_name, "..")))
        {
            continue;
        }

        if (!(strcmp(usbhid_dirp->d_name, "bind") && strcmp(usbhid_dirp->d_name, "unbind")
                && strcmp(usbhid_dirp->d_name, "module") && strcmp(usbhid_dirp->d_name, "uevent")
                && strcmp(usbhid_dirp->d_name, "new_id") && strcmp(usbhid_dirp->d_name, "remove_id")))
        {
            continue;
        }

        ///比较获得的名字是否为bus id
        strncpy(name, usbhid_dirp->d_name, sizeof(name) - 1);
        if ((name[0] >= '0') && (name[0] <= '9'))
        {
            ///卸载之前保存bus_id到usbhid列表
            usbhid.push_back(string(usbhid_dirp->d_name));

            ///对列表排序去重
            sort(usbhid.begin(), usbhid.end());                                    //排序
            usbhid.erase(unique(usbhid.begin(), usbhid.end()), usbhid.end());      //去重

            ///卸载设备
            Unload_mod(usbhid_dir, usbhid_dirp->d_name);
            IsReportUDiskOther = true;
        }
    }
    closedir(usbhid_dp);
    return 0;
}

int Not_handle_save_mod(vector<string> &not_handle)
{
    DIR *usb_dp = NULL;
    DIR *mod_dp = NULL;
    struct dirent *usb_dirp = NULL;
    struct dirent *mod_dirp = NULL;
    char name[256] = { '\0' };
    const char *sysdir = "/sys/bus/usb/drivers/";

    if ((usb_dp = opendir(sysdir)) == NULL)
    {
        perror("Can't open /sys/bus/usb/drivers/ directory!\n");
        return 1;
    }
    while ((usb_dirp = readdir(usb_dp)) != NULL)
    {
        int found = 0;

        ///排除.和..目录
        if (!(strcmp(usb_dirp->d_name, ".") && strcmp(usb_dirp->d_name, "..")))
        {
            continue;
        }

        ///排除usb, hub, usbfs, usb-storage目录
        if (!(strcmp(usb_dirp->d_name, "usb") && strcmp(usb_dirp->d_name, "hub") &&
                /*strcmp(usb_dirp->d_name, "usbfs") &&*/ strcmp(usb_dirp->d_name, "usb-storage")))
        {
            continue;
        }

        ///比较排除列表,若在排除列表里则continue
        for (vector<string>::iterator excl = exclude.begin(); excl != exclude.end(); excl++)
        {
            if ((*excl == usb_dirp->d_name) && (*excl != "usbhid"))
            {
                found = 1;
                break;
            }
        }
        ///如果找到, continue
        if (found)
        {
            continue;
        }
        char subdir[256+32] = "/sys/bus/usb/drivers/";                   // sizeof(dirp->d_name) == 256,加长subdir空间,防止溢出
        ///构造模块目录路径
        strncat(subdir, usb_dirp->d_name, sizeof(subdir) - strlen(subdir) - 1);
        if ((mod_dp = opendir(subdir)) != NULL)
        {
            while ((mod_dirp = readdir(mod_dp)) != NULL)
            {
                ///排除.和..目录
                if (!(strcmp(mod_dirp->d_name, ".") && strcmp(mod_dirp->d_name, "..")))
                {
                    continue;
                }

                if (!(strcmp(mod_dirp->d_name, "bind") && strcmp(mod_dirp->d_name, "unbind")
                        && strcmp(mod_dirp->d_name, "module") && strcmp(mod_dirp->d_name, "uevent")
                        && strcmp(mod_dirp->d_name, "new_id") && strcmp(mod_dirp->d_name, "remove_id")))
                {
                    continue;
                }

                ///比较获得的名字是否为bus id
                strncpy(name, mod_dirp->d_name, sizeof(name) - 1);

                if ((name[0] >= '0') && (name[0] <= '9'))
                {
                    ///卸载之前先保存模块名称和bus_id到Enable列表
                    not_handle.push_back(string(usb_dirp->d_name) + "_" + string(mod_dirp->d_name));
                    break;
                }
            }
            closedir(mod_dp);
        }
    }
    closedir(usb_dp);
    return 0;
}

void Exclude_modules(vector<string> &exclude, char *buf)
{
    ///加入需要排除的USB模块名称
    exclude.push_back(string("hub"));    ///来自/sys/bus/usb/drivers
    exclude.push_back(string("usb"));
    exclude.push_back(string("usbfs"));
    exclude.push_back(string("usbhid"));

    ///加入选项中的例外模块
    if (buf != NULL)
    {
        char modname[1024] = { '\0' };
        strncpy(modname, buf, sizeof(modname) - 1);
        char *tokenPtr = strtok(modname, ";");          ///多模块名间以";"相分隔
        while (tokenPtr != NULL)
        {
            exclude.push_back(string(tokenPtr));
            tokenPtr = strtok(NULL,";");
        }
    }

    ///加入需要排除的USB存储设备驱动模块
    //Get_content_of_usb_storage(exclude);

    ///对列表排序去重
    sort(exclude.begin(),exclude.end());                                   ///排序
    exclude.erase(unique(exclude.begin(), exclude.end()), exclude.end());  ///去重
}

void usb_otherdevice_ctl(string usb_ctl, string mouse_keypad)
{
    string content;
    int report_id;
    ///传入-1为不处理
    if (usb_ctl == "-1")
    {
        Enable_not_handle_dev();
        return;
    }

    ///传入参数为true时启用模块
    if (usb_ctl == "true")
    {
        Enable_dev();
	content = "USB非移动存储接口被禁用";
	report_id = 900;
    }

    ///卸载USB键盘鼠标，鼠标键盘true为卸载，usb_ctl false为卸载
    if (usb_ctl == "false")
    {
        if (mouse_keypad == "true")
        {
	    Disable_usbhid();
        }
        Disable_dev();
	content = "USB非移动存储接口被启用";
	report_id = 901;
    }
    
    if(IsReportUDiskOther) {
	Report_Hardctrl_info(content,report_id);
	IsReportUDiskOther = false;
    }
}

///-----------------------------------usb other device ctrl end--------------------------------

///-----------------------------------------udisk ctrl start ----------------------------------

int Disable_dev_Udisk()
{
    DIR *usb_dp = NULL;
    DIR *mod_dp = NULL;
    struct dirent *usb_dirp = NULL;
    struct dirent *mod_dirp = NULL;
    char name[256] = { '\0' };
    char log_buf[128] = {0};

    const char *sysdir = "/sys/bus/usb/drivers/";

    if ((usb_dp = opendir(sysdir)) == NULL)
    {
        perror("Can't open /sys/bus/usb/drivers/ directory!\n");
        return 1;
    }
    while ((usb_dirp = readdir(usb_dp)) != NULL)
    {
        ///排除.和..目录
        if (!(strcmp(usb_dirp->d_name, ".") && strcmp(usb_dirp->d_name, "..")))
        {
            continue;
        }

        ///排除usb, hub, usbfs, usb-storage目录
        if (strcmp(usb_dirp->d_name, "usb-storage") != 0 && strcmp(usb_dirp->d_name, "usbfs") != 0)
        {
            continue;
        }

        char subdir[256+32] = "/sys/bus/usb/drivers/";                   // sizeof(dirp->d_name) == 256,加长subdir空间,防止溢出
        ///构造模块目录路径
        strncat(subdir, usb_dirp->d_name, sizeof(subdir) - strlen(subdir) - 1);
        if ((mod_dp = opendir(subdir)) != NULL)
        {
            //cout << "Opendir OK" << endl;
            while ((mod_dirp = readdir(mod_dp)) != NULL)
            {
                ///排除.和..目录
                if (!(strcmp(mod_dirp->d_name, ".") && strcmp(mod_dirp->d_name, "..")))
                {
                    continue;
                }

                if (!(strcmp(mod_dirp->d_name, "bind") && strcmp(mod_dirp->d_name, "unbind")
                        && strcmp(mod_dirp->d_name, "module") && strcmp(mod_dirp->d_name, "uevent")
                        && strcmp(mod_dirp->d_name, "new_id") && strcmp(mod_dirp->d_name, "remove_id")))
                {
                    continue;
                }

                ///比较获得的名字是否为bus id
                strncpy(name, mod_dirp->d_name, sizeof(name) - 1);
                if ((name[0] >= '0') && (name[0] <= '9'))
                {
                    ///卸载之前先保存模块名称和bus_id到Enable列表
                    enable_udisk.push_back(string(usb_dirp->d_name) + "_" + string(mod_dirp->d_name));

                    ///对列表排序去重
                    sort(enable_udisk.begin(), enable_udisk.end());                                    //排序
                    enable_udisk.erase(unique(enable_udisk.begin(), enable_udisk.end()), enable_udisk.end());      //去重

                    ///卸载设备
                    //cout << "5.++++++++++" << subdir << "++++++++++" << mod_dirp->d_name << "+++++++" << endl;
                    snprintf(log_buf, sizeof(log_buf), "udisk disabled:%s,%s",
                             usb_dirp->d_name, mod_dirp->d_name);

                    dev_install_log_run_info(log_buf);
                    Unload_mod(subdir, mod_dirp->d_name);
                    IsReportUDisk = true;
                    break;
                }
            }
            closedir(mod_dp);
        }
    }
    closedir(usb_dp);
    return 0;
}

int Enable_dev_Udisk()
{
    const char *sysdir = "/sys/bus/usb/drivers";
    char *devname = NULL;                                       ///存储设备模块名
    char *bus_id = NULL;                                      ///存储bind string, Example:  2-0:1-0
    char subdir[256+32] = { '\0' };                             /// sizeof(dirp->d_name) == 256,加长subdir空间,防止溢出
    FILE *fp = NULL;
    int ret = 0;
    char log_buf[128] = {0};

    for (vector<string>::iterator ena = enable_udisk.begin(); ena != enable_udisk.end(); ena++)
    {
        string usbdev = *ena;
        ///提取在enable容器中保存的设备驱动名称和bus_id
        devname = strtok((char *)usbdev.c_str(), "_");
        bus_id = strtok(NULL, "_");

        snprintf(subdir, sizeof(subdir) - 1, "%s/%s/bind", sysdir, devname);
        if ((fp = fopen(subdir, "wb")) != NULL)
        {
            ret = fwrite(bus_id, strlen(bus_id), 1, fp);
            snprintf(log_buf, sizeof(log_buf), "enable udisk:%s with ret:%d", bus_id, ret);
            dev_install_log_run_info(log_buf);
            fclose(fp);
        }
        enable_udisk.erase(ena);
        ena--;       ///被删除元素之后的内容会自动往前移，导致迭代漏项，应在删除一项后itor--，使之从已经前移的下一个元素起继续遍历
        IsReportUDisk = true;
        system("/usr/sbin/lsusb");              ///探测USB接口，使启用生效
    }
    return 0;
}

int udisk_ctr(string udisk_str)
{
    string content;
    int code = 0;

    if(udisk_str == "true")
    {
        content = "USB移动存储接口被禁用";
        code = 900;
        Enable_dev_Udisk();
    }
    else if (udisk_str == "false")
    {
        content = "USB移动存储接口被启用";
        code = 901;
        Disable_dev_Udisk();
    }
    
    if(IsReportUDisk)
    {
        Report_Hardctrl_info(content,code);
        IsReportUDisk = false;
        dev_install_log_run_info(content.c_str());
    }
    return 0;
}

///-----------------------------------------udisk ctrl end -----------------------------------

///------------------------------------------other ide ctrl start------------------------------

int get_mountdir_form_partion(const char *partion,char *mountdir,int bufsize,int &is_readonly)
{
    ///本函数主要功能为读取/etc/mtab文件， 根据分区名获得该分区的挂载点
    int lastret=0;

    FILE *fp = popen("cat /etc/mtab","r");
    if(fp != NULL)
    {
        char linebuf[1024]= {0};
        char dev[256]= {0};
        char dir[256]= {0};
        char type[256]= {0};
        char attr1[256]= {0};
        char attr2[256]= {0};
        char attr3[256]= {0};

        while(fgets(linebuf,1023,fp))
        {
            if(strncmp(partion,linebuf,strlen(partion)) == 0)
            {
                //printf("line= %s",linebuf);
                sscanf(linebuf,"%s%s%s%s%s%s",dev,dir,type,attr1,attr2,attr3);
                //printf("mountdir= %s\n",dir);
                strncpy(mountdir,dir,bufsize-1);
                if(strncmp(attr1,"ro",2) == 0)
                {
                    is_readonly = 1;
                }
                else
                {
                    is_readonly = 0;
                }
                lastret =1;
            }
        }
        pclose(fp);
    }
    return lastret;
}

int get_dev_partion(const char *disk_dev,vector<string> &partion_list)
{
    ///本函数主要原理为遍历 /dev下的所有文件，寻找以设备名开始的文件名
    int lastret=0;

    ///首先清除原来的数据
    partion_list.clear();

    char *real_dev_name=NULL;
    char *p_char=(char *)disk_dev;
    while(*p_char != '\0')
    {
        if(*p_char == '/')
        {
            real_dev_name = p_char;
        }
        p_char++;
    }
    real_dev_name++;

    ///遍历搜索目录
    DIR   *directory_pointer;
    struct   dirent   *entry;

    if((directory_pointer=opendir("/dev"))==NULL)
    {
        printf( "Error   opening   %s\n ","/dev");
    }
    else
    {
        while((entry=readdir(directory_pointer))!=NULL)
        {
            int slen = strlen(real_dev_name);
            if(strncmp(entry->d_name,real_dev_name,slen) == 0 && strcmp(entry->d_name,real_dev_name) != 0)
            {
                //printf("%s\n",entry->d_name);
                string temp;
                temp.assign(entry->d_name);
                temp = "/dev/" + temp;

                partion_list.push_back(temp);
            }
        }
        closedir(directory_pointer);
    }
    lastret =1;
    return lastret;
}

void remove_vector_item(vector<usb_dev> &strlist,string path)
{
    vector<usb_dev> list_tmp;
    for(unsigned int i=0; i<strlist.size(); i++)
    {
        if(strlist[i].dev != path)
        {
            list_tmp.push_back(strlist[i]);
        }
    }
    strlist.clear();
    strlist = list_tmp;
}

int is_usb_device(const char * devpath)
{
    struct stat buf;
    char link[512] = {0};
    char link_path[512]= {0};
    if(lstat(devpath,&buf) < 0)
    {
        return -1;
    }
    //printf("dev=%d:%d\n",major(buf.st_rdev),minor(buf.st_rdev));
    if(S_ISBLK(buf.st_mode))
    {
        sprintf(link_path,"/sys/dev/block/%d:%d",major(buf.st_rdev),minor(buf.st_rdev));
        if(access(link_path,F_OK) >= 0 )
        {
            int i = readlink(link_path,link,512);
            if(i == -1)
            {
                perror("readlink failed");
                return -1;
            }
            string strlink = link;
            unsigned int pos = strlink.find("usb",0);
            if(pos == string::npos)
            {
	          return 1;
            }
            return 0;
        }
    }
    return -1;
}

void remove_dou(const char *str)
{
    char *p_char = (char *)str;
    while(*p_char != '\0')
    {
        if(!isdigit(*p_char))
        {
            *p_char='\0';
            break;
        }
        p_char++;
    }
}

int get_mobile_hdd_list()
{
    int is_usb_i=9;
    FILE *fp = popen("ls -l /dev/[sh]d?","r");
    char linebuf[256]= {0};
    char major[256]= {0};
    char minor[256]= {0};
    char dev[256]= {0};
    usb_dev mobile_hdd_temp;
    ///首先清除原有的信息
    mobile_hdd_list.clear();
    ///如果文件打开成功，则读取需要的信息
    if(fp != NULL)
    {
        while(fgets(linebuf,255,fp))
        {
            sscanf(linebuf,"%*s%*s%*s%*s%s%s%*s%*s%*s%s",major,minor,dev);
            remove_dou(major);
            //printf("1:%s %s %s\n",major,minor,dev);
            char removable_file_name[256]= {'\0'};
            snprintf(removable_file_name,255,"/sys/dev/block/%s:%s/removable",major,minor);
            if(access(removable_file_name,F_OK) == 0)
            {
                FILE *r_fp=fopen(removable_file_name,"r");
                if(r_fp != NULL)
                {
                    char r_file_content[256]= {0};
                    fgets(r_file_content,255,r_fp);
                    if(!strcmp(r_file_content,"0\n"))
                    {
                        if((is_usb_i=is_usb_device(dev))==1)
                        {
                            mobile_hdd_temp.major.assign(major);
                            mobile_hdd_temp.minor.assign(minor);
                            mobile_hdd_temp.dev.assign(dev);
                            //printf("mobile_hdd_dev=%s\n",dev);
                            mobile_hdd_list.push_back(mobile_hdd_temp);
                        }
                    }
                    fclose(r_fp);
                }
            }
        }
        pclose(fp);
    }
    return 0;
}

int other_ide_ctr(string other_ide)
{
    int ret=0;
    string hdd_in_use;
    FILE *hdd_fp = NULL;
    char hdd_buf_tmp[1024] = {'\0'};
    string compare_flag("0");
    get_mobile_hdd_list();
    if(system("df /opt/edp_vrv/bin/EdpService | grep -o  '/dev/[hs]d[a-z][1-9]' > hdd_tmp") == -1)
    {
        perror("get in_use hdd failed");
    }
    if((hdd_fp = fopen("hdd_tmp", "r")) != NULL)
    {
        if(fgets(hdd_buf_tmp,1024,hdd_fp) != NULL) 
        {
            if (hdd_buf_tmp[strlen(hdd_buf_tmp) -1] == '\n')
            {
                hdd_buf_tmp[strlen(hdd_buf_tmp) -1] = 0;
            }
        }
        hdd_in_use.assign(hdd_buf_tmp);
        fclose(hdd_fp);
    }


    if(hdd_in_use=="")
    {
        //putenv("LVM_SUPPRESS_FD_WARNINGS=1");
        char env_str_1[]="LVM_SUPPRESS_FD_WARNINGS=1";
        putenv(env_str_1);
        FILE *fp = popen(" pvdisplay | grep 'PV Name' | grep -o  '/dev/[hs]d[a-z][1-9]' ","r");
        if(fp != NULL)
        {
            char linebuf[1024]= {0};
            char hdd_buf_tmp_2[256]={0};
            while(fgets(linebuf,1023,fp))
            {
                sscanf(linebuf,"%s",hdd_buf_tmp_2);
                hdd_buf_tmp_2[strlen(hdd_buf_tmp_2) -1] = 0;
                hdd_in_use=hdd_buf_tmp_2;
            }
            pclose(fp);
        }
    }
    remove_vector_item(mobile_hdd_list,hdd_in_use);
    //对每一个设备进行处理
    for(unsigned int usb_i=0; usb_i<mobile_hdd_list.size(); usb_i++)
    {
        //cout<<"USBDISK:  "<<usb_dev_list[i].major<<" "<<usb_dev_list[i].minor<<" "<<usb_dev_list[i].dev<<endl;
        vector<string>  partion_list;
        ret = get_dev_partion(mobile_hdd_list[usb_i].dev.c_str(),partion_list);
        //fprintf(stderr,"get_dev_partion OK\n");
        for(unsigned int i=0; i<partion_list.size(); i++)
        {
            char mountdir[256]= {0};
            int is_readonly = -1;
            ret = get_mountdir_form_partion(partion_list[i].c_str(),mountdir,256,is_readonly);
            //fprintf(stderr,"get_mountdir_form_partion OK");
            if(ret == 1)
            {
                //fprintf(stderr,"mountdir= %s\n",mountdir);
                //fprintf(stderr,"readonly= %d\n",is_readonly);
                string cmd;
                if(other_ide == "false")	//禁止
                {
                    cmd += "umount " + partion_list[i];
                    system(cmd.c_str());
                }
                else if(other_ide == "true")	//启用
                {
                    if(is_readonly == 1)
                    {
                        cmd += "mount -o remount,rw " + partion_list[i];
                        system(cmd.c_str());
                    }
                }
                //else if(udisk_str == "-1")
                //{
                //
                //}
            }
        }
    }
    return 0;
}

///------------------------------------------other ide ctrl end------------------------------------

///------------------------------------------bluetooth ctrl  start-----------------------------------

bool getProcessState(const char process_name[])
{
    FILE *fd = NULL;
    char cmd[100] = {'\0'};
    char line[100] = {'\0'};

    sprintf(cmd, "pgrep %s",process_name);
    fd = popen(cmd, "r");
    if(NULL != fd)
    {
        fgets(line, sizeof(line)-1, fd);
        pclose(fd);
    }

    if(strlen(line) > 0)
    {
        return true;
    }
    else
    {
        return false;
    }
}

int bluetoothCtrl(string bluetooth)
{
    if(-1 == access("/usr/sbin/bluetoothd",F_OK))
    {
        cout<<"bluetooth ctrl service bluetoothd not exist."<<endl;
        return 0;
    }
    if((bluetooth == "false")&&(getProcessState("bluetoothd"))&&(!IsReportBlueTooth))
    {        
        system("service bluetooth stop");    // 停止蓝牙服务
        printf("stop bluetooth!\n");
        string content;
        content = "蓝牙设备被启用";
        Report_Hardctrl_info(content,901);
        IsReportBlueTooth = true;
        return 0;

    }
    else if((bluetooth == "true")&&(!getProcessState("bluetoothd"))&&(!IsReportBlueTooth))
    {
        system("service bluetooth start");   // 启动蓝牙服务
        printf("star bluetooth!\n");
        string content;
        content = "蓝牙设备被禁用";
        Report_Hardctrl_info(content,900);
        IsReportBlueTooth = true;
        return 0;

    }
    return 0;
}

///------------------------------------------bluetooth ctrl  end------------------------------------

///---------------------------------------------printer ctrl start------------------------------------

int getCupsState(void)
{
    FILE *fd = NULL;
    char cmd[100] = {'\0'};
    char line[100] = {'\0'};

    sprintf(cmd, "pgrep cupsd");
    fd = popen(cmd, "r");
    if(NULL != fd)
    {
        fgets(line, sizeof(line)-1, fd);
        pclose(fd);
    }
    if(strlen(line) > 0)
    {
        return 1;
    }
    else
    {
        return 0;
    }

}

#if 0
int getCupsContrl(string printer)
{
    string cups_status;
    control_cups(0, cups_status);

    if((cups_status == "")||(cups_status == "0"))//本策略可控
    {
        //写控制状态
        if(printer == "false")
        {
            cups_status = "2";
            control_cups(1,cups_status);
        }
        return 1;
    }
    else if(cups_status == "1")
    {
        cout<<"could not control cups!"<<endl;
        return 0;
    }
    else if(cups_status == "2")
    {
        return 1;
    }
}
#endif

int printerCtrl(string printer)
{
    string content;

    if(-1 == access("/usr/sbin/cupsd",F_OK))
    {
        //cout<<"printer ctrl service cupsd not exist."<<endl;
        return 0;
    }
    cout<<"cupsd exist."<<endl;

    if(1 == getCupsState())
    {
        //if(printer == "false" && getCupsContrl(printer))
        if(printer == "false" )
        {
            system("service cups stop");    // 停止打印机服务
            content = "打印机设备被启用";
            Report_Hardctrl_info(content,901);
            //cout<<"=================="<<content<<endl;
        }
    }
    else
    {
        //if(printer == "true" && getCupsContrl(printer))
        if(printer == "true")
        {
            system("service cups start");   // 启动打印机服务
            content = "打印机设备被禁用";
            Report_Hardctrl_info(content,900);          
            //cout<<"=================="<<content<<endl;
        }
    }
    return 0;
}

///-----------------------------------------printer ctrl end-----------------------------------

///----------------------------------------floppy ctrl start -----------------------------------

bool getModState(const char mod_name[])
{
    FILE *fd = NULL;
    char cmd[100] = {'\0'};
    char line[100] = {'\0'};

    sprintf(cmd, "lsmod | grep %s",mod_name);
    fd = popen(cmd, "r");
    if(NULL != fd) {
        fgets(line, sizeof(line)-1, fd);
        pclose(fd);
    }
    if(strlen(line) > 0) {
        return true;
    }
    else {
        sprintf(cmd, "modinfo %s | grep filename",mod_name);
        fd = popen(cmd, "r");
	if(NULL != fd) {
	    fgets(line, sizeof(line)-1, fd);
	    pclose(fd);
	}
	if(strlen(line) > 0) {
	    return true;
	}
	else {
	    return false;
	}
    }
}

int floppyCtrl(string floppy)
{
    if((floppy == "false")&&(getModState("floppy"))&&(!IsReportFloppy))
    {
        system("modprobe -r floppy");    // 停止打印机服务
        printf("stop floppy!\n");
        string content;
        content = "软盘设备被启用";
        Report_Hardctrl_info(content,901);
        IsReportFloppy = true;
        return 0;
    }
    else if((floppy == "true")&&(getModState("floppy"))&&(!IsReportFloppy))
    {
	system("modprobe floppy");// 启动打印机服务
	printf("star floppy!\n");
        string content;
        content = "软盘设备被禁用";
        Report_Hardctrl_info(content,900);
        IsReportFloppy = true;
        return 0;
    }
    return 0;
}

///----------------------------------------floppy ctrl end -----------------------------------

///----------------------------------------cdrom ctrl start ----------------------------------

int cdromCtrl(string cdrom)
{
    FILE *fd = NULL;
    char cmd[1024] = {'\0'};
    char line[1024] = {'\0'};
    char path[1024] = {'\0'};

    if(cdrom == "false")
    {
        sprintf(cmd, "df|grep /dev/sr|awk \'{print $1}\'");
        fd = popen(cmd, "r");
        if(NULL != fd)
        {
            while(fgets(line, sizeof(line)-1, fd))
            {
                memset(path, 0, sizeof(path));
                strncpy(path, line, strlen(line) - 1);
                if(strstr(path, "sr") == NULL) {
                    std::cout << " no cdrom found just return " << std::endl;
                    continue;
                }
                sprintf(path, "umount %s", line);
                //cout<<"path="<<path<<endl;
                system(path);
            }
            pclose(fd);
            fd = NULL;
        }
        sprintf(cmd, "ls -l /dev/sr* | awk \'{print $10}\'");
        fd = popen(cmd, "r");
        if(NULL != fd)
        {
            while(fgets(line, sizeof(line)-1, fd))
            {
                memset(path, 0, sizeof(path));
                strncpy(path, line, strlen(line) - 1);
                std::string org_srx = path;
                if(org_srx.find("_") != std::string::npos) {
                    printf("%s\n", " already named continue");
                    continue;
                }
                std::string srx = path;
                srx.append("_");
                sprintf(cmd, "mv %s %s", org_srx.c_str(), srx.c_str());
                system(cmd);
                printf("%s %s\n", " cmdbuf: ", cmd);
		string content;
		content = "光驱设备被启用";
		Report_Hardctrl_info(content,901);

#if 0
                memset(path, 0x00, sizeof(path));
                strncpy(path, line, strlen(line)-1);
                strncpy(path2, line, strlen(line)-1);
                int length = strlen(path2);
                if('x' != path2[length-2])
                {
                    path2[length+1] = '\0';
                    path2[length] = path2[length-1];
                    path2[length-1] = 'x';
                    cout<<"Length="<<length<<endl;
                    cout<<"path2="<<path2<<endl;
                    sprintf(cmd, "mv %s %s", path, path2);
                    cout<<"cmd = "<<cmd<<endl;
                    system(cmd);
                }
#endif
            }
            pclose(fd);
            fd = NULL;
        }
    }
    if(cdrom == "true")
    {
        sprintf(cmd, "ls -l /dev/sr* | awk \'{print $10}\'");
        fd = popen(cmd, "r");
        if(NULL != fd)
        {
            while(fgets(line, sizeof(line)-1, fd))
            {
                memset(path, 0, sizeof(path));
                strncpy(path, line, strlen(line)-1);
                std::string named_srx = path;
                if(std::string::npos != named_srx.find("_")) {
                    sprintf(cmd, "mv %s %s", named_srx.c_str(), 
                            named_srx.substr(0, named_srx.find("_")).c_str());
                    system(cmd);
                    printf("cmd %s\n", cmd);
		    string content;
		    content = "光驱设备被禁用";
		    Report_Hardctrl_info(content,900);
                }
#if 0
                strncpy(path, line, strlen(line)-1);
                strncpy(path2, line, strlen(line)-1);
                int length = strlen(path2);
                path2[length+1] = path2[length];
                if('x' == path2[length-2])
                {
                    path2[length-2] = path2[length-1];
                    path2[length-1] = path2[length];
                    cout<<"path2="<<path2<<endl;
                    sprintf(cmd, "mv %s %s", path, path2);
                    cout<<"cmd = "<<cmd<<endl;
                    system(cmd);
                }
#endif
            }
            pclose(fd);
            fd = NULL;
        }
    }
    return 0;
}

///----------------------------------------cdrom ctrl end -------------------------------------

bool dev_install_ctrl_init() 
{
    old_crcvalue = 0;
    dev_install_log_run_info("init start");
    dev_install_log_run_info("init end");
    return  true ;
}

bool dev_install_ctrl_worker(CPolicy * pPolicy, void * pParam) 
{
    char log_buf[128] = {0};

    if(pPolicy->get_type() != DEV_INSTALL_CTRL) 
    {
        return false ;
    }

    g_pPolicyDevInstallCtrl= (CDevInstallCtrl*)pPolicy;

    if(old_crcvalue != g_pPolicyDevInstallCtrl->get_crc())
    {
        snprintf(log_buf, sizeof(log_buf), "policy changed, old-crc,new-crc->%d,%d",
                 old_crcvalue, g_pPolicyDevInstallCtrl->get_crc());
        dev_install_log_run_info(log_buf);

        not_handle.clear();
        //enable.clear(); 
        exclude.clear();
        //usbhid.clear();
        //enable_udisk.clear();
        mobile_hdd_list.clear();
        vecModeSerialPort.clear();
        vecModeParallelPort.clear();

        printerCtrl(g_pPolicyDevInstallCtrl->PRINTER);
        //cdromCtrl(g_pPolicyDevInstallCtrl->CDROM);
        Exclude_modules(exclude, (char*)g_pPolicyDevInstallCtrl->USBINTERFACEExcept.c_str());
        Not_handle_save_mod(not_handle);
        //IsSPortForbidden = false;
        //IsPPortForbidden = false;
        IsReportUDiskOther = false;
        IsReportUDisk = false;
        IsReportBlueTooth = false;
        IsReportFloppy = false;

        ///save policy crc
        old_crcvalue = g_pPolicyDevInstallCtrl->get_crc();
    }
    udisk_ctr(g_pPolicyDevInstallCtrl->UDISK);
    other_ide_ctr(g_pPolicyDevInstallCtrl->OtherIDE);
    bluetoothCtrl(g_pPolicyDevInstallCtrl->BlueTooth);
    printerCtrl(g_pPolicyDevInstallCtrl->PRINTER);
    //FT no this one
    //floppyCtrl(g_pPolicyDevInstallCtrl->FLOPPY);
    cdromCtrl(g_pPolicyDevInstallCtrl->CDROM);
    usb_otherdevice_ctl(g_pPolicyDevInstallCtrl->USBINTERFACE, "true");
    ///handle serial port and parallel port
    SPort_PPort_DoWork(g_pPolicyDevInstallCtrl->PORT,g_pPolicyDevInstallCtrl->LPTPORT);
    //cout<<"leave  dev_install_ctrl_worker()"<<endl;
    return true;
}

void dev_install_ctrl_uninit() 
{
    dev_install_log_run_info("uninit start");

    //RECOVERYDEVICEFILE();
    cdromCtrl("true");
    Enable_dev_Udisk();
    Enable_dev();
    //    Enable_usbhid();
    not_handle.clear();
    enable.clear();
    enable_udisk.clear();
    exclude.clear();
    usbhid.clear();
    system("service bluetooth start");
    ///写cups控制状态
    //if( ! getCupsState() && getCupsContrl(g_pPolicyDevInstallCtrl->PRINTER))
    if( (-1 != access("/usr/sbin/cupsd",F_OK)) && !getCupsState() )
    {
        system("service cups start");   // 启动打印机服务
        //string cups_status = "0";
        //control_cups(1,cups_status);
    }
    system("modprobe floppy");
    enableParallelPort();
    enableSerialPort();
    //StartSerialPort();
    //StartParallelPort();
    old_crcvalue = 0;
    dev_install_log_run_info("uninit end");
    return;
}

static void dev_install_log_run_info(const char *log_content)
{
    char log_info[2048] = {0};

    if(NULL == log_content)
    {
        return ;
    }
	
    snprintf(log_info, sizeof(log_info), "hd_ctl:%s\n", log_content);

    g_GetlogInterface()->loglog(log_info);
}

