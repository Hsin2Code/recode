#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <sys/inotify.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <unistd.h>
#include "../../vrvprotocol/VRVProtocol.hxx"
#include "../../vrvprotocol/VRVProtocolEx.hxx"
#include "../../common/Commonfunc.h"
#include "../../vrcport_tool.h"
#include "../../VCFCmdDefine.h"
#include "../../../include/MCInterface.h"
#include "../../include/label_usb/edpUsbTage.h"
#include "udisk_act_ctrl.h"
#include "udisk_descramble.h"

#define EVENT_NUM 16
#define MAX_BUF_SIZE 1024

// usb设备数据类型
struct usb_dev {
    std::string major;
    std::string minor;
    std::string dev;
};

typedef struct label_usb_info {
    /*NOTE: not all info readfrom usb, only we needed*/
    std::string g_label;
    std::string s_label;
    std::string department;
    std::string office;
    std::string username;
    int usb_type;
    std::string dev_path;
    label_usb_info() {
        usb_type = INVALID_USB;
    }
} label_usb_info_t;


typedef struct report_usb_info {
    bool auth_ret;
    bool process;
    bool report;
    std::string access_mode;
    std::vector<std::string> mount_point;
    std::string content;
    std::string department;
    std::string office;
    std::string user_name;
    report_usb_info() {
        auth_ret = false;
        process = false;
        report = false;
        access_mode = "";
        mount_point.clear();
        content = "";
        department = "";
        office = "";
        user_name = "";
    }
} report_usb_info_t;


std::map<std::string, report_usb_info_t> g_current_device_info;

static std::string convert_string(const std::string &from, const std::string &to, char *instr) {
    /*never exceed 1024*/
	char out_decode[1024] = {0};
	int left_size = sizeof(out_decode);
    extern int code_convert(const char *from_charset,const char *to_charset, 
            char *inbuf,int inlen,char *outbuf,int &outlen);

    (void)code_convert(from.c_str(), to.c_str(), 
			instr, 
			strlen(instr), out_decode, left_size);
	return out_decode;
}

static int get_sector_size(const std::string &udev_path) {
#ifndef BLKPBSZGET
#define BLKSSZGET  _IO(0x12,104) /* get block device sector size */
#endif
    int logicalsectsize = -1;
    if(udev_path.empty()) {
        return logicalsectsize;
    }
    int fd = open("/dev/sdb", O_RDONLY | O_NONBLOCK);
    if(fd < 0) {
        return logicalsectsize;
    }
    if (ioctl(fd, BLKSSZGET, &logicalsectsize) < 0) {
        logicalsectsize = -1;
    }
    return logicalsectsize;
}


static void send_tips_to_ui_udisk_action(const std::string &content)
{
    char buffer[512] = "";
    tag_GuiTips * pTips = (tag_GuiTips *)buffer ;
    pTips->sign = en_TipsGUI_btnOK|en_TipsGUI_timeOut ;
    pTips->defaultret = en_TipsGUI_None;
    strncpy(pTips->szTitle,"信息提示",sizeof(pTips->szTitle));
    strncpy(pTips->szTips,content.c_str(),sizeof(pTips->szTips));
    pTips->pfunc = NULL;
    pTips->param.timeout = 5*1000;
    g_GetSendInterface()->sendto_Main(VCF_CMD_GUI_TIPS,buffer,sizeof(tag_GuiTips));
}


static int read_info_from_label_usb(label_usb_info_t &out_value,
        const std::string &dev_path, 
        const std::string &g_label,
        const int &sector_size = 512) {
	if(dev_path.empty() || g_label.empty() || sector_size <= 0) {
		std::cout << " parameter not valid" << std::endl;
        out_value.usb_type = INVALID_USB;
		return INVALID_USB;
	}
    if(access(dev_path.c_str(), F_OK) != 0) {
        std::cout << "disk path access failed: " << dev_path << std::endl;
        out_value.usb_type = INVALID_USB;
        return INVALID_USB;
    }
	InitCRC();
	EDP_TAGE_PARAM tage_parm;
	memset(&tage_parm, 0, sizeof(EDP_TAGE_PARAM));
	strcpy(tage_parm.szFileName, dev_path.c_str());
	strcpy(tage_parm.szGloableFlag, g_label.c_str());
	//strcpy(tage_parm.szUSBUniqueID, "");
	//strcpy(tage_parm.szUSBUniqueID, "69399ac8");
	tage_parm.dwSectoreSize = sector_size;
	EDP_TAGE_INFO out_param;
	memset(&out_param, 0, sizeof(EDP_TAGE_INFO));
	int ret_read = EDPReadTage(tage_parm, &out_param);
	std::cout << "ret_read is  " << ret_read <<std::endl;

	if(ret_read != 0) {
		std::cout << "read error EDPReadTage return " << std::endl;
        out_value.usb_type = NORMAL_USB;
		return NORMAL_USB;
	}

	if(strlen(out_param.szTageGlobleFlage) != 0) {
		out_value.g_label = convert_string("gb2312", "utf-8//IGNORE", 
				out_param.szTageGlobleFlage);
	}
	if(strlen(out_param.szTageSmallTage) != 0) {
		out_value.s_label = convert_string("gb2312", "utf-8//IGNORE", 
				out_param.szTageSmallTage);
	}
	if(strlen(out_param.szDepartment) != 0) {
		out_value.department  = convert_string("gb2312", "utf-8//IGNORE", 
				out_param.szDepartment);
	}
	if(strlen(out_param.szUserName) != 0) {
		out_value.office = convert_string("gb2312", "utf-8//IGNORE", 
				out_param.szUserName);
	}
	if(strlen(out_param.szOfficeName) != 0) {
		out_value.username = convert_string("gb2312", "utf-8//IGNORE", 
				out_param.szOfficeName);
	}
    out_value.dev_path = dev_path;
	/*safe xxx*/
	if(YCommonTool::endwith(out_value.s_label, "!SAFE1")) {
        out_value.usb_type = SAFE1_USB;
		return SAFE1_USB;
	} 
	if(YCommonTool::endwith(out_value.s_label, "!SAFE")) {
        out_value.usb_type = SAFEX_USB;
		return SAFEX_USB;
	} 
    out_value.usb_type = NORMAL_LABEL_USB;
	return NORMAL_LABEL_USB;
}

/*
static const char * event_array[] = {
    "File was accessed",
    "File was modified",
    "File attributes were changed",
    "writtable file closed",
    "Unwrittable file closed",
    "File was opened",
    "File was moved from X",
    "File was moved to Y",
    "Subfile was created",
    "Subfile was deleted",
    "Self was deleted",
    "Self was moved",
    "",
    "Backing fs was unmounted",
    "Event queued overflowed",
    "File was ignored"
};
*/


static unsigned int old_crcvalue = 0;
static CUdiskActCtrl *g_pPolicyUdiskActCtrl=NULL;

static pthread_t tid1;

///定义存储所有usb设备的动态数组
static int edp_inotify_fd;
static std::vector<usb_dev> usb_dev_list;
static std::vector<string> vecExceptFile;
static std::vector<wd_name> wd_name_list;    /// 定义监视列表
static std::vector<alert_node> alert_vector; /// 告警存储结构

static   volatile    bool   g_adv_enable_udiskact = true ;

static void advcfg_statchage(void *pParam) {
    bool *pbool = ( bool *)pParam;
    g_adv_enable_udiskact= *pbool ;
}

/*
static void SlipWord(string processline) {
    string strLine;
    strLine = processline;
    string strPro;
    unsigned int iPos = strLine.find("|");
    while (iPos != string::npos) {
        strPro = strLine.substr(0, iPos);
        vecExceptFile.push_back(strPro);
        strLine = strLine.substr(iPos + 1);
        iPos = strLine.find("|");
    }
    vecExceptFile.push_back(strLine);
}
*/

static void udisk_remove_dou(const char *str) {
    char *p_char = (char *)str;
    while (*p_char != '\0') {
        if (!isdigit(*p_char)) {
            *p_char = '\0';
            break;
        }
        p_char++;
    }
}

static void remove_enter(const char *str) {
    char *p_char = (char *)str;
    while (*p_char != '\0') {
        if (*p_char == '\n') {
            *p_char = '\0';
            break;
        }
        p_char++;
    }
}

static std::vector<std::string> split_udisk(const std::string &src, 
        const std::string &delimit) {
    vector<string> v;
    if (src.empty() || delimit.empty()) {
        return v;
    }
    size_t deli_len = delimit.size();
    std::string str = src;
    unsigned long index = string::npos;//, last_search_position = 0;
    while ((index = str.find(delimit)) != string::npos) {
        if (index != 0) {
            v.push_back(str.substr(0, index));
        } 
        str = str.substr(index + deli_len);
    }
    v.push_back(str);
    return v;
}

static int get_usb_dev_list() {
    ///本函数功能为获取本级中所有的USB存储设备
    ///主要原理为遍历 /proc/下面所有以sd开头的文件
    FILE *fp1 = popen("ls -l /dev/sd*", "r");
    char linebuf[256] = {0};
    char major[256]   = {0};
    char minor[256]   = {0};
    char dev[256]     = {0};
    usb_dev usb_dev_temp;

    ///首先清除原有的信息
    usb_dev_list.clear();

    ///如果文件打开成功，则读取需要的信息
    if (fp1 != NULL) {
        while (fgets(linebuf, 255, fp1)) {
            string strline = linebuf;
            vector<string> vec = split_udisk(strline, " ");
            strcpy(major, vec[4].c_str());
            strcpy(minor, vec[5].c_str());
            strcpy(dev, vec[vec.size() - 1].c_str());
            udisk_remove_dou(major);
            remove_enter(dev);

            char file_name[256] = { 0 };
            snprintf(file_name, 255, "/sys/dev/block/%s:%s/removable", major, minor);
            if (access(file_name, F_OK) == 0) {
                FILE *fp = fopen(file_name, "r");
                if (fp != NULL) {
                    char file_content[256] = { 0 };
                    fgets(file_content, 255, fp);
                    if (!strcmp(file_content, "1\n")) {
                        usb_dev_temp.major.assign(major);
                        usb_dev_temp.minor.assign(minor);
                        usb_dev_temp.dev.assign(dev);
                        usb_dev_list.push_back(usb_dev_temp);
                    }
                    fclose(fp);
                }
            }
        }
        pclose(fp1);
    }
    return 0;
}

static int udisk_get_dev_partion(const char *disk_dev, vector<string> &partion_list) {
    ///本函数主要原理为遍历 /dev下的所有文件，寻找以设备名开始的文件名
    int lastret = 0;
    char *real_dev_name = NULL;
    char *p_char = (char *)disk_dev;

    ///首先清除原来的数据
    partion_list.clear();

    while (*p_char != '\0') {
        if (*p_char == '/') {
            real_dev_name = p_char;
        }
        p_char++;
    }
    if(real_dev_name == NULL) {
        return -1;
    }
    real_dev_name++;

    ///遍历搜索目录
    DIR   *directory_pointer = NULL;
    struct   dirent   *entry = NULL;
    int slen = strlen(real_dev_name);
    string temp;
    if ((directory_pointer = opendir("/dev")) == NULL) {
        printf("Error   opening   %s\n ", "/dev");
    } else {
        while ((entry = readdir(directory_pointer)) != NULL)
        {
            if (strncmp(entry->d_name, real_dev_name, slen) == 0 && strcmp(entry->d_name, real_dev_name) != 0)
            {
                if(entry->d_name[slen] != '\0')
                {			
                    temp = entry->d_name;
                    temp = "/dev/" + temp;
                    partion_list.push_back(temp);
                }
            }
        }
        closedir(directory_pointer);
    }
    lastret = 1;
    return lastret;
}

static int search_partion(string partion) {
    for (size_t i = 0; i < wd_name_list.size(); i++) {
        if (wd_name_list[i].inotify_usb_partion == partion) {
            return 1;
        }
    }
    return 0;
}

static void CheckException(string strPorcess, bool &isFind) {
    std::vector<string>::iterator iterExcept = vecExceptFile.begin();
    std::string strExcept;
    for (; iterExcept != vecExceptFile.end(); iterExcept++) {
        strExcept = *iterExcept;
        if (strExcept == strPorcess) {
            isFind = true;
            break;
        }
    }
}

static bool listDir(char *path) {
    DIR *pDir = NULL;
    struct dirent *ent = NULL;
    char childpath[512] = {0};

    pDir = opendir(path);
    memset(childpath, 0, sizeof(childpath));
    while ((ent = readdir(pDir)) != NULL) {
        if (ent->d_type & DT_DIR) {
            if (strcmp(ent->d_name, ".") == 0 || 
                    strcmp(ent->d_name, "..") == 0) {
                continue;
            }
            sprintf(childpath, "%s/%s", path, ent->d_name);
            listDir(childpath);
        } else {
            bool isFind = false;
            string strName(ent->d_name);
            CheckException(strName, isFind);
            if (isFind) {
                closedir(pDir);
                return true;
            }
        }
    }
    closedir(pDir);
    return false;
}

static int AddWatch(const char * dir, wd_name& wd_name_tmp) {
    DIR   *directory_pointer = NULL;
    struct   dirent   *entry = NULL;
    struct stat f_ftime;
    int wd = 0;
    if ((directory_pointer = opendir(dir)) == NULL) {
        printf("Error   opening   %s\n ", "/dev");
    } else {
        while ((entry = readdir(directory_pointer)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || 
                    strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            string temp;
            temp.assign(dir);
            temp += "/";
            temp += entry->d_name;
            cout<<"temp: "<<temp<<endl;
            if (stat(temp.c_str(), &f_ftime) != 0) {
                cout<<"stat error."<<endl;
                continue;
            }
            if (S_ISDIR(f_ftime.st_mode)) {
                wd_element wd_ele_tmp;
                strncpy(wd_ele_tmp.name, temp.c_str(), 255);
                wd = inotify_add_watch(edp_inotify_fd, wd_ele_tmp.name, IN_ALL_EVENTS);
                if (wd > 0) {
                    wd_ele_tmp.wd = wd;
                    wd_name_tmp.wdelem.push_back(wd_ele_tmp);	///监视目录
                } else {
                    cout << "add watch error!" << endl;
                    closedir(directory_pointer);
                    return -1;
                }
                AddWatch(temp.c_str(), wd_name_tmp);
            }
        }
        closedir(directory_pointer);
    }
    return 0;
}

static int get_mountdir_from_partion(const char *partion, char *mountdir, 
        int bufsize, int &is_readonly) {
    ///本函数主要功能为读取/etc/mtab文件， 根据分区名获得该分区的挂载点
    int lastret = 0;

    FILE *fp = popen("cat /etc/mtab", "r");
    if (fp != NULL) {
        char linebuf[1024] = { 0 };
        char dev[256] = { 0 };
        char dir[256] = { 0 };
        char type[256] = { 0 };
        char attr1[256] = { 0 };
        char attr2[256] = { 0 };
        char attr3[256] = { 0 };

        while (fgets(linebuf, 1023, fp)) {
            if (strncmp(partion, linebuf, strlen(partion)) == 0) {
                sscanf(linebuf, "%s%s%s%s%s%s", 
                        dev, dir, type, attr1, attr2, attr3);
                strncpy(mountdir, dir, bufsize - 1);
                if (strncmp(attr1, "ro", 2) == 0) {
                    is_readonly = 1;
                } else {
                    is_readonly = 0;
                }
                lastret = 1;
            }
        }
        pclose(fp);
    }
    return lastret;
}

static int get_monitor_path(const int wd, string &path)
{
    path.clear();

    for (unsigned int i = 0; i < wd_name_list.size(); i++)
    {
        for (unsigned int j = 0; j < wd_name_list[i].wdelem.size(); j++)
        {
            if (wd == wd_name_list[i].wdelem[j].wd)
            {
                path.assign(wd_name_list[i].wdelem[j].name);
                return 0;
            }
        }
    }

    return 1;
}

/* 
 *
 * 添加目录监控(通用函数)
 */ 
unsigned int add_watch_dir(const char *path, vector<wd_element> &wd_name_vector)
{
    DIR *dir =  NULL;
    wd_element new_use_dir;

    /// 先将自身加入监控
    strncpy(new_use_dir.name, path, 255);
    new_use_dir.wd = inotify_add_watch(edp_inotify_fd, new_use_dir.name, IN_ALL_EVENTS);
    wd_name_vector.push_back(new_use_dir);

    /// 遍历目录，递归将子目录加入监控   
    dir = opendir(path);
    if (dir != NULL)
    {
        char full_name[256] = { 0 };
        struct dirent *entry;
        struct stat statbuf;

        while ((entry = readdir(dir)) != NULL)
        {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            {
                continue;
            }
            sprintf(full_name, "%s/%s", path, entry->d_name);
            if (stat(full_name, &statbuf) != 0)
            {
                closedir(dir);
                return 2;
            }
            if (S_ISDIR(statbuf.st_mode))
            {
                add_watch_dir(full_name, wd_name_vector);
            }
        }
        closedir(dir);
    }
    else
    {
        return 1;
    }

    return 0;
}

static bool get_udisk_report_ext_via_mp(const char *mp, 
        std::string &dep, std::string &office, std::string &user_name) {
    if(mp == NULL) {
        return false;
    }
    std::map<std::string, report_usb_info_t>::iterator iter 
        = g_current_device_info.begin();
    while(iter != g_current_device_info.end()) {
        std::vector<std::string> &mpr = iter->second.mount_point;
        if(std::find(mpr.begin(), mpr.end(), mp) != mpr.end()) {
            break;
        }
        iter++;
    }
    if(iter != g_current_device_info.end()) {
        dep = iter->second.department;
        office = iter->second.office;
        user_name = iter->second.user_name;
        return true;
    }
    return false;
}

int set_usb_log(int kind, char path_set[1024], 
        char *monitor_name_tmp, bool isDir, const std::string &spec_content = "")
{
    FILE *fp_put = NULL;
    char monitor_name[1024] = { 0 };

    if (NULL != monitor_name_tmp)
    {
        strcpy(monitor_name, monitor_name_tmp);
    }

    string SysUserName;
    get_desk_user(SysUserName);
    if("" == SysUserName)
    {
        SysUserName="root";
    }
    char szTime[21]="";
    YCommonTool::get_local_time(szTime);

    char buffer[2048] = {0};
    tag_Policylog *plog = (tag_Policylog *)buffer ;
    plog->type = AGENT_RPTAUDITLOG;
    plog->what = AUDITLOG_REQUEST;
    char *pTmp = plog->log ;

    ///打开文件进行读写
    fp_put = fopen("/var/log/usb_log", "a+");
    if (fp_put == NULL) {
        printf("fopen erro !\n");
        return -1;
    }
    std::map<int, std::string> default_content;
    default_content[100] = "插入移动存储设备";
    default_content[105] = "拔出移动存储设备";
    default_content[102] = "读文件";
    default_content[103] = "修改文件";
    default_content[802] = "新建文件";
    default_content[802 * 2] = "新建文件夹";
    default_content[803] = "删除文件";
    default_content[803 * 2] = "删除文件夹";
    if(default_content.find(kind) != default_content.end()) {
        std::string report_content = "";
        std::string object_str = "";
        if(monitor_name_tmp) {
            object_str.append(monitor_name_tmp);
        }
        if((kind == 802 || kind == 803) && isDir) {
            report_content = default_content[kind * 2];
        } else {
            report_content = default_content[kind];
        }
        std::string user_name;
        std::string department;
        std::string office;
        std::string ext_info = "";
        if(get_udisk_report_ext_via_mp(path_set, department, office, user_name)) {
            ext_info = "部门: " + department + " 科室: " + office + " 使用人: " + user_name;
        }

        sprintf(pTmp, "Body0=time=%s<>kind=%d<>policyid=%d<>PolicyName=%s<>KeyUserName=%s"
                      "<>classaction=%d<>riskrank=%d"
                      "<>Unit=<>Dept=<>UserName=<>sn=<>context=%s. (%s: %s"
                      "%s 设备信息(OS:Linux))%s%s%s"
                      ,szTime
                      ,kind
                      ,g_pPolicyUdiskActCtrl->get_id()
                      ,g_pPolicyUdiskActCtrl->get_name().c_str()
                      ,SysUserName.c_str()
                      ,General_Behavior
                      ,Event_Message
                      ,spec_content.empty() ? report_content.c_str() : spec_content.c_str()
                      ,object_str.c_str()
                      ,path_set
                      ,ext_info.c_str()
                      ,STRITEM_TAG_END
                      ,"BodyCount=1"
                      ,STRITEM_TAG_END);
        fprintf(fp_put, "%s", pTmp);
    }

#if 0
	100,102,103,801,802,803,804,805,105,106,806,807,808,809
#endif
    fclose(fp_put);
    report_policy_log(plog,false);
    return 0;
}

/* 
 * 添加新分区监控
 */
unsigned int build_watch_partion(const char *partion)
{
    int is_readonly = 0;
    char mountdir[256] = { 0 };
    wd_name new_usb_partion;

    /// 查看分区是否已在监控列表
    if (search_partion(partion) != 0)
    {
        return 1;
    }
    /// 构建新监控分区结构
    new_usb_partion.inotify_usb_partion = partion;
    get_mountdir_from_partion(partion, mountdir, 256, is_readonly);
    new_usb_partion.mountdir = mountdir;
    new_usb_partion.wdelem.clear();
    /// 添加监控文件夹并存储监控信息
    if (0 != add_watch_dir(mountdir, new_usb_partion.wdelem))
    {
        return 2;
    }
    /// 将新分区加入监控列表
    wd_name_list.push_back(new_usb_partion);

    return 0;
}

/* 
 * 添加目录树监控
 */
static int add_watch_tree(const char *path, const char *name) {
    char monitor_path[512] = { 0 };
    sprintf(monitor_path, "%s/%s", path, name);
    for (unsigned int i = 0; i < wd_name_list.size(); i++) {
        if (strstr(monitor_path, wd_name_list[i].mountdir.c_str())) {
            if (0 != add_watch_dir(monitor_path, wd_name_list[i].wdelem)) {
                return 1;
            }
            break;
        }
    }
    return 0;
}

/* 
 * 删除目录树监控
 */
static int remove_watch_tree(const char *path, const char *name) {
    char monitor_path[256] = { 0 };
    sprintf(monitor_path, "%s/%s", path, name);
    for (size_t i = 0; i < wd_name_list.size(); i++) {
        std::vector<wd_element>::iterator iter = wd_name_list[i].wdelem.begin();
        for (; iter != wd_name_list[i].wdelem.end(); iter++) {
            if (strlen(iter->name) >= strlen(monitor_path)) {
                if (strncmp(iter->name, monitor_path, strlen(monitor_path)) == 0) {
                    inotify_rm_watch(edp_inotify_fd, iter->wd);
                    wd_name_list[i].wdelem.erase(iter);
                    iter--;
                }
            }
        }
    }
    return 0;
}

static int save_alert(unsigned int mask, int kind, char *path_set, 
        char *monitor_name_tmp, bool is_dir) {
    alert_node node;
    node.mask = mask;
    node.kind = kind;
    strcpy(node.path_set, path_set);
    node.is_dir = is_dir;
    strcpy(node.monitor_name, monitor_name_tmp);
    alert_vector.push_back(node);
    return 0;
}

/* 
 * 预留接口
 */
static int sort_alert() {
    alert_vector.clear();
    return 0;
}

/* 
 * 预留接口
 */
static int send_alert() {
    return 0;
}

static void* handle_change_thread(void* arg) {
    int fd = edp_inotify_fd;
    char buffer[1024] = {0};
    char * offset = NULL;
    struct inotify_event *event = NULL;
    int len;
    int tmp_len;
    char strbuf[16] = {0};
    std::string strWatchPath;

    while ((len = read(fd, buffer, MAX_BUF_SIZE))) {
        if(!g_adv_enable_udiskact) {
            usleep(10000);
            continue ;
        }
        offset = buffer;
        event = (struct inotify_event *)buffer;
        while (((char *)event - buffer) < len)
        {
            if ((event->mask != (IN_ISDIR | IN_CLOSE_NOWRITE)) && (event->mask != (IN_ISDIR | IN_OPEN))) /// 这里排除非需要监控事件
            {
                string monitor_path;
                char *extension_name = NULL;

                /// 根据wd获取相应路径
                if (get_monitor_path(event->wd, monitor_path) != 0)
                {
                    goto next;
                }

                if (event->mask & IN_ISDIR) /// 针对目录事件
                {
                    memcpy(strbuf, "Direcotory", 11);

                    if ((event->mask == (IN_ISDIR | IN_MOVED_FROM)/*1073741888*/) && (strcmp(event->name, "") != 0)) /// 审计移出文件夹
                    {
                        if (0 == remove_watch_tree(monitor_path.c_str(), event->name))
                        {
                            cout << "成功移出目录树： " << monitor_path << "/" << event->name << endl;
                        }
                        set_usb_log(803, (char *)monitor_path.c_str(), event->name, true);
                        save_alert(event->mask, 803, (char *)monitor_path.c_str(), event->name, true);
                    }
                    else if ((event->mask == (IN_ISDIR | IN_DELETE)/*1073742336*/) && (strcmp(event->name, "") != 0)) /// 审计删除文件夹
                    {
                        if (0 == remove_watch_tree(monitor_path.c_str(), event->name))
                        {
                            cout << "成功删除目录树： " << monitor_path << "/" << event->name << endl;
                        }
                        set_usb_log(803, (char *)monitor_path.c_str(), event->name, true);
                        save_alert(event->mask, 803, (char *)monitor_path.c_str(), event->name, true);
                    }
                    else if ((event->mask == (IN_ISDIR | IN_CREATE)/*1073742080*/) && (strcmp(event->name, "") != 0)) /// 审计创建文件夹
                    {
                        if (0 == add_watch_tree(monitor_path.c_str(), event->name))
                        {
                            cout << "成功创建目录树： " << monitor_path << "/" << event->name << endl;
                        }
                        set_usb_log(802, (char *)monitor_path.c_str(), event->name, true);
                        save_alert(event->mask, 802, (char *)monitor_path.c_str(), event->name, true);
                    }
                    else if ((event->mask == (IN_ISDIR | IN_MOVED_TO)/*1073741952*/) && (strcmp(event->name, "") != 0)) /// 审计移入文件夹
                    {
                        if (0 == add_watch_tree(monitor_path.c_str(), event->name))
                        {
                            cout << "成功移入目录树： " << monitor_path << "/" << event->name << endl;
                        }
                        set_usb_log(802, (char *)monitor_path.c_str(), event->name, true);
                        save_alert(event->mask, 802, (char *)monitor_path.c_str(), event->name, true);
                    }
                    else
                    {
                        goto next;
                    }
                }
                else            /// 针对文件事件
                {
                    memcpy(strbuf, "File", 5);

#if 1
                    /*过滤vim行为*/
                    if(strcmp(event->name, "4913") == 0) {
                        goto next;
                    }
                    if(event->name[strlen(event->name) - 1] == '~') {
                        goto next;
                    }
#endif

                    /// 获取对象的后缀名
                    extension_name = strrchr(event->name, '.');
                    if (extension_name != NULL)
                    {
                        extension_name++;

                        /// 排除某些临时文件 
                        if (event->name[0] == '.')
                        {
                            if (!strncasecmp(extension_name, "SWP", 3) || strncasecmp(extension_name, "SWPX", 4))
                            {
                                goto next;
                            }
                        }
                    }

                    if ((event->mask == IN_CREATE) || (event->mask == IN_MOVED_TO)) /// 审计创建/移入文件
                    {
                        if ((g_pPolicyUdiskActCtrl->AuditCopyIn == "1") && (g_pPolicyUdiskActCtrl->InFileExtName != ""))
                        {
                            if (extension_name != NULL)
                            {
                                if (strcasestr(g_pPolicyUdiskActCtrl->InFileExtName.c_str(), extension_name) != NULL)
                                {
                                    printf("Object type: %s 创建\n", strbuf);
                                    set_usb_log(802, (char *)monitor_path.c_str(), event->name,false);
                                    save_alert(event->mask, 802, (char *)monitor_path.c_str(), event->name,false);
                                }
                            }
                        }
                        else if ((g_pPolicyUdiskActCtrl->AuditCopyIn == "1") && (g_pPolicyUdiskActCtrl->InFileExtName == ""))
                        {
                            printf("Object type: %s 创建\n", strbuf);
                            set_usb_log(802, (char *)monitor_path.c_str(), event->name,false);
                            save_alert(event->mask, 802, (char *)monitor_path.c_str(), event->name,false);
                        }
                        else
                        {
                            goto next;
                        }
                    }
                    else if ((event->mask == IN_DELETE) || (event->mask == IN_MOVED_FROM))   /// 审计删除/移出文件
                    {
                        if ((g_pPolicyUdiskActCtrl->AuditCopyOut == "1") && (g_pPolicyUdiskActCtrl->OutFileExtName != ""))
                        {
                            if (extension_name != NULL)
                            {
                                if (strcasestr(g_pPolicyUdiskActCtrl->OutFileExtName.c_str(), extension_name) != NULL)
                                {
                                    printf("Object type: %s 删除\n", strbuf);
                                    set_usb_log(803, (char *)monitor_path.c_str(), event->name,false);
                                    save_alert(event->mask, 803, (char *)monitor_path.c_str(), event->name,false);
                                }
                            }
                        }
                        else if ((g_pPolicyUdiskActCtrl->AuditCopyOut == "1") && (g_pPolicyUdiskActCtrl->OutFileExtName == ""))
                        {
                            printf("Object type: %s 删除\n", strbuf);
                            set_usb_log(803, (char *)monitor_path.c_str(), event->name,false);
                            save_alert(event->mask, 803, (char *)monitor_path.c_str(), event->name,false);
                        }
                        else
                        {
                            goto next;
                        }
                    } else if (event->mask == IN_MODIFY) {
                        int match_flag = 0;
                        if ((g_pPolicyUdiskActCtrl->AuditCopyOut == "1") && (g_pPolicyUdiskActCtrl->OutFileExtName != ""))
                        {
                            if (extension_name != NULL)
                            {
                                if (strcasestr(g_pPolicyUdiskActCtrl->OutFileExtName.c_str(), extension_name) != NULL)
                                {
                                    printf("Object type: %s 修改 %d\n", strbuf, __LINE__);
                                    set_usb_log(102, (char *)monitor_path.c_str(), event->name,false);
                                    save_alert(event->mask, 102, (char *)monitor_path.c_str(), event->name,false);
                                    match_flag++;
                                }
                            }
                        }
                        else if ((g_pPolicyUdiskActCtrl->AuditCopyOut == "1") && (g_pPolicyUdiskActCtrl->OutFileExtName == ""))
                        {
                            printf("Object type: %s 修改 %d\n", strbuf, __LINE__);
                            set_usb_log(102, (char *)monitor_path.c_str(), event->name,false);
                            save_alert(event->mask, 102, (char *)monitor_path.c_str(), event->name,false);
                            match_flag++;
                        }

                        if((g_pPolicyUdiskActCtrl->AuditCopyIn == "1") && (g_pPolicyUdiskActCtrl->InFileExtName != ""))
                        {
                            if (extension_name != NULL)
                            {
                                if (strcasestr(g_pPolicyUdiskActCtrl->InFileExtName.c_str(), extension_name) != NULL)
                                {
                                    printf("Object type: %s 修改 %d\n", strbuf, __LINE__);
                                    set_usb_log(103, (char *)monitor_path.c_str(), event->name,false);
                                    save_alert(event->mask, 103, (char *)monitor_path.c_str(), event->name,false);
                                    match_flag++;
                                }
                            }

                        }
                        else if((g_pPolicyUdiskActCtrl->AuditCopyIn == "1") && (g_pPolicyUdiskActCtrl->InFileExtName == "")) 
                        {
                            printf("Object type: %s 修改 %d\n", strbuf, __LINE__);
                            set_usb_log(103, (char *)monitor_path.c_str(), event->name,false);
                            save_alert(event->mask, 103, (char *)monitor_path.c_str(), event->name,false);
                            match_flag++;
                        } 
                        if(match_flag == 0) {
                            goto next;
                        }
                    }
                    else if (event->mask == IN_CLOSE_NOWRITE) /// 审计读文件
                    {
                        if ((g_pPolicyUdiskActCtrl->AuditCopyOut == "1") && (g_pPolicyUdiskActCtrl->OutFileExtName != ""))
                        {
                            if (extension_name != NULL)
                            {
                                if (strcasestr(g_pPolicyUdiskActCtrl->OutFileExtName.c_str(), extension_name) != NULL)
                                {
                                    printf("Object type: %s 关闭不写 %d\n", strbuf, __LINE__);
                                    set_usb_log(102, (char *)monitor_path.c_str(), event->name,false);
                                    save_alert(event->mask, 102, (char *)monitor_path.c_str(), event->name,false);
                                }
                            }
                        }
                        else if ((g_pPolicyUdiskActCtrl->AuditCopyOut == "1") && (g_pPolicyUdiskActCtrl->OutFileExtName == ""))
                        {
                            printf("Object type: %s 关闭不写 %d\n", strbuf, __LINE__);
                            set_usb_log(102, (char *)monitor_path.c_str(), event->name,false);
                            save_alert(event->mask, 102, (char *)monitor_path.c_str(), event->name,false);
                        }
                        else
                        {
                            goto next;
                        }
                    }
#if 1
                    else if(event->mask == IN_CLOSE_WRITE) {
                        if((g_pPolicyUdiskActCtrl->AuditCopyIn == "1") && (g_pPolicyUdiskActCtrl->InFileExtName != ""))
                        {
                            if (extension_name != NULL)
                            {
                                if (strcasestr(g_pPolicyUdiskActCtrl->InFileExtName.c_str(), extension_name) != NULL)
                                {
                                    std::cout << "关闭且写文件: " << monitor_path + "/" << event->name << " " <<__LINE__ <<std::endl;
                                    set_usb_log(103, (char *)monitor_path.c_str(), event->name,false);
                                    save_alert(event->mask, 103, (char *)monitor_path.c_str(), event->name,false);
                                }
                            }

                        }
                        else if((g_pPolicyUdiskActCtrl->AuditCopyIn == "1") && (g_pPolicyUdiskActCtrl->InFileExtName == "")) 
                        {

                            std::cout << "关闭且写文件: " << monitor_path + "/" << event->name << " " <<__LINE__ <<std::endl;
                            set_usb_log(103, (char *)monitor_path.c_str(), event->name,false);
                            save_alert(event->mask, 103, (char *)monitor_path.c_str(), event->name,false);
                        } 
                    }
#endif

#if 0               
                    ///这里屏蔽掉文件的只读操作，原因是操作系统本身存在大量的只读操作
                    ///目前也没有好的方法进行屏蔽，所以该功能暂时屏蔽
                    else if (event->mask == IN_CLOSE_NOWRITE) /// 审计打开文件
                    {
                        if ((g_pPolicyUdiskActCtrl->AuditCopyOut == "1") && (g_pPolicyUdiskActCtrl->OutFileExtName != ""))
                        {
                            if (extension_name != NULL)
                            {
                                if (strcasestr(g_pPolicyUdiskActCtrl->OutFileExtName.c_str(), extension_name) != NULL)
                                {
                                    printf("Object type: %s 读取\n", strbuf);
                                    set_usb_log(102, (char *)monitor_path.c_str(), event->name,false);
                                    save_alert(event->mask, 102, (char *)monitor_path.c_str(), event->name,false);
                                }
                            }
                        }
                        else if ((g_pPolicyUdiskActCtrl->AuditCopyIn == "1") && (g_pPolicyUdiskActCtrl->InFileExtName == ""))
                        {
                            printf("Object type: %s 读取\n", strbuf);
                            set_usb_log(102, (char *)monitor_path.c_str(), event->name,false);
                            save_alert(event->mask, 102, (char *)monitor_path.c_str(), event->name,false);
                        }
                        else
                        {
                            goto next;
                        }
                    }
#endif
                    else
                    {
                        goto next;
                    }
                }

                goto next;
            }
next:
            tmp_len = sizeof(struct inotify_event) + event->len;
            event = (struct inotify_event *)(offset + tmp_len);
            offset += tmp_len;
            sort_alert();
            send_alert();
        }
    }
    pthread_exit(0);
}



bool udisk_act_ctrl_init() 
{
    cout<<"enter udisk_act_ctrl_init() "<<endl;


    g_adv_enable_udiskact = true;
    g_GetEventNotifyinterface()->registerEvent(enNotifyer_policyAdvcfg_statChange,advcfg_statchage);

    edp_inotify_fd = inotify_init();
    if (edp_inotify_fd < 0)
    {
        cout<<"Fail to initialize inotify."<<endl;
        exit(-1);
    }

    int rc1 = 0;
    rc1 = pthread_create(&tid1, NULL, handle_change_thread, NULL);
    if (rc1 != 0) {
        cout<<"udisk act ctrl inotify thread create failed"<<endl;
        exit(-1);
    }

    cout<<"leave udisk_act_ctrl_init() "<<endl;

    return  true ;
}

/*ret == S */
typedef struct match_label_ret {
    bool ret;
    std::string mode;
    match_label_ret() {
        ret = false;
        /*default to ban*/
        mode = "X";
    }
} match_label_ret_t;


static inline std::string change_all_to_swap_mode(const std::string &org_mode) {
    std::string default_mode = "X";
    if(org_mode.empty()) {
        return default_mode;
    }
    if(org_mode.at(0) == '-') {
        return default_mode;
    } else {
        default_mode = org_mode.substr(0, 1);
    }
    return default_mode;
}

static bool match_s_label_info(const std::vector<label_auth_info_t> &label_ctl,  
        const label_usb_info_t &linfo, match_label_ret_t &ret) {
    /*TODO: add contidtion to linfo*/
    /*ret default to false*/
    if(label_ctl.empty()) {
        /*default to ban*/
        ret.ret = false;
        return false;
    }
    size_t i = 0;
    bool match_flag_label = false;
    for(; i < label_ctl.size(); i++) {
        if(label_ctl.at(i).name != linfo.s_label) {
            continue;
        }
        match_flag_label = true;
        break;
    }
    /*match right*/
    if(!match_flag_label) {
        ret.ret = false;
        return false;
    }

    /*only concern the swap area*/
    ret.mode = change_all_to_swap_mode(label_ctl.at(i).right);
    ret.ret = true;
    return true;
}


static void kick_usb_dev(const std::string &dev_path) {
    /*bad imp replace to ioctl later*/
    std::string action_cmd_prefix = "umount --force ";
    if(access(dev_path.c_str(), F_OK) != 0) {
        std::string umount_cmd = action_cmd_prefix + dev_path;
        std::cout << "umount partion usb: " << dev_path <<std::endl;
        (void)system(umount_cmd.c_str());
        return;
    }
    std::vector<string>  partion_list;
    int ret = udisk_get_dev_partion(dev_path.c_str(), partion_list);
    if(ret < 0) {
        return;
    }
    for(size_t _i = 0; _i < partion_list.size(); _i++) {
        std::string umount_cmd = action_cmd_prefix + partion_list.at(_i);
        std::cout << "umount normal usb: " << partion_list.at(_i) <<std::endl;
        (void)system(umount_cmd.c_str());
    }
}

static inline bool udisk_need_report(const std::string &dev_path) {
    std::map<std::string, report_usb_info_t>::iterator iter = 
        g_current_device_info.find(dev_path);
    if(iter == g_current_device_info.end()) {
        return true;
    }
    if(!iter->second.report) {
        return true;
    }
    return false;
}

static inline bool udisk_need_process(const std::string &dev_path) {
    std::map<std::string, report_usb_info_t>::iterator iter = 
        g_current_device_info.find(dev_path);
    if(iter == g_current_device_info.end()) {
        return true;
    }
    if(!iter->second.process) {
        return true;
    }
    return false;
}



static void combo_descram(const std::string &dev_path, int usb_type, const std::string &access_mode) {
    udisk_stat_info udisk_info;
    strcpy(udisk_info.udisk_path, dev_path.c_str());
    udisk_info.type = usb_type;
    std::cout << "before call combo descram" << std::endl;
    if(udisk_get_stat(&udisk_info) != UD_SUCCESS) {
        /*normal usb not handle here*/
        std::cout << " Get UD Status Falid" << std::endl;
    } else if(udisk_info.stat == UD_SCRAMBLE && udisk_need_process(dev_path)){
        std::cout << "is decram ?" << udisk_info.stat <<std::endl;
        char mnt_mode = access_mode == "R" ? 'R' : \
                        (access_mode == "W") ? 'W' : 'R';
        if(udisk_descramble(&udisk_info, mnt_mode) != UD_SUCCESS) {
            std::cout << "udisk_descramble error kick usb" << std::endl;
            kick_usb_dev(dev_path);
            return;
        } 
        g_current_device_info[dev_path].process = true;
        g_current_device_info[dev_path].mount_point.push_back(udisk_info.node_path);
        std::cout << "processed access_mode is: " << access_mode << std::endl;
    }
}

static void associate_report_info(const std::string &dev_path, const std::string &dep, 
        const std::string &office, const std::string &uname) {
    if(g_current_device_info[dev_path].department.empty() && !dep.empty()) {
        g_current_device_info[dev_path].department = dep;
    }
    if(g_current_device_info[dev_path].office.empty() && !office.empty()) {
        g_current_device_info[dev_path].office = office;
    }
    if(g_current_device_info[dev_path].user_name.empty() && !uname.empty()) {
        g_current_device_info[dev_path].user_name = uname;
    }
}

/*mount_with_right and check*/
static void mount_with_right(const std::string &dev_path, 
        std::vector<std::string> &mount_dir, const std::string &right) {
    std::vector<string>  partion_list;
    int ret = udisk_get_dev_partion(dev_path.c_str(), partion_list);
    if(ret < 0) {
        return;
    }
    std::string mode_str = "-o ro";
    if(right == "W") {
        mode_str = "-o rw";
    }
	char template_node[64] = "/media/vrvXXXXXX";
    char node_name[64] = {0};
    for (size_t i = 0; i < partion_list.size(); i++) {
        char mountdir[256] = { 0 };
        char mount_cmd[PATH_MAX] = {0}; /*may exceed*/
        int is_readonly;
        ret = get_mountdir_from_partion(partion_list[i].c_str(), mountdir, 256, is_readonly);
        if(ret != 1) {
            /*mount here*/
            memset(node_name, 0, sizeof(node_name));
            strcpy(node_name, template_node);
            if(mkdtemp(node_name) == NULL) {
                std::cout << "make dir error in media" << std::endl;
                continue;
            }
            snprintf(mount_cmd, PATH_MAX, "mount %s %s %s",  
                    mode_str.c_str(), partion_list[i].c_str(), node_name);
            system(mount_cmd);
            /*TODO: VERIFY SUCCESS*/
            mount_dir.push_back(node_name);
            continue;
        }
        if((right == "R" && is_readonly != 1) || (right == "W" && is_readonly != 0)) {
            std::string um_cmd = "umount --force ";
            um_cmd += partion_list[i];
            system(um_cmd.c_str());
            memset(node_name, 0, sizeof(node_name));
            strcpy(node_name, template_node);
            if(mkdtemp(node_name) == NULL) {
                std::cout << "make dir error in media" << std::endl;
                continue;
            }
            snprintf(mount_cmd, PATH_MAX, "mount %s %s %s",  
                    mode_str.c_str(), partion_list[i].c_str(), node_name);
            system(mount_cmd);
            std::cout << " remount to " << partion_list[i] << " "<<node_name << std::endl;
            mount_dir.push_back(node_name);
        } 
        /*umount ---> mount with right*/
    }
}


static void pretreatment_label_usb(const std::string &g_label, 
        const std::vector<label_auth_info_t> &label_ctl, 
        const label_usb_info_t &linfo, const std::string &dev_path) {
    /*linfo read_info_from_label_usb*/
    /*label_ctl get from policy*/
    std::string our_dep_faild_mode = "";
    std::string other_dep_faild_mode = "";
    std::string our_promote = "";
    std::string ohter_promote = "";
    bool our_can_promote = false, other_can_promote = false;
    if(g_pPolicyUdiskActCtrl) {
        our_dep_faild_mode = change_all_to_swap_mode(g_pPolicyUdiskActCtrl->FailedForReadOnly);
        /*default to ban*/
        other_dep_faild_mode = 
            change_all_to_swap_mode(g_pPolicyUdiskActCtrl->FailedOnOtherDeptmentForReadOnly);
        /*default to ban*/
        our_can_promote = !(g_pPolicyUdiskActCtrl->InsideNoWarning.empty() ? false : \
                          (g_pPolicyUdiskActCtrl->InsideNoWarning == "0" ? false : true));
        other_can_promote = !(g_pPolicyUdiskActCtrl->OutSideNoWarning.empty() ? false : \
                          (g_pPolicyUdiskActCtrl->OutSideNoWarning == "0" ? false : true));
        our_promote = g_pPolicyUdiskActCtrl->PromptInfo;
        ohter_promote = g_pPolicyUdiskActCtrl->PromptOnOtherDeptmentInfo;
    }
    /*TODO: should we use compname name ?*/
    /*other comp just frist*/
    /*normal usb(g_label will be empty) or other dep usb*/
    if(strncmp(linfo.g_label.c_str(), g_label.c_str(), 
                linfo.g_label.length()) != 0) {
        /*othrer dep auth failed*/
        /*only match the swap area*/
        /*when other dep auth failed, we don't know how to decrypt the u disk
         *so treate all contidtion as kick_usb_dev now!*/
        if(other_dep_faild_mode == "X") {
            /*ban*/
            kick_usb_dev(linfo.dev_path);
            std::cout << " other dep auth failed and config to X" << std::endl;
        } else if(other_dep_faild_mode == "W") {
            std::cout << " other dep auth failed and config to W" << std::endl;
            kick_usb_dev(linfo.dev_path);
            /*read write*/
        } else if(other_dep_faild_mode == "R") {
            std::cout << " other dep auth failed and config to R" << std::endl;
            kick_usb_dev(linfo.dev_path);
            /*read only*/
        }
        if(udisk_need_report(linfo.dev_path)) {
            report_usb_info_t report_info;
            report_info.access_mode = other_dep_faild_mode;
            report_info.content = "插入外单位认证失败U盘, U盘禁止访问";
            report_info.auth_ret = false;
            report_info.report = true;
            g_current_device_info[linfo.dev_path] = report_info;
            set_usb_log(100, (char *)linfo.dev_path.c_str(), 
                    NULL,false, report_info.content);
        }
        if(other_can_promote) {
            send_tips_to_ui_udisk_action(ohter_promote);
        }
        printf("%s\n", "Other Dep label usb return");
        return;
    } else {
        /*if g_label same the type will be NORMAL_LABEL_USB or SAFE1_USB SAFEX_USB*/
        switch(linfo.usb_type) {
            case SAFE1_USB:
            case NORMAL_LABEL_USB: {
               match_label_ret_t ret;
               if(!match_s_label_info(label_ctl, linfo, ret)) {
                   /*our dep auth failed 
                    *X --> kick_usb_dev W, R will decrypt it and monut with rights*/
                   if(our_dep_faild_mode == "X") {
                       kick_usb_dev(linfo.dev_path);
                       std::cout << " our dep auth failed and config to X" << std::endl;
                   } else if(our_dep_faild_mode == "R" || our_dep_faild_mode == "W") {
                       std::cout << "Falid auth to mode" << our_dep_faild_mode <<std::endl;
                       if(linfo.usb_type == NORMAL_LABEL_USB) {
                           std::vector<std::string> mount_dirs;
                           mount_with_right(linfo.dev_path, mount_dirs, our_dep_faild_mode);
                           g_current_device_info[linfo.dev_path].mount_point = mount_dirs;
                           associate_report_info(linfo.dev_path, linfo.department, 
                                   linfo.office, linfo.username);
                       } else if(linfo.usb_type == SAFE1_USB) {
                           combo_descram(linfo.dev_path, linfo.usb_type, our_dep_faild_mode);
                           associate_report_info(linfo.dev_path, linfo.department, 
                                   linfo.office, linfo.username);
                       }
                   } 
                   if(udisk_need_report(linfo.dev_path)) {
                       report_usb_info_t report_info;
                       report_info.access_mode = our_dep_faild_mode;
                       report_info.content = "插入本单位认证失败U盘, ";
                       if(report_info.access_mode == "X") {
                           report_info.content += "U盘禁止访问";
                       } else if(report_info.access_mode == "W") {
                           report_info.content += "U盘读写访问";
                       } else if(report_info.access_mode == "R") {
                           report_info.content += "U盘只读访问";
                       }
                       report_info.auth_ret = ret.ret;
                       report_info.report = true;
                       g_current_device_info[linfo.dev_path] = report_info;
                       set_usb_log(100, (char *)linfo.dev_path.c_str(), 
                               NULL,false, report_info.content);
                   }
                   if(our_can_promote) {
                       send_tips_to_ui_udisk_action(our_promote);
                   }
                   return;
               }
               std::cout << "our dep auth Success to label usb and right is " 
                   << ret.mode << std::endl;
               if(linfo.usb_type == SAFE1_USB && ret.mode != "X") {
                   /*desambel here and mount with rights here*/
                   combo_descram(linfo.dev_path, linfo.usb_type, ret.mode);
                   associate_report_info(linfo.dev_path, linfo.department, 
                           linfo.office, linfo.username);
               } else if(linfo.usb_type == NORMAL_LABEL_USB) {
                   if(ret.mode == "R") {
                       /*mount read only*/
                       std::vector<std::string> mount_dirs;
                       mount_with_right(linfo.dev_path, mount_dirs, ret.mode);
                       g_current_device_info[linfo.dev_path].mount_point = mount_dirs;
                       associate_report_info(linfo.dev_path, linfo.department, 
                               linfo.office, linfo.username);
                   } else if(ret.mode == "X") {
                       kick_usb_dev(linfo.dev_path);
                       /*umount*/
                   }
               }
               if(udisk_need_report(linfo.dev_path)) {
                   report_usb_info_t report_info;
                   report_info.content = "插入本单位认证成功U盘";
                   report_info.access_mode = ret.mode;
                   report_info.auth_ret = ret.ret;
                   report_info.report = true;
                   g_current_device_info[linfo.dev_path] = report_info;
                   set_usb_log(100, (char *)linfo.dev_path.c_str(), 
                           NULL,false, "插入本单位认证成功U盘");
               }
               break;
            }
            case SAFEX_USB: {
                std::cout << "Not Support for SAFEX_USB" << std::endl;
                break;
            }
            default:
                break;
        }
    }
}

static void pretreatment_all_usb(const std::string &mode, bool enable_label_usb,
        const std::vector<label_auth_info_t> &label_ctl,
        const std::string &g_label) {
    get_usb_dev_list();
    for(size_t i = 0; i < usb_dev_list.size(); i++) {
        label_usb_info_t info;
        int sector_size = get_sector_size(usb_dev_list.at(i).dev);
        sector_size = sector_size > 0 ? sector_size : 512;
        std::cout << "sector size" << sector_size <<std::endl;
        int usb_mode  = read_info_from_label_usb(info, usb_dev_list.at(i).dev, 
                g_label, sector_size);
        std::cout << "usb mode is: " << usb_mode <<std::endl;
        if((usb_mode == SAFE1_USB || usb_mode == NORMAL_LABEL_USB) && enable_label_usb) {
            pretreatment_label_usb(g_label, label_ctl, info, usb_dev_list.at(i).dev);
            continue;
        }
        if(usb_mode != NORMAL_USB) {
            continue;
        }
        /*TODO: change control usb to ioctl usbfs_ioctl 
         *      current we use a low method umount..*/
        std::string action_cmd_prefix = "umount ";
        std::vector<std::string> action_cmds;
		if(enable_label_usb) {
				kick_usb_dev(usb_dev_list.at(i).dev);
				std::string ohter_promote = "";
				bool other_can_promote = false;
				if(g_pPolicyUdiskActCtrl) {
						other_can_promote = !(g_pPolicyUdiskActCtrl->OutSideNoWarning.empty() ? false : \
										(g_pPolicyUdiskActCtrl->OutSideNoWarning == "0" ? false : true));
						ohter_promote = g_pPolicyUdiskActCtrl->PromptOnOtherDeptmentInfo;
				}
				if(other_can_promote) {
						send_tips_to_ui_udisk_action(ohter_promote);
				}
				if(udisk_need_report(usb_dev_list.at(i).dev)) {
						report_usb_info_t report_info;
						report_info.access_mode = "X";
						report_info.content = "插入外单位认证失败U盘, U盘禁止访问";
						report_info.auth_ret = false;
						report_info.report = true;
						g_current_device_info[usb_dev_list.at(i).dev] = report_info;
						set_usb_log(100, (char *)usb_dev_list.at(i).dev.c_str(), 
										NULL,false, report_info.content);
				}
				continue;

        }
        if(mode == "0") {
            kick_usb_dev(usb_dev_list.at(i).dev);
            /*kick normal usb keep other usb*/
        } else if(mode == "1") {
            /*readonly for normal usb*/
            std::cout << "not support readonly yet" << std::endl;
        } else if(mode == "2") {
            /*read write*/
            std::cout << "read write just leave it along" << std::endl;
        }
    }
}

static int media_vrv_filter(const struct dirent *entry) {
    if(entry->d_type == DT_DIR && (strcmp(entry->d_name, "vrv") > 0)) {
        return 1;
    }
    return 0;
}

static void purge_all_media_vrv_tmpdir() {
    /*1.find proc mount point
     *2.find */
    const char *proc_mount = "/proc/mounts";
    if(access(proc_mount, F_OK) != 0) {
        return;
    }
    std::ifstream infile(proc_mount);
    if(!infile.is_open()) {
        return;
    }
    std::stringstream buf;
    buf << infile.rdbuf();
    infile.close();
    std::string line = "";
    std::string mount_point = "";
    std::vector <std::string> mount_points;
    std::string common_prefix = "/dev/sd";
    while(getline(buf, line)) {
        line = YCommonTool::trim(line);
        if(YCommonTool::startwith(line, common_prefix)) {
            char tmp[PATH_MAX] = {0};
            sscanf(line.c_str(), "%*s %s %*s %*s %*s %*s", tmp);
            if(tmp[0] == '\0') {
                continue;
            }
            if(strstr(tmp, "/media/vrv") != NULL) {
                mount_points.push_back(tmp);
            }
        }
    }
    std::vector<std::string> to_delete_dir;
    struct dirent **namelist;
    int n;
    n = scandir("/media/", &namelist, media_vrv_filter, alphasort);
    if(n < 0) {
        return;
    }
    while (n--) {
        printf("dir ---> scan %s\n", namelist[n]->d_name);
        if(mount_points.empty()) {
            std::string dtmp = "/media/";
            dtmp.append(namelist[n]->d_name);
            if(std::find(to_delete_dir.begin(), to_delete_dir.end(), dtmp) 
                    == to_delete_dir.end()) {
                to_delete_dir.push_back(dtmp);
            }
        } else {
            bool find_flag = false;
            for(size_t i = 0; i < mount_points.size(); i++) {
                if(mount_points.at(i).find(namelist[n]->d_name) 
                        != std::string::npos) {
                    find_flag = true;
                    break;
                    }
            }
            if(!find_flag) {
                std::string dtmp = "/media/";
                dtmp.append(namelist[n]->d_name);
                if(std::find(to_delete_dir.begin(), to_delete_dir.end(), dtmp) 
                        == to_delete_dir.end()) {
                    to_delete_dir.push_back(dtmp);
                }
            }
        }
        free(namelist[n]);
    }
    free(namelist);
    for(size_t i = 0; i < to_delete_dir.size(); i++) {
        rmdir(to_delete_dir.at(i).c_str());
        std::cout << "rm dir " << to_delete_dir.at(i) <<std::endl;
    }
    /*replace the \040 aka space in proc/mout WTF...*/
    //YCommonTool::replace_all(mount_point, "\\040", " ");
    //LOG_DEBUG_IMP("moutn point is %s ", mount_point.c_str());
    
    return;
}


bool udisk_act_ctrl_worker(CPolicy * pPolicy, void * pParam) {
    std::cout<<"enter  udisk_act_ctrl_worker()"<< std::endl;
    if(pPolicy->get_type() != UDISK_ACT_CTRL) {
        return false ;
    }

    g_pPolicyUdiskActCtrl= (CUdiskActCtrl*)pPolicy;

    if(g_pPolicyUdiskActCtrl == NULL) {
        std::cout << "policy pointer is null worker return" << std::endl;
        return false;
    }

    //std::vector<label_auth_info_dev_t> label_usb_dev_vec;
    std::vector<label_auth_info_t> &ref_auth_info = 
        g_pPolicyUdiskActCtrl->get_label_auth();

    bool enable_label_usb = 
        g_pPolicyUdiskActCtrl->IdentityFlagLevel2.empty() ? false : \
        (g_pPolicyUdiskActCtrl->IdentityFlagLevel2 == "0" ? false : true);
    pretreatment_all_usb(g_pPolicyUdiskActCtrl->CanUseUSB, 
            enable_label_usb, ref_auth_info,
            g_pPolicyUdiskActCtrl->IdentityStringLevel1);
#if 0
    label_usb_info_t linfo;
    std::string dev_path = "/dev/sdb";
    std::string g_label = g_pPolicyUdiskActCtrl->IdentityStringLevel1;
    /*test fix*/
    read_info_from_label_usb(linfo, dev_path, g_label, 512);
    std::cout << " --- DUMP OUT VALUE ---" << std::endl;
    std::cout << linfo.g_label << std::endl;
    std::cout << linfo.s_label << std::endl;
    std::cout << linfo.department << std::endl;
    std::cout << linfo.office << std::endl;
    std::cout << linfo.username << std::endl;
#endif

    if(old_crcvalue != g_pPolicyUdiskActCtrl->get_crc()) {
        cout<<"pocliy change init all vars..."<<endl;
        std::vector<wd_name>::iterator iter = wd_name_list.begin();
        for (; iter != wd_name_list.end(); iter++) {
            iter->wdelem.clear();
        }
        wd_name_list.clear();
        usb_dev_list.clear();
        vecExceptFile.clear();
        alert_vector.clear();
        ///save policy crc
        old_crcvalue = g_pPolicyUdiskActCtrl->get_crc();
    }

    std::vector<wd_name>::iterator iter = wd_name_list.begin();
    for (iter = wd_name_list.begin(); iter != wd_name_list.end(); iter++) {
        if (access(iter->inotify_usb_partion.c_str(), F_OK) != 0) {
            string path_set_str = "";
            path_set_str=iter->mountdir;
            if (g_pPolicyUdiskActCtrl->ReportDrawRemoveDisk == "1") {
                set_usb_log(105, (char*)path_set_str.c_str(), 
                        (char*)path_set_str.c_str(),false);
            }
            kick_usb_dev(iter->inotify_usb_partion);
            std::string whole_dev = iter->inotify_usb_partion.substr(0, 
                    iter->inotify_usb_partion.find_first_of("0123456789"));
            /*for safe*/
            std::vector<std::string> mount_points = g_current_device_info[whole_dev].mount_point;
            for(size_t mp = 0; mp < mount_points.size(); mp++) {
                rmdir(mount_points.at(mp).c_str());
            }
            g_current_device_info.erase(whole_dev);
            std::cout << "after remove" << g_current_device_info.size() <<std::endl;

            std::vector<wd_element>::iterator iterElem = iter->wdelem.begin();
            for(; iterElem != iter->wdelem.end(); iterElem++) {
                inotify_rm_watch(edp_inotify_fd, iterElem->wd);
            }
            iter->wdelem.clear();
            wd_name_list.erase(iter);
            iter--;
        }
    }

    ///获取所有USB设备列表
    get_usb_dev_list();
    for (size_t usb_i = 0; usb_i < usb_dev_list.size(); usb_i++) {
        ///获取该设备的所有分区列表
        std::vector<string>  partion_list;
        int ret = udisk_get_dev_partion(usb_dev_list[usb_i].dev.c_str(), partion_list);
        if(ret < 0) {
            continue ;
        }
        ///对该设备的所有分区做出处理
        for (size_t i = 0; i < partion_list.size(); i++) {
            ///获取该分区的挂载点
            char mountdir[256] = { 0 };
            int is_readonly;
            ret = get_mountdir_from_partion(partion_list[i].c_str(), mountdir, 256, is_readonly);
            ///如果挂载点获取成功，则做出相应处理，第一个处理是U盘的控制， 第二个处理是U盘的文件的监视
            if (ret == 1)
            {
                bool isFind = listDir(mountdir);

                ///加入到监视列表数组
                if (!search_partion(partion_list[i]) && (!isFind))
                {
                    wd_element wd_ele_tmp;
                    wd_name wd_name_tmp;
                    strncpy(wd_ele_tmp.name, mountdir, 255);
                    int wd;
                    wd = inotify_add_watch(edp_inotify_fd, wd_ele_tmp.name, IN_ALL_EVENTS);
                    int k = AddWatch(mountdir, wd_name_tmp);
                    if ((wd > 0) && (k == 0))
                    {
                        wd_ele_tmp.wd = wd;
                        wd_name_tmp.inotify_usb_partion = partion_list[i];
                        wd_name_tmp.wdelem.push_back(wd_ele_tmp);
                        wd_name_list.push_back(wd_name_tmp);	///监视目录
                        if (g_pPolicyUdiskActCtrl->UDiskAction == "0")
                        {
                            set_usb_log(100, (char *)partion_list[i].c_str(), NULL,false);
                        }
                    }
                    else
                    {
                        printf("Can't add watch for %s.\n", mountdir);
                    }
                }
            }
        }
    }
    /*purge all /media/vrvxxx*/
    /*TODO: REMOVE UNPURGED mount point*/
    purge_all_media_vrv_tmpdir();
    cout<<"leave  udisk_act_ctrl_worker()"<<endl;
    return true;
}

void udisk_act_ctrl_uninit() 
{
    cout<<"enter udisk_act_ctrl_uninit()"<<endl;

    int res;
    void *thread_result = NULL;

    res = pthread_cancel(tid1);
    res = pthread_join(tid1, &thread_result);
    g_GetEventNotifyinterface()->UnregisterEvent(enNotifyer_policyAdvcfg_statChange,advcfg_statchage);
    close(edp_inotify_fd);

    vector<wd_name>::iterator iter = wd_name_list.begin();
    for (; iter != wd_name_list.end(); iter++)
    {
        iter->wdelem.clear();
    }
    wd_name_list.clear();
    usb_dev_list.clear();
    vecExceptFile.clear();

    cout<<"leave udisk_act_ctrl_uninit()"<<endl;
    return;

}

