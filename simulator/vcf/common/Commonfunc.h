#ifndef THIS_SI_COMMON_FUNC_header_dafdaljlkjsd3213213
#define THIS_SI_COMMON_FUNC_header_dafdaljlkjsd3213213
/**
 * 	一些常用到的函数 声明
 *
 *  Created on: 2014-11-27
 *      Author: sharp
 */

#ifndef NULL
	#define NULL 0
#endif

#include <vector>
#include <string>
#include <list>
#include <dirent.h>
#include <stdio.h>
#include <pwd.h>
#include <errno.h>


namespace YCommonTool  /// 一般通用工具
{

/**
 * 获得当前时间毫秒数
 */
long int  get_Timemsec();

/**
 * 获得当前的秒数
 */
time_t       get_Timesec();

/**
 * 获取系统启动毫秒数
 */

time_t       get_Startpmsec();
///获取系统启动秒数
time_t       get_Startsec();

/**
 * 获取随机字符串（大写）
 * maxlen为缓冲区长度
 */
void      get_randStr(char * buffer,int maxlen);

///获取网卡信息
int              get_Nicinfo(std::list<std::string> & niclst) ;
///获取网卡IP
std::string      get_ip(std::string & nicname);
///获取MAC
std::string      get_mac(std::string & nicname);
///获取子网掩码
std::string      get_subMask(std::string & nicname);
///获取网关
std::string      get_gatWay(std::string & nicname);


/**
 *	分割字符串
 *	@strsrc : 需要分割原字符串
 *	@vt     : 分割后的字符串数组
 *	@break_str : 分割符
 */
int  split_new(const  std::string & strsrc,
		              std::vector<std::string> & vtdest,
					  std::string  break_str);


/**
 *  用户是否登录
 *  等同与原来的函数的判断作用
 *  @返回值  0:login;1:not login;-1:operate fail
 */
int   is_UserLogin(const char * name);


typedef struct active_user_info {
    std::string user_name;
    std::string home_dir;
    std::string display_no;
    int is_local;
    int uid;
    active_user_info() {
        user_name = "", home_dir = "", display_no = "";
        is_local = -1, uid = -1;
    }
} active_user_info_t;

int   get_active_user_info_systemd(std::vector<active_user_info_t> &active_user_list);


/**
 *  获取虚拟终端的登录用户 可以取代老的 Judge_User_Login
 *  @返回值 0:login;1:not login;-1:operate fail
 *
 *	std::string name ;
 *  比如获取虚拟终端tty1的登录用户:
 *	if(get_ttyloginUser("tty1",name)>0) {
 *  	printf("tty1 loginuser = %s",name.c_str());
 *  }
 *  比如获取远程终端pts/0的登录用户:
 *  if(get_ttyloginUser("pts/0",name)>0) {
 *  	printf("pts/0 loginuser = %s",name.c_str());
 *  }
 */
int   get_ttyloginUser(const char * ttyname , std::string & name);

/**
 * 在非后台运行的情况下获取当前凭据登录用户
 * @返回true获取成功
 */
bool  get_CurloginUser(std::string & user);


/**
 * 终极获取登录函数
 */
void  get_loginUser(std::string & user);

///获取本地事件字符串
///传入数组最短20个字符
void    get_local_time(char strtime[]);

/**
 * 获取所有软件已安装软件的信息，输出到参数指定的文件中。
 * @file 为文件名
 */
int     get_rpm_all(std::string & file);


/**
 * 启动网卡
 * @nic 为网卡名
 */
int   	startup_nic(std::string & nic);

/**
 * 禁止网卡
 * @nic 为网卡名
 */
int     closeup_nic(std::string & nic);


/**
 * 根据自身IP获取网络环境类型
 */
enum  en_netaddrtype {
	addr_mix , ///内外网混杂
	addr_only_internal,///仅内网模式
	addr_only_internet,///仅外网模式
};
en_netaddrtype check_addr_type();


///字符串变大写
char *  strupr(char * sz);

// trim from start
std::string & ltrim(std::string &s);

// trim from end
std::string & rtrim(std::string &s);

// trim from both ends
std::string & trim(std::string &s);

bool startwith(std::string &s, std::string str);

bool endwith(std::string &s, std::string str);

int set_time(const std::string &time_str, int offset, time_t &outval);

std::string exec_cmd(const char* cmd);

/*color log to stdout for debug use*/
void logWarn(int line, const char *func, const char *fmt, ...);
void logErr(int line, const char *func, const char *fmt, ...);
void logInfo(int line, const char *func, const char *fmt, ...);
void logDebug(int line, const char *func, const char *fmt, ...);
void logDebugImp(int line, const char *func, const char *fmt, ...);


/*release version disable this log otherwise may slow down applications
 * TODO: async stdlog to zmq */
#define DEBUG_TO_STDOUT
#ifdef DEBUG_TO_STDOUT
#define LOG_INFO(fmt, ...) \
    YCommonTool::logInfo(__LINE__, __func__, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) \
    YCommonTool::logWarn(__LINE__, __func__, fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...) \
    YCommonTool::logErr(__LINE__, __func__, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) \
    YCommonTool::logDebug(__LINE__, __func__, fmt, ##__VA_ARGS__)
#define LOG_DEBUG_IMP(fmt, ...) \
    YCommonTool::logDebugImp(__LINE__, __func__, fmt, ##__VA_ARGS__)
#else
#define LOG_INFO(fmt, ...) 
#define LOG_WARN(fmt, ...)
#define LOG_ERR(fmt, ...)
#define LOG_DEBUG(fmt, ...)
#define LOG_DEBUG_IMP(fmt, ...)
#endif


}


#endif
