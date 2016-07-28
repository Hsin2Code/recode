#ifndef RUN_POLICY_FILE_XXXX_XX
#define RUN_POLICY_FILE_XXXX_XX

#include <string>

#define LEN_FILE_NAME 256
#define LEN_PARAM 256
#define LEN_TIP_MSG 256
#define LEN_STR_INSTALL_CHK_ITEM 256
#define LEN_STR_UP_FILE_ATTR 256

enum option
{
    WRONG,
    RIGHT
};

typedef struct policy_s
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
} policy_st;


typedef struct dl_file_info_s
{
    char full_name[LEN_FILE_NAME + 1];
    int stat_ok; 
} dl_file_info_st;


bool import_xml(const char *content);
void run_policy_sfd(const std::string &policy_content);


#endif

