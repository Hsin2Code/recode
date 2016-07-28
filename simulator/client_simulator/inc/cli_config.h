#ifndef  THIS_IS_CLI_CONFIG_HEADER
#define  THIS_IS_CLI_CONFIG_HEADER
/**************************************
* sharp.young
* EDP客户端配置定义文件
**************************************/

///EDPSERVICE 程序版本
#define EDP_SERVICE_VER     "2.0.7"
///EDP 客户端版本

#define CLIENT_VERSION  "2.2.2.2"
#define EDP_SERVICE_FLOCK   ".EdpService_flock"
#define EDP_WATCHV_FLOCK   ".Watchv_flock"

/**
*   字符串结尾宏定义
*/
#define   WINSRV

#if defined(WINSRV)
	#define STRITEM_TAG_END  "\r\n"
#else
	#define STRITEM_TAG_END  "\n"
#endif


/**
*  目标文件名定义
*/
#define  EDP_GUIAPP_REGISTER "reggui"
#define  EDP_GUIAPP_TRAY   	 "EdpUI"
#define  EDP_SVRAPP_NAME     "EdpService"
#define  EDP_UNINSTALL       "edp_uninstall"


/**
*  硬件平台定义 
*/

#define   HW_SW
#define   HW_X86
//#define     HW_ARM
//#define     HW_ARM64
//#define   HW_LONGXIN

/**
*  操作系统，厂商定义 
*  定义格式OEM_厂商缩写_系统名称
*
*  中标:  ZB
*  凝思:  NS  
*
*/
#define   OEM_ZB_KYLIN  //中标麒麟
//#define   OEM_ZB_PUHUA  //中标普华
//#define   OEM_NS_PANSHI //凝思磐石
//#define   OEM_ZB_UKYLIN //中标U麒麟
//#define   OEM_DP_DEEPIN //深度linux

/**
*  软件包管理方式
*/
//#define PKG_RPM    //rpm
#define PKG_DEB    //debian

#endif
