/////////////////////////////////////////////////////////////////////////
//VRVProtocol.hxx
//vrv
/////////////////////////////////////////////////////////////////////////

#ifndef EXPROTOCOL_H
#define EXPROTOCOL_H

#ifndef __APPLE__
#include <bits/wordsize.h>
#endif

#if __WORDSIZE == 64
    //类型定义
    typedef __int32_t			    BOOL;
    typedef char					CHAR;
    typedef __int32_t				INT;
    typedef __int32_t				LONG;
    typedef unsigned short		    WORD;
    typedef unsigned char		    UCHAR;
    typedef __uint32_t			    UINT;
    typedef __uint32_t		        ULONG;
    typedef unsigned short		    USHORT;
    typedef UCHAR				    BYTE;
    typedef ULONG				    DWORD;
    typedef 	DWORD* 				LPVOID ;
#else
    //类型定义
    typedef long					BOOL;
    typedef char					CHAR;
    typedef int					    INT;
    typedef long					LONG;
    typedef unsigned short		    WORD;
    typedef unsigned char		    UCHAR;
    typedef unsigned int			UINT;
    typedef unsigned long		    ULONG;
    typedef unsigned short		    USHORT;
    typedef UCHAR				    BYTE;
    typedef ULONG				    DWORD;
    typedef 	DWORD* 				LPVOID ;
#endif


/*added by yxl 2012.10.26 begin*/
#ifndef TRUE
#define TRUE	1
#endif
#ifndef FALSE
#define FALSE	0
#endif
/*added by yxl 2012.10.26 end*/
////////////////////////////////////////////////////////////////////////////////////////////////
//m_Type
////////////////////////////////////////////////////////////////////////////////////////////////
#define EX_OK					0		//成功
#define EX_FAIL					1		//注册失败
#define REG_DEVICE_040726		2		//注册计算机						结构 Device
#define SCAN_RESULT				3       //区域管理器发给扫描器的结果		结构 ScanResoult
#define SCAN_ASK_050313			4       //扫描请求							结构 ManageConfig
#define SCAN_NEWIP          	5       //通知管理端修改了ip
#define SCAN_HACK_IP        	6       //通知攻击某个ip					结构 AttackPkt
#define MODOULE_ECHO        	7       //探头回复扫描器					结构 ModouleECHO
#define DEVICE_CHANGE_050313   	8       //设备改变							结构 Device
#define REG_CONFIG				9		//注册成功后管理器发给探头的发配	结构 ManageConfig
#define REG_TRANSFILE			10		//注册成功后管理器下发探头文件		结构 TransFile
#define REG_TRANSFINISH			11		//注册成功后管理器下发探头文件结束

#define TRANS_REG_DEVICE		12		//下级转发给上级的注册信息
#define TRANS_SCAN_RESULT		13		//下级转发给上级的注册信息
#define TRANS_DEVICE_CHANGE		14		//下级转发给上级的注册信息

#define FIND_DAILUP_050103		15		//发现上网						结构 FindDail+Device
#define TRANS_FIND_DAILUP		16		//下级转发给上级的发现上网			结构 FindDail+Device
#define VRV_UPGRADE				17		//请求升级
#define AGENT_PROCESS			18		//探头上报进程信息					结构 AgentHead+Process
#define TRANS_AGENT_PROCESS		19		//下级转发给上级的探头上报进程信息	结构 AgentHead+Process
#define SCAN_CONFIG_050313		20		//扫描器取得自己的扫描配置			结构 ScanConfig+ScanIPRange
#define SCAN_REQUEST_050413		21		//扫描器发给区域管理器的请求
#define TRANS_SCAN_REQUEST  	22		//下级转发给上级的扫描器发给区域管理器的请求
#define DETECT_ACTIVE			23		//探测区域管理器的端口是不是我们的端口
#define	SCAN_GETCHANGE			24		//扫描器发送给区域管理器的获取要阻断或更新操作
#define	AGENT_GETCONFIG			25		//探头从区域管理器取配置判断有没有升级，一天做一次
#define	AGENT_RPTSTATUS_050103	26		//探头上报曾经出过外网后又回到内网
#define DISTRIBUTE_SOFTWARE		27		//软件分发
#define APPLET_GETSQLCFG		28		//地图获取SQL配置
#define	REPORT_DOWNPATCH		29		//上报下载补丁,SUS上报的补丁下载日志
#define	REPORT_SYSTEMPATCH		30		//上报系统补丁
#define	REPORT_SOFTWARE			31		//上报安装软件
#define	REPORT_VIRUS			32		//上报病毒
#define SCAN_NEWDEVICE			33		//扫描器获取新增加的设备
#define AGENT_DOWNLOAD			34		//探头下载文件
#define GET_FILEATTRIBUTE		35		//获得文件属性
#define AGENT_RPTKVS_050313		36		//杀毒软件报警
#define REG_DEVICE				37		//设备注册	REG_DEVICE_050313
#define GET_AGENTPROCESS		38		//web获取探头进程
#define	KILL_AGENTPROCESS		39		//web杀探头进程
#define	GET_PATCH				40		//web求要打的补丁
#define SENDREG_MESSAGE			41		//给探头发重新注册消息
#define AGENT_GET_TASK			42		//探头来取分发任务或者补丁策略
#define LOWERDEPT_DOWNLOAD		43		//级联下载文件
#define AGENT_RPTDEVEX_050622	44		//探头上报设备扩展信息
#define AGENT_RPTNOINSPATCH		45		//探头上报未打补丁
#define AGENT_RPTPATCHSTATUS	46		//探头上报打补丁状态包括下载错误，安装错误，安装时间
#define DETECTAGENT_ISACTIVE	47		//1.保护程序探测探头是否存活，如果返回EX_OK就说明存活 2.探头每1小时上报存活消息
#define GET_AGENTLOG			48		//取探头那边的日志，阻断和违规
#define FIND_DAILUP				49		//字符串方式的违规联网报警
#define	AGENT_RPTSTATUS			50		//字符串方探头上报曾经出过外网后又回到内网
/*
//启动被控与主控程序的通信(已经在探头里面定义了)
#define	CALL_STARTCLIENT		51		//启动anywhere被控端
#define	CALL_STARTSERVER		52		//启动anywhere主控制端
#define CALL_MANAGER			53      //呼叫管理员
*/
#define DISTRIBUTE_POLICY		54		//分发策略
#define DOWNLOAD_POLICY			55		//下载策略
#define DEVICE_CHANGE			56		//设备改变(字符串模式得)
#define SCAN_REQUEST			57		//扫描器发给区域管理器的请求(字符串模式得)
#define SCAN_ASK				58      //扫描请求(字符串模式得)
#define SCAN_CONFIG				59		//扫描器取得自己的扫描配置			结构 ScanConfig+ScanIPRange
#define AGENT_RPTKVS			60		//杀毒软件报警
#define AGENT_RPTAUDITLOG		61		//上报审计日志
#define AGENT_RPTFLUX			62		//上报流量
#define REG_DEVICE_STRING		114
#define REG_TRANSFILE_STRING	115
#define REG_TRANSFINISH_STRING	116

////////////////////////////////////////////////////////////////////////////////
//vrvrf_c.exe
////////////////////////////////////////////////////////////////////////////////
#define T_POLICY_IFCHANGED      63 //询问策略是否改变
#define T_REPORT_POLICYLOG      64 //上报程序传过来的信息,
#define T_REQUEST_DISCON        65 //请求阻断本地地址
#define T_REQUEST_SHUTDOWN      66 //请求关闭计算机
#define T_POLICY_LOGDELETED     67 //本地策略日志已经删除
#define T_WHOCAN_DISCON     	68 //由谁来执行阻断客户端
///////////////点对点标记
#define T_POINT_GET_CPU_MEM_INFO 69  //查看CPU,内存使用情况信息
#define T_POINT_RUNEXE          70   //加载程序
#define T_POINT_GET_IECACHE		71   //查看IE缓存
#define T_POINT_GET_SOFT_INFO	72   //获取软件列表
#define T_POINT_CHANGE_IP		73   //修改IP网络信息
#define T_POINT_GET_SERVICE		81	 //获取服务列表
#define T_POINT_GET_PORT		82	 //获取端口列表
#define T_POINT_GET_CAP			83	 //执行抓包程序
#define T_POINT_GET_SHAREPATH	86
#define T_POINT_MESSAGE			95		//点对点消息
#define T_POINT_KILLVIRUS		96		//点对点启动杀毒软件
#define T_POINT_DEBUGVRVEDP		100		//
#define T_POINT_GET_FILE		101		//
#define T_POINT_BATCH_PATCH		102		//
#define T_POINT_USERGROUP		110
#define T_POINT_WORKDIRECTORYPOLICY		118
#define T_POINT_QUERYFILE				119
#define T_POINT_QUERYPOLICY				121
#define T_POINT_QUERYPATCHSTATE			125
#define T_POINT_UNINSTALLSOFT			128		//卸载软件
//#define T_POINT_FLUXINFO				134		//流量信息
//#define AGENT_RPT_SOCKPROCMOD	137		//探头上报访问网络进程和模块
//#define AGENT_RPT_REGPROCMOD	138		//探头上报进程访问注册表和模块
//const int T_POINT_EVENTFILE = 139;


////////////////////////////////////////////////////////////////////////////////
//end vrvrf_c.exe
////////////////////////////////////////////////////////////////////////////////
#define AGENT_RCVMSGSUCCESS		74		//探头上报接受消息成功
#define AGENT_RPTSOFTSTATUS		75		//探头上报软件分发状态
#define AUTOLOAD_DETECTSTATUS	76		//管理器保护程序探测管理器工作状态
#define AGENT_RPTDEVEX			77		//探头上报设备扩展信息
#define AGENT_SYNTIME			78		//探头时间同步
#define WEB_UPLOAD_FILE			79		//WEB上传文件或者获取上传文件列表
#define IPORMAC_CHANGE			80		//IP和MAC变化报警
#define AGENT_SCANRESOULT		84		//探头扫描到的开机没有探头的设备
#define SCAN_FETCHCACHE			85		//扫描器获取探头扫描到的开机没有注册的设备
#define AGENT_WARNING			87		//探头通用报警
#ifndef SCAN_NOTIFY
#define SCAN_NOTIFY				88		//管理器通知扫描器做相应的操作，比如阻断，消息通知 这个用PktHeadEx
#endif
//#define SCAN_CONNECT			89		//扫描器连接到管理器的两个socket 一个是读，一个是写
//#define SCAN_RESOULT			90		//扫描器上报扫描到的结果
#define	AGENT_ONLINETIME		91		//上报在线时间
#define	AGENT_UPGRADE			92		//探头请求升级，判断版本号
#define	AGENT_RPTRUNLEVEL		93		//探头上报运行等级
#define	AGENT_RPTIDLESTATUS		94		//探头上报空闲状态
#define AGENT_DOWNLOADFILE		97		//文件下载请求
#define AGENT_DOWNLOADFINISH	98		//文件下载完毕
#define AGENT_GETDOWNLOADLIST	99		//探头获取下载IP列表
#define USB_AUTHENTICATION		103		//USB认证
#define AGENT_UPLOADFILE		104		//探头违规上传
#define REPORT_WARCENTER		105		//管理器报警到报警中心
#define USB_ATCIONLOG			106		//制作U盘工作日志
#define AGENT_UPDATEONLYID		107		//探头更新唯一ID
#define DETECT_ENCRYPT			109		//探测是否支持加密
#define AGENT_RPT_PROCESS		111		//进程上报
#define AGENT_RPT_SOFTWARE		112		//软件安装上报
#define AGENT_RPT_SYSTEMPATCH	113		//已安装补丁
#define AGENT_GETCONFIG_STRING	117
#define AGENT_RTP_AMTSTATUS		120		//探头上报AMT计算机所在状态
#define AGENT_RPT_LONGINUSERS	123		//探头上报登陆用户和注册用户
#define AGENT_RPT_IPMACBINDST	124		//探头上IP MAC绑定状态
#define AGENT_RPT_SHAREFOLDERS	126		//探头上报共享目录列表
//#define AGENT_VLAN				127		//802.1x协议
//#define AGENT_YANGDUN_1			129		//阳盾同步
//#define AGENT_RESTOREPOINT		130		//	xp还原
//#define AGENT_RPT_IEPLUGINS		133		//
#define AGENT_REQUEST_UPDATE		136		//新版本的升级接口

//REG_DEVICE 设备注册
#define REG_AUTHENTICATION		1		//密码认证
#define REG_LCS_AUTHENTICATION	2		//license 认证

////////// T_WHOCAN_DISCON m_What如下定义;
#define W_MAINDO_DISCON			0  //由探头执行阻断
#define W_AGENTDO_DISCON		1  //由策略执行辅助程序执行阻断
///////

//阻断模式 在我发送T_WHOCAN_DISCON后 由你回给我 m_What=T_WHOCAN_DISCON m_Type=DISCON_SUPER_MODE
#define DISCON_NORMAL_MODE      0 //正常模式，按策略设定执行
#define DISCON_ALL_MODE         1 //全通模式，所有的IP以及端口都可以使用
#define DISCON_SUPER_MODE       2 //仅允许用户设置的超级IP和超级端口和我们程序需要的IP和端口可以连通，其余的都禁止不通(这个是你目前发送给我的阻断模式)
#define DISCON_DEFAULE_MODE		3 //仅我们程序需要的IP和端口可以连通，其余的都不通

//T_POLICY_IFCHANGED 询问策略是否改变 m_What
#define W_POLICY_NOTCHANGED		0  //策略未改变
#define W_POLICY_CHANGED		1  //策略改变

//启动被控与主控程序的通信(已经在探头里面定义了)

#define	CALL_STARTCLIENT	51		//启动anywhere被控端
#define	CALL_STARTSERVER	52		//启动anywhere主控制端
#define CALL_MANAGER        53      //呼叫管理员
#define	CALL_STARTCLIENT2	151		//启动anywhere被控端
#define	CALL_STARTSERVER2	152		//启动anywhere主控制端
#define CALL_MANAGER2       153     //呼叫管理员
/*added by yxl 2014.6.9 begin*/
//m_type
#define REPORT_CLIENT_SYS_LOG_LINUX     154
//m_what
#define LOG_REPORT_STATE   0 //上报成功，服务器回复，解析失败，回复非零
#define LOG_REFRESH        1 //首次上报
#define LOG_APPEND         2 //追加
/*added by yxl 2014.6.9 end*/

/*added by yxl 2014.6.26 begin*/
//<>classaction=  行为类别上报字段
#define Illegal_Behavior  0  //违规行为
#define Abnormal_Behavior 1  //异常行为
#define General_Behavior  2  //一般行为

//<>riskrank=    风险级别上报字段
#define Event_Emergency 0  //紧急：系统不可用
#define Event_Alarm     1  //警报：必须立即进行处理
#define Event_Critical  2  //关键：符合关键条件
#define Event_Error     3  //错误：符合错误条件
#define Event_Caution   4  //警告：符合警告条件
#define Event_Inform    5  //通知：普通情况，但具有重要意义
#define Event_Message   6  //信息：一般信息消息
#define Event_Debug     7  //调试：调试级别信息
/*added by yxl 2014.6.26 end*/



////////////////////////////////////////////////////////////////////////////////////////////////
//m_What
////////////////////////////////////////////////////////////////////////////////////////////////

//SCAN_GETCHANGE 扫描器发送给区域管理器的获取要阻断或更新操作
#define GETFORCEOUT_UPDATE	1		//扫描器发出的请求
#define ECHOFORCEOUT_UPDATE	2		//给扫描器的回亏

//攻击模式
#define HACK_ARP            1       //发送arp网卡冲突包
#define HACK_DOWN           2       //自动关机
#define HACK_ALLSTYLE       3       //自动关机

//REG_FAIL
#define FAIL_NOIPMALLOC		1		//IP段没有分配
#define FAIL_NETIPRESERVED	2		//此ip段为保留IP段
#define FAIL_NETIPFORBID	3		//此ip段被禁用
#define FAIL_SENDTOUPREG	4		//发给上级管理器注册失败
#define FAIL_COM_ERROR		5		//com初始化失败
#define FAIL_UNKNOWN		6		//未知
#define FAIL_LINCE_ERROR	7		//lcs验证错误
#define FAIL_LINCE_EMPTY	8		//lcs为空

//设备改变
#define IP_CHANGE			1		//IP地址变了
#define MAC_CHANGE			2		//MAC地址变了
#define NAME_CHANGE			4		//设备名称变了
#define ID_CHANGE			8		//硬盘序列号CRC地址变了
#define MEM_CHANGE			16		//内存大小改变了
#define DISKSIZE_CHANGE		32		//硬盘大小改变了
#define	RUNLEVEL_CHANGE		64		//运行等级变化
//发现上网
#define FIND_DAILUPING		1		//正在上网
#define FIND_DAILUPED		2		//曾经上过网
#define FIND_OUTOFNETWORK	4		//曾经上过网

//升级 VRV_UPGRADE
#define REQUEST_UPGRAD		1		//请求升级
#define ECHO_UPGRAD			2		//请求升级的回应
#define FORCE_UPGRAD		3		//请求强制升级

//扫描器获取配置 SCAN_GET_CONFIG
#define CONFIG_GET			1
#define CONFIG_ECHO			2

//区域管理器给扫描器的结果SCAN_RESULT
#define RESOULT_KILL		0x01
#define RESOULT_SUCCESS		0x02
#define RESOULT_REGISTERED	0x04
#define RESOULT_FAIL		0x08
#define RESOULT_CFGKILL		0x10
#define RESOULT_KILLNOTIFY	0x20
#define RESOULT_MANUAL		0x40

//扫描器发给区域管理器的请求	SCAN_REQUEST
#define RUN_ACTIVE			1
#define RUN_SHUTDOWN		2
#define AGENT_UNINSTALL		3
#define AGENT_ACTIVE		4
#define ATTACK_REQUEST		5
//////////////////////////////////////////////////////////
//探测区域管理器的端口是不是我们的端口的请求	DETECT_ACTIVE
#define DETECT_REQUEST		1
#define DETECT_ECHO			2

//探头从区域管理器取配置判断有没有升级，一天做一次 AGENT_GETCONFIG
#define	AGENT_REQUEST		1
#define AGENT_ECHO			2

//探头上报曾经出过外网后又回到内网 AGENT_RPTSTATUS
#define	STATUS_FINDOUT		1

//IP和MAC绑定变化 DEVICE_CHANGE
#define ATTACK_CHANGE		1

//DISTRIBUTE_SOFTWARE 软件分发
//包括(4.11.12)老版本
#define DISTRIBUTE_FILE				1	//文件分发
#define DISTRIBUTE_MSG				2	//消息通知
#define DISTRIBUTE_SCRIPT			3	//执行教本
#define TRANS_DATA					4	//传送数据
#define TRANS_FINISH				5	//数据传送完毕
#define DISTRIBUTE_PATCH_PLOICY		6	//终端补丁策略
#define DISTRIBUTE_PATCH_FILE		7	//终端补丁文件

//改成文件分发为下拉方式的(4.11.12)版本以后不包括(4.11.12)
#define DISTRIBUTE_FILE_2			128	//下拉方式文件分发
#define DISTRIBUTE_MSG_2			129	//消息通知
#define DISTRIBUTE_SCRIPT_2			130	//执行教本
#define DISTRIBUTE_PATCH_PLOICY_2	131	//终端补丁策略
#define DISTRIBUTE_PATCH_FILE_2		132	//终端补丁文件

//出错信息
#define ERROR_OK			0	//OK
#define	ERROR_CRC32			1	//CRC错误
#define	ERROR_PWD			2	//口令错误

//地图获取SQL配置 APPLET_GETSQLCFG	28
#define	APPLET_REQUEST		1
#define APPLET_ECHO			2

//上报系统补丁 REPORT_SYSTEMPATCH
#define PATCH_REFRESH		1	//刷新-把已经存在的记录删掉，用新的替换调
#define PATCH_ADDTAIL		2	//追加
#define PATCH_DELETE		3	//删除

//上报安装软件 REPORT_SOFTWARE
#define SOFTWARE_REFRESH	1  //刷新-把已经存在的记录删掉，用新的替换调
#define SOFTWARE_ADDTAIL	2  //追加
#define SOFTWARE_DELETE		3  //删除已经卸载过的软件

//扫描器获取新增加的设备 SCAN_NEWDEVICE
#define NEWDEVICE_REQUEST	1		//请求
#define NEWDEVICE_ECHO		2		//ECHO

//探头下载文件 AGENT_DOWNLOAD
#define DOWNLOAD_REQUEST	1		//请求
#define DOWNLOAD_OK			2		//ECHO
#define DOWNLOAD_DATAERROR	3		//数据错误
#define DOWNLOAD_RETRYLATER	4		//过一会在试
#define DOWNLOAD_REQUEST_2	5		//新的下载请求,这个给回下载这个文件的列表
#define DOWNLOAD_IPLIST		6		//发送的IP列表
#define DOWNLOAD_FINISH		7		//这个文件下载完毕
#define DOWNLOAD_DISTRIBUTE	8		//分发文件的下载

// GET_FILEATTRIBUTE	35		//获得文件属性
#define FILEATTRIBUTE_REQUEST	1
#define FILEATTRIBUTE_ECHO		2

//AGENT_RPTKVS					//病毒防火墙
#define KVS_SHUTDOWN		1	//处理结果,重启
#define KVS_PROMPT			2	//处理结果,警告提示
#define KVS_CUTNET			4	//断开网络

//GET_AGENTPROCESS
#define AGENTPROCESS_REQUEST 1	//请求
#define AGENTPROCESS_ECHO	 2	//回亏


//REPORT CLIENT_START STOP
#define AGENT_STATUS_REPORT 255
#define CLIENT_START 1
#define CLIENT_STOP  2


//autoload.exe 和 管理器之间通讯协议和错误类型
#define TYPE_ERR_CONNECT		1
#define TYPE_ERR_NOREPORT		2
#define TYPE_ERR_DBNOINIT		4

//报警数据提示信息索引
#define NOTIFY_COUNT			11
//同时连接内外网时：
#define NOTIFY_INOUT_SHUTDOWN	1		//自动关机
#define NOTIFY_INOUT_PROMPT		2		//仅提示
#define NOTIFY_INOUT_CHECK		3		//断开外网候进行安全检查
#define NOTIFY_INOUT_CUTNET		9		//断开网络
//客户端仅在外网中
#define NOTIFY_OUT_SHUTDOWN		4		//自动关机
#define NOTIFY_OUT_PROMPT		5		//仅提示
#define NOTIFY_OUT_CHECK		6		//接回网候进行安全检查
#define NOTIFY_OUT_CUTNET		10		//断开网络
//客户端未运行杀毒软件
#define NOTIFY_KVS_SHUTDOWN		7		//自动关机
#define NOTIFY_KVS_PROMPT		8		//仅提示
#define NOTIFY_KVS_CUTNET		11		//断开网络

//启动被控与主控程序的通信
#define SCREEN_READONLY			0      	//只读启动
#define SCREEN_READWRITE		1		//读写启动

#define _CONNECT_PROMPT			0
#define _CONNECT_PASSWORD		1
#define _CONNECT_AUTO			2

//获取探头日志 GET_AGENTLOG
#define LOG_ATTACK				1
#define LOG_PATIOLATE			2
#define LOG_SETTING				3
#define LOG_PATCH				4
#define LOG_NETWORKDATA			5
#define LOG_HARDWARE			10
#define LOG_SYSTEMLOG			11

//DOWNLOAD_POLICY 下载策略
#define DETECT_POLICY			1
#define GET_POLICY				2
#define ECHO_POLICY				3
#define LOWER_DETECT_POLICY		4
#define LOWER_GET_POLICY		5

//AGENT_RPTAUDITLOG	 上报审计日志
#define AUDITLOG_REQUEST		1	//上报请求
#define AUDITLOG_ECHO			2	//上报回应

//AGENT_RPTFLUX	 上报审计日志
#define FLUX_REQUEST		1	//上报请求
#define FLUX_ECHO			2	//上报回应
#define FLUX_OVERLIMIT		3	//超过流量上限

//AUTOLOAD_DETECTSTATUS 管理器保护程序探测管理器工作状态
#define AUTOLOAD_REQUEST	1	//上报请求
#define AUTOLOAD_ECHO		2	//上报回应

//WEB_UPLOAD_FILE WEB上传文件或者获取上传文件列表
#define GET_FILELIST		1	//获取可分发文件列表
#define UPLOAD_FILE			2	//上传文件
#define UPLOAD_EXPORT_FILE	3	//REGION上传文件

//USB_AUTHENTICATION USB用户认证结果
#define USB_SUCCESS			0
#define USB_FAILED			0x0100
#define USB_FAILED_ONUSER	0x0001
#define USB_FAILED_PASSERR	0x0002
#define USB_FAILED_DBERR	0x0004

/*
只发送一个头，其他没有数据，返回时候也只发还给我一个头
m_PktHead->m_Flag = VRV_FLAG;
m_PktHead->m_Type = CALL_STARTCLIENT||CALL_STARTSERVER;
m_PktHead->m_Pwd = longip; //用这个传请求IP inet_addr()函数转换后的。如果是请求启动被控端，则这个IP是主控端IP,如果这个是请求启动主控端，这个是被控端的IP
m_PktHead->m_What =1;
m_PktHead->PktCrc =MAKEWORD(SCREEN_READONLY||SCREEN_READWRITE,CONNECT_PROMPT||CONNECT_PASSWORD||CONNECT_AUTO);  //被控制端是以读，还是读写方式启动
m_PktHead->PktLen = sizeof(PktHead);


返回
m_what = 2  //启动成功
m_what = 5  //启动主，被控程序出错。
m_what = 10 //探头没有找到主控或，被控程序。
*/



//端口定义
#define DATA_PORT			2388	//传送数据端口
#define ALERT_PORT			2399	//传送数据端口
#define MANAGER_PORT        88		//管理端打开端口，备用端口88＋100
#define SCANER_PORT         22125   //扫描端打开端口，备用端口22125＋100
#define MODOULE_PORT        22104   //探头端打开端口，备用端口22105＋100
#define VRV_FLAG			0x56525620	//2.0
#define VRV_FLAG10			0x56525610	//1.0
#define VRV_FLAG11			0x56525611	//1.1
#define AGENT_VERSION		"6.6.20.3370"
#define VERSION_FLAG		0x565256
#define VRV_DOWNFLAG		0x56525645 //VRVD
#define VRV_NOTIFY			0x5652564E //VRVN
#define AUTOLOADECHO1_SIZE	64
#define PKTHEAD_SIZE		20
#define SCANRESOULT_SIZE	sizeof(ScanResoult)
#define SCANRESOULTEX_SIZE	sizeof(ScanResoultEx)
#define MAX_PKTHEAD_NUM		SCAN_NOTIFY
#define SZ_DEVEX_1			68
//#define SZ_DEVEX_2		72


//DETECT_ACTIVE
#define DETECT_ACTIVE_PROBE 1
#define DETECT_ACTIVE_PROBE_RETURN 2

////////////////////////////////////////////////////////////////////////////////////////////////

struct PktHead
{
	DWORD m_Flag;//VRV1.0=0x56525610
	WORD  m_Type;//类型，是上报注册信息，变化，还是错误信息
	WORD  m_What;//信息内容
	DWORD m_Pwd;
	DWORD PktCrc;
	DWORD PktLen;//包括包头的数据报的长度
};

#endif //EXPROTOCOL_H
