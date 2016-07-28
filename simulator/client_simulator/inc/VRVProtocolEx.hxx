/////////////////////////////////////////////////////////////////////////
//VRVProtocolEx.hxx
//vrv 
/////////////////////////////////////////////////////////////////////////

#ifndef EXPROTOCOL_1_H
#define EXPROTOCOL_1_H

//////////////////////////////////////////////////////////////////////
//CANST VARIABLE 常量定义
//////////////////////////////////////////////////////////////////////

#define VRV_TAG					0x5652
#define PKTHEADEX_SIZE			28

//////////////////////////////////////////////////////////////////////
//END CANST VARIABLE
//////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////
//CBKPARAM m_Type 协议定义
//////////////////////////////////////////////////////////////////////

#define SCAN_OK					0
#define SCAN_RUNSTATUS			1		//扫描器状态
#define SCAN_GETSETTING			3		//扫描器启动获取配置
#ifndef SCAN_NOTIFY
#define SCAN_NOTIFY				88		//管理器通知扫描器做相应的操作，比如阻断，消息通知 这个用PktHeadEx
#endif
#define SCAN_CONNECT			89		//扫描器连接到管理器的两个socket 一个是读，一个是写
#define SCAN_RESOULT			90		//扫描器上报扫描到的结果

//////////////////////////////////////////////////////////////////////
//END CBKPARAM m_Type
//////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////
//CBKPARAM m_What
//////////////////////////////////////////////////////////////////////

//SCAN_RUNSTATUS=1
#define	STATUS_RUN				1		//启动
#define STATUS_STOP				2		//停止
#define STATUS_STARTSCAN		3		//开始扫描
#define STATUS_FINISHSCAN		4		//扫描完毕
#define STATUS_SCANING			5		//正在扫描

//SCAN_NOTIFY=86
#define NOTIFY_ATTACK			1		//阻断某一台计算机
#define NOTIFY_UNATTACK			2		//取消阻断某一台计算机
#define NOTIFY_MESSAGE			3		//消息通知
#define NOTIFY_SETTING			4		//扫描器配置改变
#define NOTIFY_INPUTNEWDEV      5       //添加新设备标识

//SCAN_CONNECT
#define CONNECT_READ			1		//读socket
#define CONNECT_WRITE			2		//写socket

//////////////////////////////////////////////////////////////////////
//END CBKPARAM m_What
//////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////
//STRUCT DEFINE 结构定义
//////////////////////////////////////////////////////////////////////

struct PktHeadEx
{
	DWORD m_Flag;		//VRV2.0=0x56525610 VRV_FLAG
	WORD  m_Type;		//类型，是上报注册信息，变化，还是错误信息
	WORD  m_What;		//信息内容
	DWORD m_Pwd;		//加密密码
	DWORD PktCrc;		//不带头的校验和
	DWORD PktLen;		//包括包头的数据报的长度
	WORD  m_Tag;		//标记  VRV_TAG
	WORD  m_Size;		//头的大小
	DWORD m_Address;	//IP地址
};

//////////////////////////////////////////////////////////////////////
//END STRUCT DEFINE
//////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////
//FUNCTION DECLARE 函数声明
//////////////////////////////////////////////////////////////////////

/*
//CALLBACK 回调函数原形
typedef DWORD ( *_CBKFUN)(PktHeadEx&,LPVOID);
*/

//////////////////////////////////////////////////////////////////////
//END FUNCTION DECLARE
//////////////////////////////////////////////////////////////////////

#endif //EXPROTOCOL_1_H
