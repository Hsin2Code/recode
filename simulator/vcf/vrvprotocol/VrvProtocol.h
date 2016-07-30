#ifndef _VrvProtocol_H
#define _VrvProtocol_H
#include <string>
using namespace std;
#include "VRVProtocol.hxx"
#include "VRVProtocolEx.hxx"

#include <string.h>

#define ENC_VERSION1 0x56000001
/*added by yxl 2012.11.26 begin*/
typedef struct 
{
    PktHead linux_head;
	string linux_data;
}Linux_Pkt;
/*added by yxl 2012.11.26 end*/
//加解密函数
BOOL  Encrypt_V1(DWORD m_Pwd,LPVOID LpIn, LPVOID LpOut, DWORD m_Len, DWORD m_Offset);
BOOL  Decrypt_V1(DWORD m_Pwd,LPVOID LpIn, LPVOID LpOut, DWORD m_Len, DWORD m_Offset);

//CRC函数
void  CRCInit();
ULONG CRC32(ULONG StartCRC,BYTE *Addr, ULONG Size);
ULONG CRC32Raw(ULONG StartCRC,BYTE *Addr, ULONG Size);
int   get_pwd(int sockfd,unsigned int &pwd);

///////////////////////////////////////////////////////////
//数据包通信定义

	class VRVPacket
	{
	public:
		PktHead head;
		string m_data;
	    //added by yxl 2012.11.26
	    Linux_Pkt linux_pkt;
		
		VRVPacket() {
			memset(&head,0,sizeof(PktHead));
		}
		
		//如果pwd不为0，则自动加密发送
		int SendPkt(int sockfd,WORD m_Type,WORD m_What,DWORD m_Pwd,DWORD PktCrc,BYTE * data,int datalen,int isencrypt = 1);
		
		//如果pwd不为0，则解密数据，并且把pwd置为0
		int RecvPkt(int sockfd,unsigned int pwd = 1);
		//added by yxl 2012.11.26
		int sent_audit_info(int sockfd,WORD m_Type,WORD m_What,DWORD m_Pwd,DWORD PktCrc,BYTE *data,int datalen,int isencrypt = 1);
	
	};
	
	class VRVPacketEx
	{
	public:
		PktHeadEx head;
		string m_data;
		
		//如果pwd不为0，则自动加密发送
		int SendPktEx(int sockfd,WORD m_Type,WORD m_What,DWORD m_Pwd,DWORD PktCrc,DWORD Address,BYTE *data,int datalen,int isdecrypt = 1);
		
		//如果pwd不为0，则解密数据，并且把pwd置为0
		int RecvPktEx(int sockfd,unsigned int pwd = 1);	
		VRVPacketEx()
		{
		    memset(&head,0,sizeof(PktHeadEx));
			m_data = "";
		}
	};
	
	
	//先做两个测试文件
	//CRC测试[已完成]
	//加解密函数测试
#endif
