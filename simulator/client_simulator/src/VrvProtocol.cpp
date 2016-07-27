using namespace std;
#include <stdlib.h>
#include <string.h>

//测试
#include <iostream>

#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>


#include "VrvProtocol.h"
#include "common.h"


/////////////////
//加密解密函数


DWORD m_EncryptVersion = ENC_VERSION1; // 0x56000001;
BYTE m_Key[24]=
{
    0xCB,0xB6,0xD8,0xBF,
    0xBB,0xB1,0xD8,0xBF,
    0xE0,0xBC,0xBB,0xC4,
    0xC1,0xC6,0xB4,0xD4,
    0xC5,0xD0,0xB1,0xB1,
    0xA9,0xBE,0xB1,0xB1
};

BOOL Encrypt_V1(DWORD m_Pwd,LPVOID LpIn, LPVOID LpOut, DWORD m_Len, DWORD m_Offset)
{
    if(LpIn == NULL || LpOut == NULL)
        return FALSE;
    BYTE m_Tmp[sizeof(m_Key)];
    memcpy(m_Tmp, m_Key, sizeof(m_Key));

    DWORD *LpKey = (DWORD*)m_Tmp, m_Count, i;
    m_Count = sizeof(m_Key) / sizeof(DWORD);
    for(i = 0; i < m_Count; i++)
    {
        *LpKey ^=m_Pwd; LpKey++;
    }
    m_Count = m_Offset % sizeof(m_Tmp);
    for(i = 0; i < m_Len; i++)
    {
        ((BYTE*)LpOut)[i] = ((BYTE*)LpIn)[i] ^ m_Tmp[m_Count];
        //下一个
        m_Count++;
        if(m_Count == sizeof(m_Key))
        {
            m_Count=0;
        }
    }

    return TRUE;
}

BOOL Decrypt_V1(DWORD m_Pwd,LPVOID LpIn, LPVOID LpOut, DWORD m_Len, DWORD m_Offset)
{
    return Encrypt_V1(m_Pwd,LpIn,LpOut,m_Len,m_Offset);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	CRC函数

ULONG	    CRCTab[256];
void CRCInit()
{

    int I,J;
    ULONG C;
    for(I=0;I<256;I++)
    {
        for (C=I,J=0;J<8;J++)
        {
            C=(C & 1) ? (C>>1)^0xEDB88320L : (C>>1);
        }
        CRCTab[I]=C;
    }
}

ULONG CRC32(ULONG StartCRC,BYTE *Addr, ULONG Size)
{
    CRCInit();

    for(ULONG I=0; I<Size; I++)
    {
        StartCRC = CRCTab[(BYTE)StartCRC ^ Addr[I]] ^ (StartCRC >> 8);
    }

    return(StartCRC);
}

ULONG CRC32Raw(ULONG StartCRC,BYTE *Addr, ULONG Size)
{
    StartCRC ^= 0xffffffffL;
    for(ULONG I=0; I<Size; I++)
    {
        StartCRC = CRCTab[(BYTE)StartCRC ^ Addr[I]] ^ (StartCRC >> 8);
    }
    StartCRC ^= 0xffffffffL;
    return(StartCRC);
}


//zhangjian
int VRVPacket::SendPkt(int sockfd,WORD m_Type,WORD m_What,DWORD m_Pwd,DWORD PktCrc,BYTE *data,int datalen,int isencrypt)
{
    int PktHeadLen = sizeof(PktHead);

    //清空数据包头
    memset(&head,0,PktHeadLen);

    ULONG crc = 0;
    /*if(NULL != data)
      {crc = CRC32(crc, data, datalen);}*/

    //填充数据
    head.m_Flag = VRV_FLAG;
    head.m_Type = m_Type;
    head.m_What = m_What;
    head.m_Pwd=   m_Pwd;
    head.PktCrc=  crc;
    head.PktLen = PktHeadLen;

    if(data != NULL && datalen>0) {
        head.PktLen += datalen;
    }

    //发送包头
    int nbytes;
    nbytes = send(sockfd,&head,PktHeadLen,MSG_WAITALL);
    if (nbytes != PktHeadLen) {
        return(0);
    }

    //发送数据
    if(data != NULL && datalen>0) {
        m_data.assign((char *)data,datalen);

        //加密数据
        if(isencrypt == 1 && m_Pwd != 0) {
            Encrypt_V1(m_Pwd,(LPVOID)m_data.c_str(),(LPVOID)m_data.c_str(),m_data.size(),0);
        }

        int send_len = 0 ;

        while(send_len < m_data.size()) {
            nbytes = send(sockfd,m_data.c_str() + send_len,m_data.size() - send_len,MSG_WAITALL);
            if(nbytes < 0) {
                SM_ERROR() << "send error: " << errno;
                return(0); ;
            }
            send_len += nbytes ;
        }
        SM_LOG() << "send size: " << send_len << " should send: " << m_data.size();
        if (nbytes != (int)m_data.size()) {
            return(0);
        }
    } else {

    }

    return 1;
}
int VRVPacket::sent_audit_info(int sockfd, WORD m_Type, WORD m_What, DWORD m_Pwd, DWORD PktCrc, BYTE * data, int datalen, int isencrypt)
{
    int PktHeadLen = sizeof(PktHead);

    //清空数据包头
    memset(&head,0,PktHeadLen);
    /*modify by yxl 2012.11.26 begin*/
    linux_pkt.linux_head.m_Flag = VRV_FLAG;
    linux_pkt.linux_head.m_Type = m_Type;
    linux_pkt.linux_head.m_What = m_What;
    linux_pkt.linux_head.m_Pwd = m_Pwd;
    linux_pkt.linux_head.PktCrc = PktCrc;
    linux_pkt.linux_head.PktLen = PktHeadLen ;
    if(data != NULL && datalen>0)
    {
        linux_pkt.linux_head.PktLen+= datalen;
        m_data.assign((char *)data,datalen);
        if(isencrypt == 1 && m_Pwd != 0)
        {
            Encrypt_V1(m_Pwd,(LPVOID)m_data.c_str(),(LPVOID)m_data.c_str(),m_data.size(),0);
        }
        linux_pkt.linux_data = m_data;
    }
    int nbytes;
    nbytes = send(sockfd,&linux_pkt,linux_pkt.linux_head.PktLen,0);
    if(linux_pkt.linux_head.PktLen != (ULONG)nbytes)
    {
        SM_ERROR() << "sent packethead fail!";
        return 0;
    }
    return 1;
}
int VRVPacket::RecvPkt(int sockfd,unsigned int pwd)
{
    int PktHeadLen = sizeof(PktHead);

    //接收包头
    int nbytes;
    nbytes = recv(sockfd,&head,PktHeadLen,MSG_WAITALL);
    if (nbytes !=PktHeadLen) {
        SM_ERROR() << "recive packethead fail!!  --  " << nbytes;
        return(0);
    }

    //计算长度和申请空间
    int datalen = head.PktLen - PktHeadLen;

    if(datalen > 0)
    {
        unsigned char *data = new unsigned char[datalen];

        //接收数据
        nbytes = recv(sockfd,data,datalen,MSG_WAITALL);
        if (nbytes != datalen)
        {
            //fprintf(stderr, "WRITE Error:%s\n", strerror(errno));
            SM_ERROR() << "recive data fail!!";
            delete[] data;
            return(0);
        }
        //解密数据
        if(pwd != 0) {
            Decrypt_V1(pwd,(LPVOID)data,(LPVOID)data,datalen,0);
        }
        /*added by yxl 2014.4.2 begin*/
#if 0
        ULONG crc = 0;
        crc = CRC32(crc, data, datalen);
        if(crc != head.PktCrc)
        {
            return 0;
        }
#endif
        /*added by yxl 2014.4.2 end*/
        m_data.assign((char *)data,datalen);
        delete[] data;
    }

    return 1;
}

int VRVPacketEx::SendPktEx(int sockfd,WORD m_Type,WORD m_What,DWORD m_Pwd,DWORD PktCrc,DWORD Address,BYTE *data,int datalen,int isencrypt )
{
    int PktHeadLen = sizeof(PktHeadEx);

    //清空数据包头
    memset(&head,0,PktHeadLen);
    /*added by yxl 2014.4.2 begin*/
    ULONG crc = 0;
    /*if(NULL != data)
      {crc = CRC32(crc, data, datalen);}*/
    /*added by yxl 2014.4.2 end*/
    //填充数据
    head.m_Flag = VRV_FLAG;
    head.m_Type = m_Type;
    head.m_What = m_What;
    head.m_Pwd=m_Pwd;
    head.PktCrc=crc;
    head.PktLen = PktHeadLen;
    head.m_Tag = VRV_TAG;
    head.m_Size = PKTHEADEX_SIZE;
    head.m_Address = Address;
    if(data != NULL && datalen>0) {
        head.PktLen += datalen;
    }

    //发送包头
    ssize_t nbytes;
    nbytes = send(sockfd,&head,PktHeadLen,MSG_WAITALL);
    if (nbytes != PktHeadLen) {
        SM_ERROR() << "send VRVPacketEx Header failed.";
        return(0);
    }

    //发送数据
    if(data != NULL && datalen>0) {
        //加密数据
        if(isencrypt == 1 && m_Pwd != 0) {
            Encrypt_V1(m_Pwd,(LPVOID)data,(LPVOID)data,datalen,0);
        }

        int send_len = 0 ;

        while(send_len < datalen) {
            nbytes = send(sockfd,data + send_len,datalen - send_len,MSG_WAITALL);
            if(nbytes < 0) {
                SM_ERROR() << "socket send error: " << errno;
                return(0); ;
            }
            send_len += nbytes ;
        }

        if ((unsigned int)send_len != datalen) {
            SM_ERROR() << "last time send error";
            return(0);
        }
    }
    SM_LOG() << "send sucess and return";
    return 1;
}
int VRVPacketEx::RecvPktEx(int sockfd,unsigned int pwd)
{
    int PktHeadLen = sizeof(PktHeadEx);

    SM_LOG() << "start recive packet ex";
    //接收包头
    int nbytes;
    nbytes = recv(sockfd,&head,PktHeadLen,MSG_WAITALL);
    if (nbytes !=PktHeadLen) {
        SM_ERROR() << "socket recive error: " << errno;
        return(0);
    }
    //计算长度和申请空间
    int datalen = head.PktLen - PktHeadLen;

    SM_LOG() << "recive packet data len: " << datalen;
    if(datalen > 0) {
        unsigned char *data = new unsigned char[datalen];

        //接收数据
        nbytes = recv(sockfd,data,datalen,MSG_WAITALL);
        if (nbytes != datalen) {
            SM_ERROR() << "socket recive error";
            delete[] data;
            return(0);
        }

        //解密数据
        if(pwd != 0) {
            Decrypt_V1(pwd,(LPVOID)data,(LPVOID)data,datalen,0);
        }
#if 0
        ULONG crc = 0;
        crc = CRC32(crc, data, datalen);
        if(crc != head.PktCrc)
        {
            return 0;
        }
#endif
        m_data.assign((char *)data,datalen);
        delete[] data;
    }
    SM_LOG() << "recive data success";
    return 1;
}

int get_pwd(int sockfd,unsigned int &pwd)
{
    std::string get_pwd_str = "GET_PWD_SEND:" + g_dev_id;
    VRVPacketEx pkt;
    int ret=0;
    {
        TIMED_SCOPE(timer, get_pwd_str.c_str());
        ret = pkt.SendPktEx(sockfd,DETECT_ENCRYPT,0,0x56000001,0,0,NULL,0);
        if(ret == 0)
        {
            return 0;
        }
    }

    get_pwd_str = "GET_PWD_RECV:" + g_dev_id;
    {
        TIMED_SCOPE(timer, get_pwd_str.c_str());
        ret = pkt.RecvPktEx(sockfd);
        if(ret == 0)
        {
            return 0;
        }

        if(pkt.head.m_Flag == VRV_FLAG && pkt.head.m_Type == EX_OK )
        {
            pwd = pkt.head.m_Pwd;
            return 1;
        }
        else
        {
            return 0;
        }

    }
}
