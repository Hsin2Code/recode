/*
 * CheckSum.h
 *
 *  Created on: 2015-1-19
 *      Author: sharp
 *
 *  @提供网络数据包的定义，计算校验和等功能。
 */

#ifndef CHECKSUM_H_
#define CHECKSUM_H_

/*物理帧头结构*/
struct tag_ethHeader {
	///目的MAC地址
    unsigned char desmac[6];
    ///源MAC地址
    unsigned char srcmac[6];
	///帧类型
    unsigned short ethertype;
} ;

/**
 * IP报报头结构
 */
struct  tag_ipHeader {
	///IP包头部长度
    unsigned char ver_len;
    ///服务类型
    unsigned char tos;
    ///IP包 长度
    unsigned short total_len;
    ///标识 ident
    unsigned short ident;
    ///标志位
    unsigned short frag_and_flags;
    ///生存事件
    unsigned char ttl;
    ///协议
    unsigned char proto;
    ///校验和
    unsigned short checksum;
    ///源地址(32位)
    unsigned int  sourceIP ;
    ///目的地址(32位)
    unsigned int destIP;
} ;
/**
 * TCP报头
 */
struct tag_tcpHeader  {
	///源端口
    unsigned short srcport;
    ///目的端口
    unsigned short dstport;
    ///顺序号
    unsigned int   seqnum;
    ///确认号
    unsigned int   acknum;
    ///TCP长度
    unsigned char  dataoff;
    ///标识位
    unsigned char  flags;
    ///窗口大小
    unsigned short window;
    ///校验和
    unsigned short chksum;
    ///紧急指针
    unsigned short urgptr;    // 紧急指针
} ;
/**
 * TCP伪首部 用于进行TCP校验和的计算,保证TCP效验的有效性
 */
struct tag_tcpVHeader {
	///源IP地址
	unsigned int  sourceip;
	///目的IP地址
	unsigned int  destip;
	//置空(0)
	unsigned char mbz;
	///协议类型(IPPROTO_TCP)
	unsigned char ptcl;
	///TCP包的总长度(单位:字节)
    unsigned short tcpl;
};

inline unsigned short checksum(unsigned short * buffer,int size) {
    unsigned long cksum=0;
    while(size>1) {
        cksum+=*buffer++;
        size-=sizeof(unsigned short);
    }
    if(size) {
        cksum+=*(unsigned char *)buffer;
    }
    //将32位数转换成16
    while (cksum>>16)
    {
        cksum=(cksum>>16)+(cksum & 0xffff);
    }
    return (unsigned short) (~cksum);
}

/**
 * 计算数据包的校验和
 */
inline  void  check_packet_sum() {
  return ;
}


#endif /* CHECKSUM_H_ */
