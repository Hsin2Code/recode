#ifndef _PROTOCOL_H___
#define _PROTOCOL_H___



#ifndef VRV_TAG
#define VRV_TAG         0x5652  //初始化pkt_head.mtag项
#endif//VRV_TAG

#ifndef VRV_FLAG
#define VRV_FLAG        0x56525620 //VRV1.0=0X56525620
#endif//VRV_FLAG



#define PKTHEADEX_SIZE  28       /* 数据包头长度 */

#include "type.h"

struct pkt_head_t
{
    DWORD flag;             //VRV2.0=0x56525610 VRV_FLAG
    WORD  type;             //类型，是上报注册信息，变化，还是错误信息
    WORD  what;             //信息内容
    DWORD key;              //加密密码
    DWORD data_crc;         //不带头的校验和
    DWORD pkt_len;          //包括包头的数据报的长度
    WORD  tag;              //标记  VRV_TAG
    WORD  head_len;         //头的大小
    DWORD address;          //IP地址
};

#endif
