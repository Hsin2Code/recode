#ifndef _PROTOCOL_H___
#define _PROTOCOL_H___
#include "type.h"

#define EX_OK                0  //成功
#define EX_FAIL              1  //注册失败

#define PKTHEADEX_SIZE       28 /* 加强版协议包头长度 */



#define DOWNLOAD_POLICY      55 /* 下载策略 */
#define DETECT_POLICY        1
#define GET_POLICY           2
#define ECHO_POLICY          3
#define LOWER_DETECT_POLICY  4
#define LOWER_GET_POLICY     5

#define AGENT_RPTAUDITLOG    61     /* 上报审计日志 */
#define AUDITLOG_REQUEST     1      /* 上报请求 */
#define AUDITLOG_ECHO        2      /* 上报回应 */

#define DETECT_ENCRYPT       109    /* 探测是否支持加密 */
#define REG_DEVICE_STRING    114    /* 上报注册信息 */
#define AGENT_GETCONFIG_STRING  117 /* 心跳 */
#ifndef VRV_TAG
#define VRV_TAG              0x5652  //初始化pkt_head.mtag项
#endif//VRV_TAG

#ifndef VRV_FLAG
#define VRV_FLAG             0x56525620 //VRV1.0=0X56525620
#endif//VRV_FLAG

struct head_t
{
    DWORD flag;             //VRV1.0=0x56525610 VRV_FLAG
    WORD  type;             //类型，是上报注册信息，变化，还是错误信息
    WORD  what;             //信息内容
    DWORD key;              //加密密码
    DWORD data_crc;         //不带头的校验和
    DWORD pkt_len;          //包括包头的数据报的长度
};
/* 通信协议包基准版 */
struct packet_t
{
    struct head_t head;
    char data[0];
};

struct head_ex_t
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
/* 通信协议包加强版 */
struct packet_ex_t
{
    struct head_ex_t head;
    char data[0];
};
/* 发送数据包 基准 */
uint32_t
send_pkt(const int sock, struct packet_t *pkt);
/* 接收数据包 基准 */
int recv_pkt(const int sock, struct packet_t ** pkt);
/* 发送数据包 扩展 */
uint32_t
send_pkt_ex(int sock, struct packet_ex_t* pkt);
/* 接收数据包 扩展 */
uint32_t
recv_pkt_ex(int sock, struct packet_ex_t **pkt);
/* 获取通讯加密密钥 */
uint32_t
get_encrypt_key(int sock, uint32_t *key);

#endif
