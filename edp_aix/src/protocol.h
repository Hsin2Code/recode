#ifndef _PROTOCOL_H___
#define _PROTOCOL_H___
#include "type.h"

#define EX_OK                0  //成功
#define EX_FAIL              1  //注册失败

//<>classaction=  行为类别上报字段
#define Illegal_Behavior     0  //违规行为
#define Abnormal_Behavior    1  //异常行为
#define General_Behavior     2  //一般行为

//<>riskrank=    风险级别上报字段
#define Event_Emergency      0  //紧急：系统不可用
#define Event_Alarm          1  //警报：必须立即进行处理
#define Event_Critical       2  //关键：符合关键条件
#define Event_Error          3  //错误：符合错误条件
#define Event_Caution        4  //警告：符合警告条件
#define Event_Inform         5  //通知：普通情况，但具有重要意义
#define Event_Message        6  //信息：一般信息消息
#define Event_Debug          7  //调试：调试级别信息

#define PKTHEADEX_SIZE       28 /* 加强版协议包头长度 */


#define FIND_DAILUP          49     /* 字符串方式的违规联网报警 */
#define FIND_DAILUPING       1      /* 正在上网 */
#define FIND_DAILUPED        2      /* 曾经上过网 */
#define FIND_OUTOFNETWORK    4      /* 曾经上过网 */


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
