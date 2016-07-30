
/**
 * sys_conn_monitor.h
 *
 *  Created on: 2015-03-12
 *  Author: liu
 *
 *
 *  该文件是主机连接监控普策略类对应的头文件；
 *
 */

#ifndef _VRV_SYS_CONN_MONITOR_H
#define _VRV_SYS_CONN_MONITOR_H

#include <vector>
#include <string>
#include <pcap.h>
#include "../policysExport.h"


using namespace std;

/**
 *用于外部调用的函数声明。
 */
extern bool sys_conn_monitor_init(void);
extern bool sys_conn_monitor_worker(CPolicy *pPolicy, void *pParam);
extern void sys_conn_monitor_uninit(void);

/**
 *宏定义
 */
#define TCPSYN_LEN 20
#define MAXBYTES2CAPTURE 2048
#define LEN_POLICY_ID 16
#define LEN_POLICY_NAME 256
#define LEN_IP_ADDR 15
#define LEN_CONN_INFO_ITEM 64 

/**
 *枚举,结构类型定义
 */
typedef unsigned short u_int16;
typedef unsigned long u_int32;

enum iptb_type_e
{
    IPTB_INPUT = 0,
    IPTB_OUTPUT
};


enum vector_type_e
{
    VECTOR_WHITE = 0, 
    VECTOR_WHITE_TO_USE, 
    VECTOR_BLACK, 
    VECTOR_BLACK_TO_USE, 
};

typedef struct{
	string srcIpRange;
    string dstIpRange;
    string srcportRange;
    string dstportRange;
    int proctol;
}ipNode;

typedef struct{
    char srcIp[LEN_IP_ADDR + 1];
    char dstIp[LEN_IP_ADDR + 1];
    char port[LEN_CONN_INFO_ITEM];
    char protocol[LEN_CONN_INFO_ITEM];
    char applyProctol[LEN_CONN_INFO_ITEM];
    char programName[LEN_CONN_INFO_ITEM];
    char context[LEN_CONN_INFO_ITEM];
    char strTime[LEN_CONN_INFO_ITEM];
    char domain[LEN_CONN_INFO_ITEM];
}connInfo_t;

typedef struct pseudoheader {
    u_int32_t src;
    u_int32_t dst;
    u_char zero;
    u_char protocol;
    u_int16_t tcplen;
} tcp_phdr_t;

struct sysConnMonitor_t 
{
    int nfq_fd;
    string white_List;
    string black_List;
    string UpRegionService;
    string WriteLocalFile;
    int AuditMode;
    int ControlMode;
    vector<ipNode> whiteVector;
    vector<ipNode> whiteVectorToUse;
    vector<ipNode> blackVector;
    vector<ipNode> blackVectorToUse;
    vector<connInfo_t> auditVector;

    struct nfq_q_handle *q_queue_handle;
    struct nfq_handle *queue_handle;
    char policy_id[LEN_POLICY_ID];
    char policy_name[LEN_POLICY_NAME];
    char local_ip[LEN_IP_ADDR + 1];
    char server_ip[LEN_IP_ADDR + 1];
};


/**
 *主机连接监控类定义
 */
class CSysConnMonitor: public CPolicy{
public:
    CSysConnMonitor();
    virtual ~CSysConnMonitor();
public:
    virtual bool import_xml(const char*);
    virtual void copy_to(CPolicy * pDest);

    int nfq_fd;
    time_t curTime;
    string white_List;
    string black_List;
    string UpRegionService;
    string WriteLocalFile;
    int AuditMode;
    int ControlMode;
    vector<ipNode> whiteVector;
    vector<ipNode> whiteVectorToUse;
    vector<ipNode> blackVector;
    vector<ipNode> blackVectorToUse;
    vector<connInfo_t> auditVector;
};
#endif// _VRV_SYS_CONN_MONITOR


