#ifndef COMMON_H_XXX
#define COMMON_H_XXX
/* c header */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
/* c++ header */
#include <iostream>
#include <sstream>
#include <exception>
#include <string>
#include <vector>
#include <fstream>
/* custom */
#include "socket.h"
#include "SimpleIni.h"
#include "VrvProtocol.h"

#ifndef ELPP_THREAD_SAFE
#define ELPP_THREAD_SAFE
#endif

#define ELPP_DISABLE_DEFAULT_CRASH_HANDLING
#ifndef ELPP_DEFAULT_LOG_FILE
#define ELPP_DEFAULT_LOG_FILE "./logs/simulator.log"
#endif

#include "easylogging++.h"

#include <string>

#define STRITEM_TAG_END  "\r\n"

#define IL "info_logger"
/*above waring log to here */ 
#define EL "error_logger"
#define PL "policy_logger"

#define SM_LOG() CLOG(INFO, IL)
#define SM_WARN() CLOG(WARNING, EL)
#define SM_ERROR() CLOG(ERROR, EL)

#define SM_POLICY() CLOG(INFO, PL)


typedef enum {
    SEND,
    RECIVE,
    NO_SUB_ACTION
} SUB_ACTION;

typedef enum {
    REGESITER,
    REPORT_ASSERT,
    PULL_POLICY,
    SEND_LOG,
    NO_ACTION
} ACTION;

typedef struct action {
    ACTION p;
    SUB_ACTION s;
} action_t;

typedef struct action_result {
    int ret;
    std::string reason;
    action_result() {
        ret = -1;
        reason = "default";
    }
} action_result_t;

typedef struct clog_header {
    std::string time;
    action_t action;
    action_result_t result;
    std::string content;
    clog_header() {
        action.p = NO_ACTION, action.s = NO_SUB_ACTION;
        time = "", content = "";
    }
} clog_header_t;


typedef struct network_info{
	char ip[16];
	char mac[16];
	char gateway[16];
	char sub_mask[16];
	char eth_name[16];
	//if need,added later
} net_info;

void test();

void get_local_time(char strtime[]);

int get_logHeader(char * buffer
        ,std::string  &  regip,  ///注册IP
        std::string  &  regmac, ///注册MAC
        std::string  &  id, ///ID
        std::string  &  sysuser);

/*fake code convert do nothing*/
int code_convert(const char *from_charset,const char *to_charset,char *inbuf,int inlen,char *outbuf,int & outlen);


extern std::string g_server_ip;
extern std::string g_dev_id;
extern int g_server_port;

extern std::string g_mac_addr;
extern std::string g_self_ipaddr;
extern std::string g_gw_ip;

extern int g_log_interval;
extern int g_policy_interval;
extern int g_sfd_flag;
extern int g_upload_log_times;

extern int g_run_times;



#endif
