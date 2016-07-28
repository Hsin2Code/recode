#include <stdlib.h>
#include "common.h"


using namespace std;
uint32_t send_num = 0;
uint32_t error_num = 0;
uint32_t success_num = 0;

int make_data(char * data,uint32_t size) {
    memset(data, 0, size);
    string user = "hsin";
    size_t npos = get_logHeader(data, g_self_ipaddr, g_mac_addr, g_dev_id, user);
    char *ptmp = data + npos;
    
    char local_time[21]="";
    get_local_time(local_time);
    
    std::string random_content;
	int len = rand() % 300;
	for(int i = 0 ; i < len ; i++) {
        char c_append = rand() % 26 + 'A';
		random_content.push_back(c_append);
	}
    sprintf(ptmp,
	     "Body0=time=%s<>kind=%d<>policyid=%d<>policyname=%s<>KeyUserName=%s<>classaction=%d<>riskrank=%d<>context=%s%s%s%s",
	     local_time,900,0,"hardware control","hsin",0,2,random_content.c_str(),"\r\n","BodyCount=1","\r\n");

    return strlen(data);
}
int send_data(uint8_t * data,uint32_t len) {
    TCP tcp(g_server_ip, g_server_port);
    VRVPacket pkt;
    if( 0 != tcp.connect()) {
        SM_ERROR() << "[report] connect error";
    }
    uint32_t type = AGENT_RPTAUDITLOG;
    uint32_t what = AUDITLOG_REQUEST;
    uint32_t isencrypt = 1;
    int i = 0;
    while((i++) < g_upload_log_times){
        send_num++;
        if(pkt.SendPkt(tcp.socket_id(), type, what, tcp.passwd(), 0, data, len, isencrypt)) {
            // report success
            if(!pkt.RecvPkt(tcp.socket_id(),tcp.passwd())) {
                SM_ERROR() << "upload log recive failed";
            }
            if(pkt.head.m_Flag  != VRV_FLAG) {
                SM_ERROR() << "upload log recive VRV_FLAG failed";
            } else {
                success_num++;
            }
        }else {
            error_num++;
            SM_ERROR() << "[report] send_report_log error";
        }
    }
    tcp.close();
    return 0;
}
void * thread_send_msg(void *arg) {
    uint8_t data[2048];
    int len;
    int _inner_count = 0;
    while(1) {
        len = make_data((char *)data, 2048);
        {
            std::string upload;
            upload = "UPLOAD_LOG:" + g_dev_id;
            TIMED_SCOPE(timer, upload.c_str());
            send_data(data, len);
        }
        SM_LOG() << "total:" << send_num;
        SM_LOG() << "success:" << success_num;
        SM_LOG() << "error:" << error_num;
        sleep(g_log_interval);
        _inner_count++;
        if(_inner_count >= g_run_times) {
            pthread_exit(NULL);
        }
    }
    return NULL;
}
