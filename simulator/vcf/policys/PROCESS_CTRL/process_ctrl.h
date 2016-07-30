/*
 * process_ctrl.h
 *
 *  Created on: 2015-1-19
 *      Author: lg
 */

#ifndef PROCESS_CTRL_H_
#define PROCESS_CTRL_H_
#include <vector>
#include <map>
#include <string>
#include "../policysExport.h"
#include "dbus_comm.h"

extern bool process_ctrl_init();
extern bool process_ctrl_worker(CPolicy * pPolicy, void * pParam);
extern void  process_ctrl_uninit();

using namespace std;

class processinfo
{
    public:
    string process_name;
    string company_name;
    string product_name;
    string source_name;
    string process_cksum; /*process chksum*/
    int process_id;
    int ctrlmode; /*contrl status:forbid--0,must run--1,permit--2*/
    int autokill; /*atuo:1*/
};

typedef struct active_process_info {
	int pid;
	int uid;
	active_process_info(){
		pid = 0, uid = -1;
	}
} active_process_info_t;


class ProcessCtrl: public CPolicy {
    public:
        ProcessCtrl(void);
        ~ProcessCtrl(void);
        void copy_to(CPolicy * pDest);
        int OnStop(); //停止策略
        int OnInit(); //初始化策略
        int OnRun(); //循环运行主函数
        //int get_process_status(const char* processname,vector<int> &pid_list);
        int get_process_status_ext(const char *processname, 
                std::vector<active_process_info_t> &pid_list);
        int filter_ac_process_by_uid(const std::vector<active_process_info_t> &pid_list, int uid);
        void init_status();
        void update_status(int status);
        int execute_new(const char *exepath, const active_user_info_t &current_user);
        bool import_xml(const char *pxml);
        void illegal_deal();
        int creat_content(int kind, string &content, const std::string &usrname, int pid);

        vector<processinfo> processlist;
        vector<processinfo>::iterator p_ctrl; //规则中可控制的列表迭代器
        map<string,string> xmlitem;
        map<string,string> timeitem;
        map<string, int> status_list;

        string history_data;
        int disable_net;//0:未断网 1:已断网
        int deal_flag;
};

#endif /* PROCESS_CTRL_H_ */
