/*
 * VrvPolicyServiceCtrl.h
 *
 *  Created on: 2013-4-1
 *      Author: lg
 */

#ifndef VRVPOLICYSERVICECTRL_H_
#define VRVPOLICYSERVICECTRL_H_

#include <string>
#include <vector>
#include <list>
#include <map>
#include "../policysExport.h"
using namespace std;

extern bool service_ctrl_init();
extern bool service_ctrl_worker(CPolicy * pPolicy, void * pParam);
extern void  service_ctrl_uninit();


typedef struct ctrlinfo
{
    string name; /*service name*/
    int ctrlmode; /*contrl status:forbid--0,must run--1,permit--2*/
    int autokill; /*atuo:1*/
} ctrl_info;

class ServiceCtrl:public CPolicy
{
public:
    ServiceCtrl(void);
    ~ServiceCtrl(void);
    virtual void copy_to(CPolicy * pDest);
    int deal_flag; //处理标记,上报及违规处理
    int disable_net; //断开网络标记
    string history_data; //上一次计算的上报的部分内容

    map<string, string> xmlitem;
    map<string, string> timeitem;
    map<string, int> status_list;
    list<ctrl_info> ctrl_list;
    list<ctrl_info>::iterator p_ctrl; //规则中可控制的列表迭代器
    int OnStop(); //停止策略
    int OnInit(); //初始化策略
    int OnRun(); //循环运行主函数
    bool import_xml(const char *pxml);
    int illegal_deal(void);
    int get_service_status(const char name[]);
    void update_status(string ser_name, int status);
    int creat_content(int kind, string &content, int policy_id, string policy_name, string ser_name,int autokill);
};

#endif /* VRVPOLICYSERVICECTRL_H_ */
