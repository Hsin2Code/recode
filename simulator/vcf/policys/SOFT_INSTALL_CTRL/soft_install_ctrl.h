/*
 * soft_install_ctrl.h
 *
 *  Created on: 2015-2-2
 *      Author: lg
 */

#ifndef SOFT_INSTALL_CTRL_H_
#define SOFT_INSTALL_CTRL_H_

#include "../policysExport.h"

extern bool soft_install_ctrl_init();
extern bool soft_install_ctrl_worker(CPolicy * pPolicy, void * pParam);
extern void  soft_install_ctrl_uninit();

using namespace std;


typedef struct softinfo
{
    string name; /*soft name*/
    int ctrlmode; /*contrl status:forbid--0,must--1,permit--2*/
} softctrl;


class SoftInstallCtrl: public CPolicy
{

    public:
    SoftInstallCtrl(void);
    virtual ~SoftInstallCtrl(void);
    void copy_to(CPolicy * pDest);
    int OnStop(); //停止策略
    int OnInit(); //初始化策略
    int OnRun(); //循环运行主函数
    int get_soft_status(const char* softname);
    bool import_xml(const char *pxml);
    void illegal_deal();
    int creat_content(int kind, string &content);

    vector<softctrl>::iterator p_ctrl; //规则中可控制的列表迭代器
    vector<softctrl> soft_list;
	vector<string> allowsoft;
    map<string,string> xmlitem;
    string history_data;
    int disable_net;//0:未断网 1:已断网
    int deal_flag;
};

#endif /* SOFT_INSTALL_CTRL_H_ */
