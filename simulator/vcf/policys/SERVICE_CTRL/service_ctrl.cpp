/*
 * VrvPolicyServiceCtrl.cpp
 *
 *  Created on: 2013-4-1
 *      Author: lg
 */
using namespace std;
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <string>
#include <iostream>
#include <sstream>
#include <sys/sysinfo.h>

#include "../../vrcport_tool.h"
#include "../../vrvprotocol/VRVProtocol.hxx"
#include "../../../include/MCInterface.h"
#include "service_ctrl.h"

extern int code_convert(const char *from_charset, const char *to_charset, char *inbuf, int inlen, char *outbuf,
                int & outlen);

ServiceCtrl sctl;

static string int2str(int &i)
{
    string s;
    stringstream str(s);
    str << i;
    return str.str();
}

static void service_dialog(string content)
{
    char buffer[512] = "";
    tag_GuiTips * pTips = (tag_GuiTips *) buffer;
    pTips->sign = en_TipsGUI_btnOK | en_TipsGUI_timeOut;
    strncpy(pTips->szTitle, "信息提示", sizeof(pTips->szTitle));
    strncpy(pTips->szTips, content.c_str(), sizeof(pTips->szTips));
    pTips->defaultret = en_TipsGUI_None;
    pTips->pfunc = NULL;
    pTips->param.timeout = 5 * 1000;
    g_GetSendInterface()->sendto_Main(VCF_CMD_GUI_TIPS, buffer, sizeof(tag_GuiTips));
}

/*获取运行级别*/
static int get_run_level(void)
{
    char buf[256] = { 0 };
    FILE *fp = NULL;
    fp = popen("runlevel|awk '{print $2}'", "r");
    if(NULL == fp)
    {
        return -1;
    }
    fgets(buf, sizeof(buf) - 1, fp);
    pclose(fp);
    return atoi(buf);
}

static int get_system_boot_time(char strtime[])
{
    struct sysinfo info;
    time_t cur_time = 0;
    time_t boot_time = 0;
    struct tm *ptm = NULL;
    if(sysinfo(&info))
    {
        return -1;
    }
    time(&cur_time);
    if(cur_time > info.uptime)
    {
        boot_time = cur_time - info.uptime;
    }
    else
    {
        boot_time = info.uptime - cur_time;
    }
    ptm = localtime(&boot_time);
    sprintf(strtime, "%d-%02d-%02d %02d:%02d:%02d", ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday, ptm->tm_hour,
                    ptm->tm_min, ptm->tm_sec);
    return 0;
}

bool service_ctrl_init()
{
    sctl.OnInit();
    return true;
}
bool service_ctrl_worker(CPolicy * pPolicy, void * pParam)
{
    if(sctl.get_crc() != pPolicy->get_crc())
    {
        sctl.OnStop();
        pPolicy->copy_to(&sctl);
        sctl.OnInit();
    }
    sctl.OnRun();
    return true;
}
void service_ctrl_uninit()
{
    unsigned int crc = 0;
    sctl.set_crc(crc);
    sctl.OnStop();
}

int ServiceCtrl::OnInit()
{
    printf("hello service OnInit--------------------------------\n");
    ctrl_list.reverse();
    deal_flag = 0; //1:处理 0：不处理
    disable_net = 0;//0:未断网 1:已断网
    history_data = "";

    return 0;
}

int ServiceCtrl::OnRun()
{
    int i = 0;
    char chk_cmd[128] = { 0 };
    int status = -1;
    string pkt_data;
    string content;
    string on_off_choice;
    string start_stop_choice;
    string new_value = "";
    printf("hello service OnRun--------------------------------\n");

#if 1
    cout << "ctrl_list size=" << ctrl_list.size() << endl;
#endif
    for (p_ctrl = ctrl_list.begin(); p_ctrl != ctrl_list.end(); p_ctrl++)
    {
        status = get_service_status(p_ctrl->name.c_str());
        update_status(p_ctrl->name, status);
#if 1
        cout << "name=" << p_ctrl->name << " ctrlmode=" << p_ctrl->ctrlmode << endl;
#endif
        if((status != p_ctrl->ctrlmode) && (-1 != status) && (p_ctrl->ctrlmode != 2))
        {
            if((p_ctrl->ctrlmode == 1) && (0 == status))
            {
                deal_flag = 1;
                on_off_choice = "on";
                start_stop_choice = "start";
                creat_content(211, content, get_id(), get_name(), p_ctrl->name, p_ctrl->autokill);
            }
            if((p_ctrl->ctrlmode == 0) && (1 == status))
            {
                deal_flag = 1;
                on_off_choice = "off";
                start_stop_choice = "stop";
                creat_content(210, content, get_id(), get_name(), p_ctrl->name, p_ctrl->autokill);
            }

            if(p_ctrl->autokill == 1)
            {
            	#ifndef PKG_DEB
                snprintf(chk_cmd, sizeof(chk_cmd) - 1, "chkconfig --level %d %s %s", get_run_level(),
                                (p_ctrl->name).c_str(), on_off_choice.c_str());
                system(chk_cmd);
                #endif
                memset(chk_cmd, '\0', sizeof(chk_cmd));
                snprintf(chk_cmd, sizeof(chk_cmd) - 1, "service %s %s", (p_ctrl->name).c_str(),
                                start_stop_choice.c_str());
                system(chk_cmd);
                memset(chk_cmd, '\0', sizeof(chk_cmd));
            }
            new_value += content;
            //要上报的信息
            char strtime[128] = { 0 };
            YCommonTool::get_local_time(strtime);
            pkt_data = pkt_data + "Body" + int2str(i) + "=time=" + strtime + content + STRITEM_TAG_END;
            i++;

        }
    }

    if(deal_flag == 1)
    {
        deal_flag = 0;
        pkt_data = pkt_data + "BodyCount=" + int2str(i) + STRITEM_TAG_END;
        char buffer[2048] = { 0 };
        tag_Policylog * plog = (tag_Policylog *) buffer;
        plog->type = AGENT_RPTAUDITLOG;
        plog->what = AUDITLOG_REQUEST;
        sprintf(plog->log, "%s", pkt_data.c_str());
        g_GetlogInterface()->log_trace(pkt_data.c_str());
        if(xmlitem["NeedUpLog"] == "1") //是否持续上报管理
        {
            report_policy_log(plog);
        }
        else
        {
            if(history_data != new_value)
            {
                report_policy_log(plog);
            }
            history_data = new_value;
        }
        illegal_deal();//违规处理
    }
    printf("hello service OnRun  finish--------------------------------\n");
    return 0;
}

int ServiceCtrl::OnStop()
{
    printf("hello service OnStop--------------------------------\n");
    ctrl_list.clear();
    if(1 == disable_net)
    {
        //恢复网络
        tag_openNet tmp;
        tmp.policy = SERVICE_CTRL;
        g_GetSendInterface()->sendto_Main(VCF_CMD_OPEN_NET, &tmp, sizeof(tag_openNet));
        g_GetlogInterface()->log_trace("取消断网");
    }
    return 0;
}

//const char *ptr="<?xml version="1.0" encoding="gb2312"?><vrvscript PolicyExecuteLevel="0" EdpPolicyFlags="1" Class="SERVICE-CONTROL" AuditTypeBigNum="" AuditTypeNum="" PolicyName="1" Priority="1" StartPolicy="1" PolicyVersion="1.0" PolicyRiskLevel="0" PolicyStartTime="" PolicyEndTime="" InvalidWeekDay="0" DBT1="" DET1="" DBT2="" DET2="" DBT3="" DET3="" ControlRegionMode="129" NetValidMode="0" CloningMachineValidMode="0" UserValidMode="0" ExceptUser="" GatewayValidMode="0" ExceptGateway="" ImportPolicyNotStop="0" Remark="" FourceUseFatherDeal="0"> <item  DealMode="1" PromptInfo1="asssss" PromptInfo2="" PromptInfo3=""  NeedUpLog="1"  OtherProcessDeal="0"  PersistAttack="0"  AttackWSTVPN="0"  ProcessCount="3" ></item><item ProcessName0="sshd" CompanyName0="*" ProductName0="*" SourceName0="*" Notes0="yuancheng" IsService0="1" MustRunProcess0="1" AutoKill0="1" ></item><item ProcessName1="sssd" CompanyName1="*" ProductName1="*" SourceName1="*" Notes1="" IsService1="1" MustRunProcess1="1" AutoKill1="1" ></item><item ProcessName2="pcscd" CompanyName2="*" ProductName2="*" SourceName2="*" Notes2="" IsService2="1" MustRunProcess2="1" AutoKill2="0" ></item></vrvscript>";

bool ServiceCtrl::import_xml(const char *pxml)
{
    printf("hello ServiceCtrl import_xml\n");
    if(pxml == NULL)
    {
        return false;
    }

    string in_info = pxml;
    string out_info;
    int srclen = in_info.length();
    int dstlen = srclen * 2 + 1;
    char *dst = new char[dstlen];
    code_convert("gb2312", "utf-8", (char *) in_info.c_str(), srclen, dst, dstlen);
    out_info.assign(dst);
    delete[] dst;

    char property[256] = { 0 };
    ctrl_info item;
    ctrl_list.clear(); //清除上一次策略中的服务列表
    CMarkup xml;
    if(!xml.SetDoc(out_info.c_str()))
    {
        return false;
    }

    if(false == xml.FindElem("vrvscript"))
    {
        return false;
    }

    int itemnum = 0;
    xml.IntoElem();
    while (xml.FindElem("item"))
    {
        itemnum++;
        if(1 == itemnum)
        {
            xmlitem["DealMode"] = xml.GetAttrib("DealMode");
            xmlitem["PromptInfo1"] = xml.GetAttrib("PromptInfo1");
            xmlitem["PromptInfo2"] = xml.GetAttrib("PromptInfo2");
            xmlitem["NeedUpLog"] = xml.GetAttrib("NeedUpLog");
            xmlitem["PromptInfo3"] = xml.GetAttrib("PromptInfo3");
            xmlitem["OtherProcessDeal"] = xml.GetAttrib("OtherProcessDeal");
            xmlitem["PersistAttack"] = xml.GetAttrib("PersistAttack");
            xmlitem["AttackWSTVPN"] = xml.GetAttrib("AttackWSTVPN");
            xmlitem["ProcessCount"] = xml.GetAttrib("ProcessCount");
        }
        if(itemnum > 1)
        {
            int index = itemnum - 2;
            snprintf(property, sizeof(property) - 1, "ProcessName%d", index);
            item.name = xml.GetAttrib(property);
            memset(property, '\0', sizeof(property));
            snprintf(property, sizeof(property) - 1, "MustRunProcess%d", index);
            item.ctrlmode = atoi(xml.GetAttrib(property).c_str());
            memset(property, '\0', sizeof(property));
            snprintf(property, sizeof(property) - 1, "AutoKill%d", index);
            item.autokill = atoi(xml.GetAttrib(property).c_str());
            ctrl_list.push_back(item);
        }

    }
    xml.OutOfElem();
    if(!xml.SetDoc(pxml))
    {
        return false;
    }
    return import_xmlobj(xml);
}

//以下处理共用接口
int ServiceCtrl::illegal_deal(void)
{
    switch (atoi(xmlitem["DealMode"].c_str()))
    {
        case 0:
            break;
        case 1:
        {
            g_GetlogInterface()->log_trace(xmlitem["PromptInfo1"].c_str());
            service_dialog(xmlitem["PromptInfo1"]);
            break;
        }
        case 2:
        {
            tag_closeNet tc;
            tc.policy = get_type();
            if(1 == atoi(xmlitem["PersistAttack"].c_str()))
            {
                tc.bAlaways = true; //永久断网
            }
            else
            {
                tc.bAlaways = false;//非永久断网
            }
            g_GetSendInterface()->sendto_Main(VCF_CMD_CALL_CLOSENET, &tc, sizeof(tag_closeNet));
            disable_net = 1;
            g_GetlogInterface()->log_trace(xmlitem["PromptInfo2"].c_str());
            service_dialog(xmlitem["PromptInfo2"]);
            break;
        }
        case 3:
        {
            g_GetlogInterface()->log_trace(xmlitem["PromptInfo3"].c_str());
            service_dialog(xmlitem["PromptInfo3"]);
            g_GetSendInterface()->sendto_Main(VCF_CMD_CALL_SHUTDOWN, NULL, 0);
            break;
        }
        default:
        {
            g_GetlogInterface()->log_trace("illegal deal mode error\n");
            break;
        }
    }
    return 0;
}

//status: 0:off,1:on,-1:unknown
int ServiceCtrl::get_service_status(const char name[])
{
    FILE *fp = NULL;
    char buf[1024] = { 0 };
    char cmd[128] = { 0 };
    //special deal
    if(0 == strcmp(name, "iptables"))
    {
        snprintf(cmd, sizeof(cmd) - 1, "service %s status|grep '1' 2>/dev/null", name);
    }
    else
    {
        snprintf(cmd, sizeof(cmd) - 1, "service %s status 2>/dev/null", name);
    }
    fp = popen(cmd, "r");
    if(NULL == fp)
    {
        return -1;
    }
    while (NULL != fgets(buf, sizeof(buf) - 1, fp))
    {
#ifdef PKG_DEB
        if(NULL != strstr(buf, "process"))
        {
            pclose(fp);
            return 1;
        }
        else
        {
        	pclose(fp);
        	return 0;
        }
#else
        if((NULL != strstr(buf, "正在运行")) || (NULL != strstr(buf, "is running")))
        {
            pclose(fp);
            return 1;
        }
        else if((NULL != strstr(buf, "已停")) || (NULL != strstr(buf, "not running")))
        {
            pclose(fp);
            return 0;
        }
        else
        {
            //special deal
            if(strcmp(name, "iptables"))
            {
                if(NULL != strstr(buf, "1"))
                {
                    pclose(fp);
                    return 1;
                }
                else
                {
                    pclose(fp);
                    return 0;
                }
            }
            else
            {
                continue;
            }
        }
#endif
    }
    pclose(fp);
    return -1;
}

//获取服务描述
int get_description(char in_buf[], char out_buf[])
{
    int flag = 0;
    char *index = NULL;
    char buf[1024] = { 0 };
    char line[1024] = { 0 };
    char cmd[128] = { 0 };

    sprintf(cmd, "/etc/rc.d/init.d/%s", in_buf);
    FILE *fp = fopen(cmd, "r");
    if(NULL == fp)
    {
        return -1;
    }

    while (NULL != fgets(buf, sizeof(buf), fp))
    {
        if(NULL != (index = strstr(buf, "description:")) || NULL != (index = strstr(buf, "Description:")))
        {
            index = index + strlen("description:");
            sscanf(index, "%[^\n]", out_buf);
            memset(buf, '\0', sizeof(buf));
            if(NULL != (index = strstr(out_buf, "\\")))
            {
                *index = '\0';
                flag = 1;
                continue;
            }
            else
            {
                break;
            }
        }
        if(1 == flag)
        {
            flag = 0;
            if(NULL != (index = strstr(buf, "#")))
            {
                index = index + 1;
                while (isspace(*index))
                {
                    index++;
                }
                sscanf(index, "%[^\n]", line);
            }
            if(NULL != (index = strstr(line, "\\")))
            {
                *index = '\0';
                flag = 1;
            }
            else
            {
                flag = 2;
            }
            strcat(out_buf, line);
            memset(line, '\0', sizeof(line));
            memset(buf, '\0', sizeof(buf));
        }
        if(2 == flag)
        {
            break;
        }
    }

    /*若出现双引号，则进行转义*/
    while (NULL != (index = strstr(out_buf, "\"")))
    {
        *index = '\'';
    }
    fclose(fp);
    return 0;
}

void ServiceCtrl::update_status(string ser_name, int status)
{
    char strtime[128] = { 0 };
    YCommonTool::get_local_time(strtime);
    if(status_list.end() != status_list.find(ser_name))
    {
        if((status_list[ser_name] != status) && (status != -1))
        {
            timeitem[p_ctrl->name] = strtime;
        }
    }
    status_list[ser_name] = status;
}

//获取系统服务相关的核心内容
int ServiceCtrl::creat_content(int kind, string &content, int policy_id, string policy_name, string ser_name,
                int autokill)
{
    char buf[1024] = { 0 };
    char strtime[128] = { 0 };
    char starttime[128] = { 0 };
    //    char description[1024]={0};

    string usrname;
    YCommonTool::get_local_time(strtime);
    get_desk_user(usrname);
    //    get_description((char*)ser_name.c_str(),description);

    if(timeitem[ser_name] == "")
    {
        get_system_boot_time(starttime);
        timeitem[ser_name] = starttime;
    }

    if(kind == 210)//启动了禁用的服务
    {
        snprintf(buf, sizeof(buf) - 1,
                        "<>kind=%d<>policyid=%d<>policyname=%s<>KeyUserName=%s<>context=启动了禁用的服务,服务名:%s;服务启用时间：%s",
                        kind, policy_id, policy_name.c_str(), usrname.c_str(), ser_name.c_str(),
                        timeitem[ser_name].c_str());
    }
    if(kind == 211)//关闭了必须运行的服务
    {
        snprintf(buf, sizeof(buf) - 1,
                        "<>kind=%d<>policyid=%d<>policyname=%s<>KeyUserName=%s<>context=关闭了必须运行的服务,服务名:%s;服务停用时间：%s",
                        kind, policy_id, policy_name.c_str(), usrname.c_str(), ser_name.c_str(),
                        timeitem[ser_name].c_str());
    }
    content = buf;

    if(autokill == 1)
    {
        timeitem[ser_name] = strtime;
    }

    return 0;
}

ServiceCtrl::ServiceCtrl(void)
{
    enPolicytype type = SERVICE_CTRL;
    set_type(type);
}

ServiceCtrl::~ServiceCtrl(void)
{
}

void ServiceCtrl::copy_to(CPolicy * pDest)
{
    if(pDest->get_type() != SERVICE_CTRL)
    {
        return;
    }
    ServiceCtrl * pCtrl = (ServiceCtrl *) pDest;
    pCtrl->xmlitem = xmlitem;
    pCtrl->ctrl_list = ctrl_list;
    CPolicy::copy_to(pDest);
}
