/*
 * soft_install_ctrl.cpp
 *
 *  Created on: 2015-2-2
 *      Author: lg
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>

#include <algorithm>
#include <iostream>
#include <fstream>
#include <sstream>
#include "../../common/Commonfunc.h"
#include "../../vrvprotocol/VRVProtocol.hxx"
#include "../../../include/MCInterface.h"
#include "soft_install_ctrl.h"

extern int code_convert(const char *from_charset,const char *to_charset,char *inbuf,int inlen,char *outbuf,int & outlen);


SoftInstallCtrl sictl;
vector<string> allInstalled; 
vector<string>::iterator matchsoft ;
bool  soft_install_ctrl_init()
{
    sictl.OnInit();
    return true;
}

bool soft_install_ctrl_worker(CPolicy * pPolicy, void * pParam)
{
    cout<<sictl.get_crc()<<"=sictl.get_crc()  pPolicy->get_crc()="<<pPolicy->get_crc()<<endl;
    if(sictl.get_crc() != pPolicy->get_crc())
    {
        sictl.OnStop();
        pPolicy->copy_to(&sictl);
        sictl.OnInit();
    }
    sictl.OnRun();
    return true;
}

void  soft_install_ctrl_uninit()
{
    unsigned int crc = 0;
    sictl.set_crc(crc);
    sictl.OnStop();
}
static void get_soft_info(string & file,vector<string>  & softlist)
{
	softlist.clear();
	FILE *fp = fopen(file.c_str(),"r");
	if(NULL == fp){
		return ;
	}
//#ifdef PKG_DEB
	int package_len = strlen("Package");
	int pri_len   = strlen("Priority") ;
	char buf[256] ="";
	char *index = NULL;
	string name;
	memset(buf,'\0',sizeof(buf));
	name.assign(256,'\0');
	char * pName = const_cast<char *>(name.c_str());
	bool binvalidate = true;
	while(fgets(buf,sizeof(buf),fp)){
		//每个软件最后一行都是描述
		if(strncmp("Description",buf,11) == 0){
			if(binvalidate){
				vector<string>::iterator iter = find(softlist.begin(),softlist.end(),pName);
				if(iter == softlist.end()){
					softlist.push_back(pName);
				}
			}
				binvalidate = true;
				continue;
		}
			if((index = strstr(buf,"Package")) != NULL){
			  index += package_len;
			if((index = strstr(index, ":")) != NULL){//防止其他位置出现关键字选项
				sscanf(index + 1, "%s", pName);
			}
			continue ;
			}
			/* 若是系统软件,用户接口,开发库的信息则不存入容器中 */
			if((index = strstr(buf, "Priority")) != NULL) {
				index += pri_len;
				if(((index = strstr(index, ":")) != NULL)) {
					//以下条件可根据情况增删
					if((strstr(index+1, "required") != NULL)
								|| (strstr(index+1, "standard") != NULL)) {
						binvalidate = false ;
					}
				}
			}
	}
	fclose(fp);
}

 static int get_rpm_all(std::string & file){
	int ret;
	string rpmcmd = "export LANG=zh_CN.UTF-8;rpm -qa|xargs rpm -qi>";
	rpmcmd = rpmcmd + file;
	ret = system(rpmcmd.c_str());
	if(-1 == ret){
		return 0;
	}
	return 1;
}

bool SoftInstalled()
{
	std::string fileName;
#ifdef PKG_DEB
	fileName = "/var/lib/dpkg/status";
#else
	fileName = "installsoft.tmp";
	if(!get_rpm_all(fileName)){
			return false;
	}
#endif
		get_soft_info(fileName,allInstalled);
#ifdef PKG_RPM
		remove(fileName.c_str());
#endif
		return true;
}

SoftInstallCtrl::SoftInstallCtrl(void)
{
    enPolicytype type = SOFT_INSTALL_CTRL;
    set_type(type);
}

SoftInstallCtrl::~SoftInstallCtrl(void)
{

}

static void soft_dialog(string content)
{
    char buffer[512] = "";
    tag_GuiTips * pTips = (tag_GuiTips *)buffer ;
    pTips->sign = en_TipsGUI_btnOK|en_TipsGUI_timeOut ;
    strncpy(pTips->szTitle,"信息提示",sizeof(pTips->szTitle));
    strncpy(pTips->szTips,content.c_str(),sizeof(pTips->szTips));
    pTips->defaultret = en_TipsGUI_None;
    pTips->pfunc = NULL;
    pTips->param.timeout = 5*1000;
    g_GetSendInterface()->sendto_Main(VCF_CMD_GUI_TIPS,buffer,sizeof(tag_GuiTips));
}


/*封装vsnprintf，方便记录日志*/
void soft_install_ctrl_log(const char* fmt, ...)
{
    char log[256]={0};
    va_list args;         //定义一个va_list类型的变量，用来储存单个参数
    va_start(args, fmt);  //使args指向可变参数的第一个参数
    vsnprintf(log,sizeof(log)-1,fmt,args);
    va_end(args);         //结束可变参数的获取
    g_GetlogInterface()->log_trace(log);
}


static string int2str(int &i)
{
    string s;
    stringstream str(s);
    str << i;
    return str.str();
}


//需要实现的初始化代码
int SoftInstallCtrl::OnInit()
{
    printf("SoftInstallCtrl::OnInit--------------------------------\n");
    disable_net = 0;//0:未断网 1:已断网
    deal_flag = 0;
    history_data = "";
	SoftInstalled();
    return 0;
}


//需要实现的停止和清理代码
int SoftInstallCtrl::OnStop()
{
    printf("SoftInstallCtrl::OnStop--------------------------------\n");
    if(1 == disable_net)
    {
        tag_openNet tmp;
        tmp.policy = SOFT_INSTALL_CTRL;
        g_GetSendInterface()->sendto_Main(VCF_CMD_OPEN_NET,&tmp,sizeof(tag_openNet));
        g_GetlogInterface()->log_trace("取消断网");
        cout << "取消断网" << endl;
    }
    return 1;
}

//需要实现的主循环代码
int SoftInstallCtrl::OnRun()
{
    printf("SoftInstallCtrl::OnRun--------------------------------\n");
    int i = 0;
    int status = -1;
    string pkt_data;
    string content;
    string new_value = "";
#if 1
    cout << "soft_list size=" << soft_list.size() << endl;
#endif
    for (p_ctrl = soft_list.begin(); p_ctrl != soft_list.end(); p_ctrl++)
    {
        status = get_soft_status(p_ctrl->name.c_str());
#if 1
        cout << "name=" << p_ctrl->name << " ctrlmode=" << p_ctrl->ctrlmode <<" status=" << status << endl;
#endif
        if((status != p_ctrl->ctrlmode) && (-1 != status) && (p_ctrl->ctrlmode != 2))
        {
            if((p_ctrl->ctrlmode == 1) && (0 == status))
            {
                deal_flag = 1;
                creat_content(201, content);
            }
			if((p_ctrl->ctrlmode == 0) && (1 == status))
            {
                deal_flag = 1;
                creat_content(200, content);
                if(4 == atoi(xmlitem["DealMode"].c_str()))
                {
                	string cmd ;
                	#ifdef PKG_DEB
                	cmd = "dpkg -P ";
                	#else
                	cmd = "rpm -e ";
                	#endif
                    
                    cmd = cmd + p_ctrl->name;
                    system(cmd.c_str());
                }
            }
            new_value += content;
            //要上报的信息
            char strtime[128]={0};
            YCommonTool::get_local_time(strtime);
            pkt_data = pkt_data + "Body" + int2str(i) + "=time="+strtime+ content + STRITEM_TAG_END;
            i++;
        }
    }
//	printf("allInstalled :%d\n",allowsoft.size());
	//vector<string>::iterator matchsoft ;
	vector<string>::iterator allowlist;
	if(atoi(xmlitem["OtherSoftDeal"].c_str()) == 1 && allowsoft.size() != 0 ) 
		{
			   for (matchsoft = allInstalled.begin(); matchsoft != allInstalled.end(); matchsoft++)
				{				
					 allowlist = find(allowsoft.begin(),allowsoft.end(),*matchsoft);
						if(allowlist == allowsoft.end())
							{
								deal_flag = 1;
								printf("software:%s\n",matchsoft->c_str());
								creat_content(203, content);
								break;
							}
				}
			   new_value += content;
			   //要上报的信息
			   char strtime[128]={0};
			   YCommonTool::get_local_time(strtime);
			   pkt_data = pkt_data + "Body" + int2str(i) + "=time="+strtime+ content + STRITEM_TAG_END;
			   i++;
  		}
      if(deal_flag == 1)
      {
          deal_flag = 0;
          pkt_data = pkt_data + "BodyCount=" + int2str(i) + STRITEM_TAG_END;
        char buffer[2048]={0};
        tag_Policylog * plog = (tag_Policylog *)buffer;
        plog->type = AGENT_RPTAUDITLOG;
        plog->what = AUDITLOG_REQUEST;
        sprintf(plog->log,"%s",pkt_data.c_str());
        //防止反复上报
        if(history_data != new_value)
        {
            report_policy_log(plog);
            g_GetlogInterface()->log_trace(pkt_data.c_str());
            illegal_deal();//违规处理
        }
    }
    history_data = new_value;
    printf("SoftInstallCtrl::OnRun finish--------------------------------\n");
    return 0;
}


//status: 0:off,1:on,-1:unknown
int SoftInstallCtrl::get_soft_status(const char* softname)
{
    char cmd[256]={0};
    char buf[256]={0};
    char name[256]={0};
    char *index = NULL;
    
#ifdef PKG_DEB
    const char *section = "Package";
    snprintf(cmd,sizeof(cmd),"dpkg -s %s",softname);
#else
    const char *section = "Name";
    snprintf(cmd,sizeof(cmd),"rpm -qi %s",softname);
#endif
    FILE *fp = popen(cmd,"r");
    if(fp == NULL)
    {
        return -1;
    }
    while (fgets(buf, sizeof(buf), fp))
    {
        if((index = strstr(buf, section)) != NULL)
        {
            index += strlen(section);
            if((index = strstr(index, ":")) != NULL)     //防止其他位置出现关键字选项
            {
                sscanf(index + 1, "%s", name);
            }
            if(0 == strcmp(name,softname))
            {
                pclose(fp);
                return 1;
            }
        }
    }
    pclose(fp);
    return 0;
}


bool SoftInstallCtrl::import_xml(const char *pxml)
{
    printf("hello SoftInstallCtrl import_xml\n");
    if(pxml == NULL)
    {
        return false;
    }

    string in_info = pxml;
    string out_info;
    int srclen = in_info.length();
    int dstlen = srclen * 2+1;
    char *dst = new char[dstlen];
    code_convert("gb2312","utf-8",(char *)in_info.c_str(),srclen,dst,dstlen);
    out_info.assign(dst);
    delete[] dst;

    char property[256] = { 0 };
    softctrl item;
    soft_list.clear();  //释放掉上一次策略中的软件列表，否则更新时会审计上一次策略中的软件
	allowsoft.clear();
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
            xmlitem["PromptInfo4"] = xml.GetAttrib("PromptInfo4");
            xmlitem["AttackWSTVPN"]  = xml.GetAttrib("AttackWSTVPN");
            xmlitem["PersistAttack"] = xml.GetAttrib("PersistAttack");
            xmlitem["OtherSoftDeal"]  = xml.GetAttrib("OtherSoftDeal");
            xmlitem["SoftCount"]  = xml.GetAttrib("SoftCount");
        }
        if(itemnum > 1)
        {
            int index = itemnum - 2;
            snprintf(property, sizeof(property) - 1, "SoftName%d", index);
            item.name = xml.GetAttrib(property);

            memset(property, '\0', sizeof(property));
            snprintf(property, sizeof(property) - 1, "MustInstallSoft%d", index);
            item.ctrlmode = atoi(xml.GetAttrib(property).c_str());
            soft_list.push_back(item);

        }
    }
    xml.OutOfElem();
    soft_install_ctrl_log("import xml soft_list size = %d",soft_list.size());
	 for (p_ctrl = soft_list.begin(); p_ctrl != soft_list.end(); p_ctrl++)
		{
			if(p_ctrl->ctrlmode == 2){
			  allowsoft.push_back(p_ctrl->name);
			}
		}
	 cout<<"allowsoft.size"<<allowsoft.size()<<endl;
    cout<<"soft_list.push_back(item):"<<soft_list.size()<<endl;
    if(!xml.SetDoc(pxml))
    {
        return false;
    }
    return import_xmlobj(xml);
}

void SoftInstallCtrl::illegal_deal()
{
    soft_install_ctrl_log("DealMode = %s",xmlitem["DealMode"].c_str());
    switch(atoi(xmlitem["DealMode"].c_str()))
    {
        case 0:
            break;
        case 1:
        {
            soft_install_ctrl_log("%s",xmlitem["PromptInfo1"].c_str());
            soft_dialog(xmlitem["PromptInfo1"]);
            break;
        }
        case 2:
        {
            soft_install_ctrl_log("disable_net = %d",disable_net);
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
            soft_install_ctrl_log("%s",xmlitem["PromptInfo2"].c_str());
            soft_dialog(xmlitem["PromptInfo2"]);
            break;
        }
        case 4:
        {
            soft_install_ctrl_log("%s",xmlitem["PromptInfo4"].c_str());
            soft_dialog(xmlitem["PromptInfo4"]);
            break;
        }
        default:
            break;
    }
}


int SoftInstallCtrl::creat_content(int kind, string &content)
{
    char buf[1024]={0};

    string usrname;
    get_desk_user(usrname);

    if(kind == 200)//安装了禁止的软件
    {
        snprintf(buf,sizeof(buf)-1,"<>kind=%d<>policyid=%d<>policyname=%s<>KeyUserName=%s<>context=安装了禁止安装的软件:%s",
                        kind,get_id(),get_name().c_str(),usrname.c_str(),p_ctrl->name.c_str());
    }
    if(kind == 201)//未安装必须安装的软件
    {
        snprintf(buf,sizeof(buf)-1,"<>kind=%d<>policyid=%d<>policyname=%s<>KeyUserName=%s<>context=未安装必须安装的软件:%s",
                        kind,get_id(),get_name().c_str(),usrname.c_str(),p_ctrl->name.c_str());
    }
	if(kind == 203)//非允许安装的软件
	{
		snprintf(buf,sizeof(buf)-1,"<>kind=200<>policyid=%d<>policyname=%s<>KeyUserName=%s<>context=安装了非允许安装的软件:%s等",
	                        get_id(),get_name().c_str(),usrname.c_str(),matchsoft->c_str());
	}
    content = buf;
    return 0;
}


void SoftInstallCtrl::copy_to(CPolicy * pDest)
{
    if(pDest->get_type() != SOFT_INSTALL_CTRL)
    {
        return;
    }
    SoftInstallCtrl * pCtrl = (SoftInstallCtrl *) pDest;
    pCtrl->soft_list = soft_list;
	pCtrl->allowsoft = allowsoft;	
    pCtrl->xmlitem = xmlitem;
    CPolicy::copy_to(pDest);
}
