/*
 * process_ctrl.cpp
 *
 *  Created on: 2015-1-19
 *      Author: lg
 */

#include <iostream>
#include <string.h>
#include <fstream>
#include <sstream>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <iterator>
#include <ctime>
#include <sys/param.h>
#include <string.h>
#include <signal.h>
#include <dirent.h>
#include <sys/sysinfo.h>
#include "../../vrcport_tool.h"
#include "../../vrvprotocol/VRVProtocol.hxx"
#include "../../../include/MCInterface.h"
#include "process_ctrl.h"
#define  MAX_BUF_SIZE  256

extern int code_convert(const char *from_charset,const char *to_charset,char *inbuf,int inlen,char *outbuf,int & outlen);


ProcessCtrl pctl;

bool  process_ctrl_init()
{
    pctl.OnInit();
    return true;
}

bool process_ctrl_worker(CPolicy * pPolicy, void * pParam)
{
    cout<<pctl.get_crc()<<"=pctl.get_crc()  pPolicy->get_crc()="<<pPolicy->get_crc()<<endl;
    if(pctl.get_crc() != pPolicy->get_crc())
    {
        pctl.OnStop();
        pPolicy->copy_to(&pctl);
        pctl.OnInit();
		pctl.init_status();
    }
    pctl.OnRun();
    return true;
}

void  process_ctrl_uninit()
{
    unsigned int crc = 0;
    pctl.set_crc(crc);
    pctl.OnStop();
}


static std::string int2str(int &i)
{
    std::string s;
    stringstream str(s);
    str << i;
    return str.str();
}


static int get_system_boot_time(char strtime[])
{
    struct sysinfo info;
    time_t cur_time = 0;
    time_t boot_time = 0;
    struct tm *ptm = NULL;
    if (sysinfo(&info))
    {
        return -1;
    }
    time(&cur_time);
    if (cur_time > info.uptime)
    {
        boot_time = cur_time - info.uptime;
    }
    else
    {
        boot_time = info.uptime - cur_time;
    }
    ptm = localtime(&boot_time);
    sprintf(strtime,"%d-%02d-%02d %02d:%02d:%02d", ptm->tm_year + 1900,
        ptm->tm_mon + 1, ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
    return 0;
}

static void process_dialog(std::string content)
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

static std::string get_process_run_time(int pid)
{
	int fd; 
	char buff[128];
	char *p; 
	unsigned long uptime;
	struct timeval tv; 
	static time_t boottime;
	std::string run_time = "";

	if ((fd = open("/proc/uptime", 0)) != -1) {
		if (read(fd, buff, sizeof(buff)) > 0) {
			uptime = strtoul(buff, &p, 10);
			gettimeofday(&tv, 0); 
			boottime = tv.tv_sec - uptime;
		}   
		close(fd);
	}   

	ifstream statusFile;
	string status = "/proc/"+int2str(pid)+"/status";
	statusFile.open(status.c_str());

	char str[255];
	while(1)
	{
		statusFile.getline(str, 255);	
		if (strstr(str, "Tgid")!=NULL)
		{
			if (strstr(str, int2str(pid).c_str())!=NULL)
			{
				break;
			}
			else
			{
				return run_time;		
			}
		}
	}

	ifstream procFile;
	string stat = "/proc/"+int2str(pid)+"/stat";
	procFile.open(stat.c_str());
	if (!procFile.is_open()) {
		return run_time;
	}
	procFile.getline(str, 255);  // delim defaults to '\n'
    procFile.close();

	vector<string> tmp;
	istringstream iss(str);
	copy(istream_iterator<string>(iss),
			istream_iterator<string>(),
			back_inserter<vector<string> >(tmp));
	
	std::time_t now = std::time(0);
	std::time_t lapsed = ((now - boottime) - (atof(tmp.at(21).c_str()))/HZ);

	int days = lapsed / 60 / 60 / 24;
	int hours = (lapsed / 60 / 60) % 24;
	int minutes = (lapsed / 60) % 60;
	int seconds = lapsed % 60;

	run_time = int2str(days)+"天"+int2str(hours)+"小时"+int2str(minutes)+"分"+int2str(seconds)+"秒";

	return run_time;
}

ProcessCtrl::ProcessCtrl(void)
{
    enPolicytype type = PROCESS_CTRL;
    set_type(type);
}

ProcessCtrl::~ProcessCtrl(void)
{

}

//需要实现的初始化代码
int ProcessCtrl::OnInit()
{
    printf("ProcessCtrl::OnInit--------------------------------\n");
    disable_net = 0;//0:未断网 1:已断网
    deal_flag = 0;
    history_data = "";
    return 0;
}


//需要实现的停止和清理代码
int ProcessCtrl::OnStop()
{
    printf("ProcessCtrl::OnStop--------------------------------\n");
    if(1 == disable_net)
    {
        tag_openNet tmp;
        tmp.policy = PROCESS_CTRL;
        g_GetSendInterface()->sendto_Main(VCF_CMD_OPEN_NET,&tmp,sizeof(tag_openNet));
        g_GetlogInterface()->log_trace("取消断网");
        cout << "取消断网" << endl;
    }
    return 1;
}

//需要实现的主循环代码
int ProcessCtrl::OnRun()
{
    printf("ProcessCtrl::OnRun--------------------------------\n");
    int i = 0;
    int status = -1;
    int old_status = -1;
    std::string on_off_choice;
    std::string pkt_data;
    std::string content;
    std::string new_value = "";
    active_user_info_t current_user;
#if 1
    cout << "processlist size=" << processlist.size() << endl;
#endif


    /*detect active usr info*/
    std::vector<active_user_info_t> infolist;
#if defined(OEM_ZB_YINHE_KYLIN)
    /*VRV:TODO: test on multiple machine*/
    if(YCommonTool::get_active_user_info_systemd(infolist) >= 1) {
        /*just peak one usr*/
        current_user = infolist.at(0);
    } else {
	std::cout << "fdsafdasfsdfasfa" << std::endl;
    }
#else
    /*VRV:TODO: test on multiple machine*/
    if(get_active_user_info(infolist) && infolist.size() >= 1) {
        /*just peak one usr*/
        current_user = infolist.at(0);
    } 
#endif

    
    std::cout << " -->" << current_user.home_dir << std::endl;
    std::cout << " -->" << current_user.user_name << std::endl;
    std::cout << " -->" << current_user.uid << std::endl;
    std::cout << " -->" << current_user.display_no << std::endl;

    if(current_user.uid == -1) {
        return -2;
    }

	


    for (p_ctrl = processlist.begin(); p_ctrl != processlist.end(); p_ctrl++)
    {
        //vector<pid_t> pid_list;
        //status = get_process_status(p_ctrl->process_name.c_str(),pid_list);
        
        std::vector<active_process_info_t> pid_list;
        get_process_status_ext(p_ctrl->process_name.c_str(), pid_list);
        old_status = status_list[p_ctrl->process_name];
		status = filter_ac_process_by_uid(pid_list, current_user.uid);
        update_status(status);

#if 1
        cout << "name=" << p_ctrl->process_name << " ctrlmode=" << p_ctrl->ctrlmode <<" status=" << status << endl;
#endif
        if((status != p_ctrl->ctrlmode) && (-1 != status) && (p_ctrl->ctrlmode != 2))
        {
            if((p_ctrl->ctrlmode == 1) && (0 == status))
            {
                deal_flag = 1;
                on_off_choice = "on";
                creat_content(205, content, current_user.user_name, -1);
            }
            if((p_ctrl->ctrlmode == 0) && (1 == status))
            {
                deal_flag = 1;
                on_off_choice = "off";
                creat_content(204, content, current_user.user_name, -1);
            }
            if(p_ctrl->autokill == 1)
            {
                if(on_off_choice == "off")
                {
                    for(int j = 0;j<(int)pid_list.size();j++)
                    {
                        kill(pid_list[j].pid,SIGKILL);
                    }
                }
                if(on_off_choice == "on")
                {
                    execute_new(p_ctrl->process_name.c_str(), current_user);
                }
            }
            new_value += p_ctrl->process_name + int2str(status) + current_user.user_name;
            //要上报的信息
            char strtime[128]={0};
            YCommonTool::get_local_time(strtime);
            pkt_data = pkt_data + "Body" + int2str(i) + "=time="+strtime+ content + STRITEM_TAG_END;
            i++;
        }
		
		if ((p_ctrl->ctrlmode == 2) /*&& (xmlitem["OtherProcessDeal"] == "1")*/)
		{
				std::cout<<"process name"<<p_ctrl->process_name<<"status:"<<status<<"old status:"<<old_status<<std::endl;
			if (1 == status)
			{
			//上报正在运行
				for (int j=0; j<(int)pid_list.size(); j++)
				{
					deal_flag = 1;			
					creat_content(207, content, current_user.user_name, pid_list[j].pid);
					if (content != "")
					{
						new_value += p_ctrl->process_name + int2str(status) + current_user.user_name;
						char strtime[128]={0};
						YCommonTool::get_local_time(strtime);
						pkt_data = pkt_data + "Body" + int2str(i) + "=time="+strtime+ content + STRITEM_TAG_END;
						i++;
					}
				}
			}	
			if ((0==status) && (old_status==1))
			{
				old_status = status;
				//上报进程停止
				deal_flag = 1;
				creat_content(207, content, current_user.user_name, -1);

				new_value += p_ctrl->process_name + int2str(status) + current_user.user_name;
				char strtime[128]={0};
				YCommonTool::get_local_time(strtime);
				pkt_data = pkt_data + "Body" + int2str(i) + "=time="+strtime+ content + STRITEM_TAG_END;
				i++;
			}

		}

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
    printf("ProcessCtrl::OnRun finish--------------------------------\n");
    return 0;
}


#if 0
//status: 0:off,1:on,-1:unknown
int ProcessCtrl::get_process_status(const char* processname, vector<pid_t> &pid_list)
{
    pid_t pid;
    FILE *fp;
    DIR *dir;
    struct dirent *next;

    char cmdline[MAX_BUF_SIZE];
    char path[MAX_BUF_SIZE];
    int count = 0;
    char *base_pname = (char*)basename(processname);
    if(strlen(base_pname) <= 0)  return -1;
    dir = opendir("/proc");
    if (!dir)
    {
        g_GetlogInterface()->log_trace("opendir error");
        return -1;
    }
    while ((next = readdir(dir)) != NULL)
    {
        /* skip non-number */
        if (!isdigit(*next->d_name))
            continue;

        pid = strtol(next->d_name, NULL, 0);
        sprintf(path, "/proc/%u/status", pid);
        fp = fopen(path, "r");
        if(fp == NULL)
        {
            g_GetlogInterface()->log_trace("fopen error");
            continue;
        }
        memset(cmdline, 0, sizeof(cmdline));
        if(fgets(cmdline, MAX_BUF_SIZE - 1, fp) == NULL)
        {
            fclose(fp);
            continue;
        }
        fclose(fp);
        if(NULL!=strstr(cmdline,base_pname))
        {
            pid_list.push_back(pid);
            p_ctrl->process_id = pid;
            count++;
        }
    }
    closedir(dir) ;
    cout<<"count="<<count<<endl;
    if(count>0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}
#endif

int ProcessCtrl::get_process_status_ext(const char* processname, 
        std::vector<active_process_info_t> &pid_list)
{
	pid_t pid;
	FILE *fp;
	DIR *dir;
	struct dirent *next;

	char cmdline[MAX_BUF_SIZE];
	char path[MAX_BUF_SIZE];
	int count = 0;
	char *base_pname = (char*)basename(processname);
	cout << "base name is :" << base_pname << std::endl; 
	cout << "base name strlen " << strlen(base_pname) << std::endl;
	if(strlen(base_pname) <= 0)  return -1;
	dir = opendir("/proc");
	if (!dir)
	{
		printf("opendir error\n");
		return -1;
	}
	while ((next = readdir(dir)) != NULL) {

		/* skip non-number */
		if (!isdigit(*next->d_name))
			continue;

		pid = strtol(next->d_name, NULL, 0);
		sprintf(path, "/proc/%u/status", pid);
		fp = fopen(path, "r");
		if(fp == NULL)
		{
			printf("fopen error\n");
			continue;
		}
		memset(cmdline, 0, sizeof(cmdline));
#if 1
		if(fgets(cmdline, MAX_BUF_SIZE - 1, fp) == NULL) {
			fclose(fp);
			continue;
		}
#endif
		if(NULL != strstr(cmdline,base_pname)) {
			active_process_info_t pinfo;
			pinfo.pid = pid;
			while(fgets(cmdline, MAX_BUF_SIZE - 1, fp) != NULL) {
				if(strstr(cmdline, "Uid") == cmdline) {
					int read_uid = -1;
					sscanf(cmdline, "%*s%d%*d%*d%*d", &read_uid);
					pinfo.uid = read_uid;
					break;
				}
			}
			pid_list.push_back(pinfo);
			std::cout << "Find Process ID : " << pid << std::endl;
			count++;
		}

		//std::cout << "cmdline content is : " << cmdline << std::endl;
		fclose(fp);
	}
	closedir(dir) ;
	std::cout<< " get process status ext count= "<< count <<endl;
	if(count > 0) {
		return 1;
	} else {
		return 0;
	}
}
int ProcessCtrl::filter_ac_process_by_uid(
        const std::vector<active_process_info_t> &pid_list, int uid){
    int ret = 0;
    std::vector<active_process_info_t>::const_iterator iter = pid_list.begin();
    for(; iter != pid_list.end(); iter++) {
        if(iter->uid == uid) {
            ret++;
        }
    }
    return ret;
}

bool ProcessCtrl::import_xml(const char *pxml)
{
    printf("hello ProcessCtrl import_xml\n");
    if(pxml == NULL)
    {
        return false;
    }

    std::string in_info = pxml;
    std::string out_info;
    int srclen = in_info.length();
    int dstlen = srclen * 2+1;
    char *dst = new char[dstlen];
    code_convert("gb2312","utf-8",(char *)in_info.c_str(),srclen,dst,dstlen);
    out_info.assign(dst);
    delete[] dst;

    char property[256] = { 0 };
    processinfo item;
    processlist.clear();//清除上一次策略中的进程列表
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
            xmlitem["PersistAttack"] = xml.GetAttrib("PersistAttack");
            xmlitem["OtherProcessDeal"]  = xml.GetAttrib("OtherProcessDeal");
        }
        if(itemnum > 1)
        {
            int index = itemnum - 2;
            snprintf(property, sizeof(property) - 1, "ProcessName%d", index);
            item.process_name = xml.GetAttrib(property);
		    item.process_name = YCommonTool::trim(item.process_name);

            memset(property, '\0', sizeof(property));
            snprintf(property, sizeof(property) - 1, "MustRunProcess%d", index);
            item.ctrlmode = atoi(xml.GetAttrib(property).c_str());

            memset(property, '\0', sizeof(property));
            snprintf(property, sizeof(property) - 1, "AutoKill%d", index);
            item.autokill = atoi(xml.GetAttrib(property).c_str());

            memset(property, '\0', sizeof(property));
            snprintf(property, sizeof(property) - 1, "CompanyName%d", index);
			item.company_name = xml.GetAttrib(property);
			item.company_name = YCommonTool::trim(item.company_name);

			memset(property, '\0', sizeof(property));
			snprintf(property, sizeof(property) - 1, "ProductName%d", index);
			item.product_name = xml.GetAttrib(property);
			item.product_name = YCommonTool::trim(item.product_name);

            memset(property, '\0', sizeof(property));
			snprintf(property, sizeof(property) - 1, "SourceName%d", index);
			item.source_name = xml.GetAttrib(property);
			item.source_name = YCommonTool::trim(item.source_name);
            item.source_name = YCommonTool::trim(item.source_name);
            item.process_cksum = "";
            item.process_id = 0;
            processlist.push_back(item);
        }
    }
    xml.OutOfElem();
    cout<<"processlist.push_back(item):"<<processlist.size()<<endl;
    if(!xml.SetDoc(pxml))
    {
        return false;
    }
    return import_xmlobj(xml);
}

void ProcessCtrl::illegal_deal()
{
    switch(atoi(xmlitem["DealMode"].c_str()))
    {
        case 0:
            break;
        case 1:
        {
            g_GetlogInterface()->log_trace(xmlitem["PromptInfo1"].c_str());
            process_dialog(xmlitem["PromptInfo1"]);
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
            process_dialog(xmlitem["PromptInfo2"]);
            break;
        }
        case 3:
            g_GetlogInterface()->log_trace(xmlitem["PromptInfo3"].c_str());
            process_dialog(xmlitem["PromptInfo3"]);
            sleep(5);
            g_GetSendInterface()->sendto_Main(VCF_CMD_CALL_SHUTDOWN, NULL, 0);
            break;
        default:
            break;
    }
}


//本函数执行exepath指定的程序
int ProcessCtrl::execute_new(const char *exepath, const active_user_info_t &current_user)
{
    if(exepath == NULL)
    {
        return 0;
    }
    std::string real_exe = "";
    real_exe.append(exepath);
    real_exe = YCommonTool::trim(real_exe);
    //检测文件是否存在
    if(access(real_exe.c_str(),F_OK) == -1)
    {
        return 0;
    }

    pid_t pid;
    if((pid = fork())<0)
    {
        return -1;
    }
    else if(pid == 0)   //子进程中运行
    {
        /*here we just ignore is local attribute
         *because we can't figure it out clearly yet*/

        if(current_user.uid != -1) {
            setuid(current_user.uid);
            //std::cout << "++++ -> " << current_user.uid <<std::endl;
            setenv("HOME", current_user.home_dir.c_str(), 1);
            setenv("DISPLAY", current_user.display_no.c_str(), 1);
            setenv("USER", current_user.user_name.c_str(), 1);
            setenv("LANG", "zh_CN.UTF-8", 1);
            /*
            char *_pl = getenv("LANG");
            if(_pl == NULL) {
                setenv("LANG", "zh_CN.UTF-8", 1);
            }
            */
        }
        //system("env");
        /*
        std::string usrname;
        get_desk_user(usrname);
        g_GetlogInterface()->log_trace(usrname.c_str());

        if("root"!=usrname)
        {
            char str1[]="DISPLAY=:0.0";
            putenv(str1);
        }
        */
        printf("exepath = %s \n", real_exe.c_str());
        char *argv_execvp[]={(char*)real_exe.c_str(), NULL};
        if(execvp(real_exe.c_str(), argv_execvp)<0)
        {
            g_GetlogInterface()->log_trace("exec process fail");
            perror("exec process fail");
        }
        _exit(127);//子进程正常执行则不会执行此语句
    }
    else//主进程
    {
        signal(SIGCHLD, SIG_IGN);
    }
    return 1;
}

void ProcessCtrl::init_status()
{
	int status = -1;
    active_user_info_t current_user;

    /*detect active usr info*/
    std::vector<active_user_info_t> infolist;
#if defined(OEM_ZB_YINHE_KYLIN)
    /*VRV:TODO: test on multiple machine*/
    if(YCommonTool::get_active_user_info_systemd(infolist) >= 1) {
        /*just peak one usr*/
        current_user = infolist.at(0);
    } else {
	std::cout << "Init get user_info test on multiple machine" << std::endl;
    }
#else
    /*VRV:TODO: test on multiple machine*/
    if(get_active_user_info(infolist) && infolist.size() >= 1) {
        /*just peak one usr*/
        current_user = infolist.at(0);
    } 
#endif

	if(current_user.uid == -1) {
		std::cout << "Get user_info fail" << std::endl;
		return;
    }

	for (p_ctrl = processlist.begin(); p_ctrl != processlist.end(); p_ctrl++)
    {
        std::vector<active_process_info_t> pid_list;
        get_process_status_ext(p_ctrl->process_name.c_str(), pid_list);
		status = filter_ac_process_by_uid(pid_list, current_user.uid);
		update_status(status);
	}
}



void ProcessCtrl::update_status(int status)
{
	char strtime[128]={0};
	YCommonTool::get_local_time(strtime);
	if(status_list.end() != status_list.find(p_ctrl->process_name))
	{
		if((status_list[p_ctrl->process_name] != status) && (status != -1))
		{
			timeitem[p_ctrl->process_name] = strtime;
		}
	}
	status_list[p_ctrl->process_name] = status;
}

int ProcessCtrl::creat_content(int kind, std::string &content, const std::string &usrname, int pid)
{
	char buf[1024]={0};
	char strtime[128]={0};
	char starttime[128]={0};

#if 0
	std::string usrname;
	YCommonTool::get_local_time(strtime);
	get_desk_user(usrname);
#endif

	if(timeitem[p_ctrl->process_name] == "")
	{
		get_system_boot_time(starttime);
		timeitem[p_ctrl->process_name] = starttime;
	}

	if(kind == 204)//启动了禁用的进程
	{
		snprintf(buf,sizeof(buf)-1,"<>kind=%d<>policyid=%d<>policyname=%s<>KeyUserName=%s<>context=进程名：%s，启动时间：%s,进程公司名:%s,产品名称：%s,源文件名称：%s",
				kind,get_id(),get_name().c_str(),usrname.c_str(),basename(p_ctrl->process_name.c_str()),
				timeitem[p_ctrl->process_name].c_str(),
				p_ctrl->company_name.c_str(),
				p_ctrl->product_name.c_str(),
				p_ctrl->source_name.c_str()
				);
	}
	if(kind == 205)//关闭了必须运行的进程
	{
		snprintf(buf,sizeof(buf)-1,"<>kind=%d<>policyid=%d<>policyname=%s<>KeyUserName=%s<>context=进程名：%s，关闭时间：%s,进程公司名:%s,产品名称：%s,源文件名称：%s",
				kind,get_id(),get_name().c_str(),usrname.c_str(),basename(p_ctrl->process_name.c_str()),
				timeitem[p_ctrl->process_name].c_str(),
				p_ctrl->company_name.c_str(),
				p_ctrl->product_name.c_str(),
				p_ctrl->source_name.c_str()
				);
	}
	
	if (kind == 207 && pid != -1)
	{	
		std::string proc_run_time;
		proc_run_time = get_process_run_time(pid);
		printf("run_time :%s\n",proc_run_time.c_str());
		if (proc_run_time != "")
		{
			snprintf(buf,sizeof(buf)-1,"<>kind=%d<>policyid=%d<>policyname=%s<>KeyUserName=%s<>context=进程名(pid=%d)：%s，运行时间：%s,进程公司名:%s,产品名称：%s,源文件名称：%s",
				kind,get_id(),get_name().c_str(),usrname.c_str(),pid,basename(p_ctrl->process_name.c_str()),
				proc_run_time.c_str(),
				p_ctrl->company_name.c_str(),
				p_ctrl->product_name.c_str(),
				p_ctrl->source_name.c_str()
				);
		}
	}
	if (kind == 207 && pid == -1)
	{	
			snprintf(buf,sizeof(buf)-1,"<>kind=%d<>policyid=%d<>policyname=%s<>KeyUserName=%s<>context=进程名：%s，关闭时间：%s,进程公司名:%s,产品名称：%s,源文件名称：%s",
				kind,get_id(),get_name().c_str(),usrname.c_str(),basename(p_ctrl->process_name.c_str()),
				timeitem[p_ctrl->process_name].c_str(),
				p_ctrl->company_name.c_str(),
				p_ctrl->product_name.c_str(),
				p_ctrl->source_name.c_str()
				);
	}
	content = buf;
	if(p_ctrl->autokill == 1)
	{
		timeitem[p_ctrl->process_name] = strtime;
	}
	return 0;
}


void ProcessCtrl::copy_to(CPolicy * pDest)
{
    if(pDest->get_type() != PROCESS_CTRL)
    {
        return;
    }
    ProcessCtrl * pCtrl = (ProcessCtrl *) pDest;
    pCtrl->processlist = processlist;
    pCtrl->xmlitem = xmlitem;
    CPolicy::copy_to(pDest);
}
