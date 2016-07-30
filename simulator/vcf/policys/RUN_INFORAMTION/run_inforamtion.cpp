#include "run_inforamtion.h"

#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <unistd.h>
#include <sys/vfs.h>
#include "../../vrvprotocol/VRVProtocol.hxx"
#include "../../vrvprotocol/VRVProtocolEx.hxx"
#include "../../common/Commonfunc.h"
#include "../../vrcport_tool.h"
#include "../../VCFCmdDefine.h"
#include "../../../include/MCInterface.h"
using namespace std;

extern int code_convert(const char *from_charset,const char *to_charset,char *inbuf,int inlen,char *outbuf,int & outlen);

typedef struct cpu_occupy
{
    char name[20];
    unsigned int user;
    unsigned int nice;
    unsigned int system;
    unsigned int idle;
}CPU_OCCUPY;

#define DISKSTATS "/proc/diskstats"
#define UPTIME "/proc/uptime"

static unsigned int old_crcvalue;
static CPU_OCCUPY oldCpu;
static CPU_OCCUPY newCpu;
static int cpu_keep_times;
static int cpu_temp_keep_times;
static int disk_rd_keep_times;
static int disk_wr_keep_times;
static unsigned int hz;
static unsigned long old_rd_sectors=0;
static unsigned long old_wr_sectors=0;
static unsigned long new_rd_sectors;
static unsigned long new_wr_sectors;
static unsigned long long old_time;
static unsigned long long new_time;
static int mem_times;
static vector<string> vecDisk;
static vector<string> vecDiskOut;
static map<string,int> mapDiskTimes;	
static map<string,int> mapProCpu;
static map<string,int> mapOneProCpu;
static map<string,int> mapProMem;
static map<string,int> mapOneProMem;
#define HZ hz
#define S_VALUE(m,n,p)	(((double) ((n) - (m))) / (p) * HZ)

static CPolicyRunInforamtion *g_pPolicyRunInforamtion=NULL;

void Report_Audit_Info(string kind, string text)
{
    string SysUserName;

    //cout<<"Report_Audit_Info.........."<<endl;
    //YCommonTool::get_ttyloginUser("tty1", SysUserName);
    get_desk_user(SysUserName);
    if("" == SysUserName)
    {
        SysUserName="root";
    }
    char szTime[21]="";
    YCommonTool::get_local_time(szTime);

    char buffer[2048]={0};
    tag_Policylog *plog = (tag_Policylog *)buffer ;
    plog->type = AGENT_RPTAUDITLOG;
    plog->what = AUDITLOG_REQUEST;
    char *pTmp = plog->log ;
    sprintf(pTmp,"Body0=time=%s<>kind=%s<>policyid=%d<>policyname=%s<>KeyUserName=%s<>classaction=%d<>riskrank=%d<>context=%s%s%s%s"
    ,szTime
    ,kind.c_str()
    ,g_pPolicyRunInforamtion->get_id()
    ,g_pPolicyRunInforamtion->get_name().c_str()
    ,SysUserName.c_str()
    ,Abnormal_Behavior
    ,Event_Inform
    ,text.c_str()
    ,STRITEM_TAG_END
    ,"BodyCount=1"
    ,STRITEM_TAG_END);
    report_policy_log(plog);
    //cout<<"report finish........"<<endl;
}

void dialog_edp(string content)
{
    char buffer[512] = "";

    tag_GuiTips *pTips = (tag_GuiTips *)buffer ;
    pTips->sign = en_TipsGUI_btnOK | en_TipsGUI_timeOut ;
    pTips->defaultret = en_TipsGUI_None;
    sprintf(pTips->szTitle,"%s","提示");
    sprintf(pTips->szTips,"%s",content.c_str());
    pTips->pfunc = NULL;
    pTips->param.timeout = 5000;
    g_GetSendInterface()->sendto_Main(VCF_CMD_GUI_TIPS,buffer,sizeof(tag_GuiTips));
}

void get_cpuoccupy(CPU_OCCUPY *cpust)
{
    FILE *fd=NULL;
    char buff[256];
    CPU_OCCUPY *cpu_occupy;
    cpu_occupy = cpust;

    fd = fopen("/proc/stat", "r");
    if(fd)
    {
    	 fgets(buff, sizeof(buff), fd);
    	 sscanf(buff, "%s %u %u %u %u", cpu_occupy->name, &cpu_occupy->user, &cpu_occupy->nice, &cpu_occupy->system, &cpu_occupy->idle);
    	 fclose(fd);
    }

}
int get_cputemp()//need debug
{
    FILE *fd = NULL;
    char buff[32]={0};
    int tmp=0;

    fd=fopen("/sys/devices/platform/hwmon-loongson/cpu0_sensor1","r");
    if(fd !=  NULL)
    {
      fgets(buff,sizeof(buff),fd);
	  sscanf(buff,"%d",&tmp);
	  fclose(fd);
	  return tmp;
    }
    //cout<<"get_cputemp file not exist"<<endl;
    return 0;
}

void GetAllDisk()
{
    vecDisk.clear();
    char cFlag = 'a';
    string strDisk = "/dev/sd";
    while (1)
    {
        strDisk += cFlag;
        if (0 == access(strDisk.c_str(), F_OK))
        {
            vecDisk.push_back(strDisk);
            strDisk = "/dev/sd";
            cFlag += 1;
        }
        else
        {
            break;
        }
    }

    strDisk = "/dev/hd";
    cFlag = 'a';
    while (1)
    {
        strDisk += cFlag;
        if (0 == access(strDisk.c_str(), F_OK))
        {
            vecDisk.push_back(strDisk);
            strDisk = "/dev/hd";
            cFlag += 1;
        }
        else
        {
            break;
        }
    }
}

void cpNewToOld(CPU_OCCUPY *oldCpu, CPU_OCCUPY *newCpu)
{
    strncpy(oldCpu->name, newCpu->name, 20);
    oldCpu->user = newCpu->user;
    oldCpu->nice = newCpu->nice;
    oldCpu->system = newCpu->system;
    oldCpu->idle = newCpu->idle;
}

int cal_cpuoccupy(CPU_OCCUPY *o, CPU_OCCUPY *n)
{
    unsigned int od, nd;
    unsigned int id, sd;
    int cpu_use = 0;

    od = (unsigned int)(o->user + o->nice + o->system + o->idle);///第一次(用户+优先级+系统+空闲)的时间再赋给od
    nd = (unsigned int)(n->user + n->nice + n->system + n->idle);///第二次(用户+优先级+系统+空闲)的时间再赋给od

    id = (unsigned int)(n->user - o->user);    ///用户第一次和第二次的时间之差再赋给id
    sd = (unsigned int)(n->system - o->system);///系统第一次和第二次的时间之差再赋给sd
    if ((nd - od) != 0)
    {
        cpu_use = (int)((sd + id) * 10000) / (nd - od); ///((用户+系统)乖100)除(第一次和第二次的时间差)再赋给g_cpu_used
    }
    else
    {
        cpu_use = 0;
    }
    //printf("cpu: %u/n",cpu_use);
    return cpu_use;
}

void Process_Cpu_Mem_Info()
{
    mapOneProCpu.clear();
    mapOneProMem.clear();
    char line[2048] = { 0 };
    char csCpuPer[128] = { 0 };
    char csMemPer[128] = { 0 };
    char csCommand[256] = { 0 };
    float cpuPer = 0.0;
    float memPer = 0.0;
    string strCommand;
    bool dialog_proc_cpu = false;
    bool dialog_proc_mem = false;
    FILE *fp = NULL;
    fp = popen("ps haux --sort=-%cpu", "r"); //ps -eo pid,%cpu,cmd --sort=cpu
    if(fp == NULL) 
    {
    	return ;
    }
    while (fgets(line, 2048, fp))
    {
        if (strncmp("", line, 2048) == 0)
        {
            continue;
        }
        sscanf(line, "%*s%*s%s%s%*s%*s%*s%*s%*s%*s%s", csCpuPer, csMemPer, csCommand);
        cpuPer = atof(csCpuPer);
        memPer = atof(csMemPer);
        strCommand = csCommand;
        if(g_pPolicyRunInforamtion->ProcessCPUPercent !="" && g_pPolicyRunInforamtion->ProcessCPUKeepTime != "")
        {
            if ((int)cpuPer >= atoi(g_pPolicyRunInforamtion->ProcessCPUPercent.c_str()))
            {
                mapOneProCpu[strCommand] = 1;
            }
        }
        if(g_pPolicyRunInforamtion->ProcessMemoryPercent != "" && g_pPolicyRunInforamtion->ProcessMemoryKeepTime != "")
        {
            if ((int)memPer >= atoi(g_pPolicyRunInforamtion->ProcessMemoryPercent.c_str()))
            {
                mapOneProMem[strCommand] = 1;
            }
        }
    }
    pclose(fp);

    map<string, int>::iterator iterCpu = mapOneProCpu.begin();
    for (iterCpu = mapOneProCpu.begin(); iterCpu != mapOneProCpu.end(); iterCpu++)
    {
        int iTimes = 0;
        if (mapProCpu.find(iterCpu->first) == mapProCpu.end())
        {
            iTimes = 1;
            mapProCpu[iterCpu->first] = iTimes;
        }
        else
        {
            mapProCpu[iterCpu->first]++;
            iTimes = mapProCpu[iterCpu->first];
        }

        if (iTimes >= atoi(g_pPolicyRunInforamtion->ProcessCPUKeepTime.c_str()))
        {
            if ("1" == g_pPolicyRunInforamtion->ProcessPrompt) //report
            {
                string str = "进程" + iterCpu->first + "的CPU使用率连续" + g_pPolicyRunInforamtion->ProcessCPUKeepTime + "秒超出指定阀值" + g_pPolicyRunInforamtion->ProcessCPUPercent + "%" + "，告警成功！";
                Report_Audit_Info("310", str);
            }
            dialog_proc_cpu = true;
            mapProCpu[iterCpu->first] = 0;
        }
    }

    if(dialog_proc_cpu)
    {
        if ("1" == g_pPolicyRunInforamtion->ProcessInfo)
        {
             char outbuffer[129]="";
             int  out_len = 129 ;
             code_convert("gb2312","utf-8",const_cast<char *>(g_pPolicyRunInforamtion->ProcessPromptInfo.c_str()),g_pPolicyRunInforamtion->ProcessPromptInfo.length(),outbuffer,out_len);
             string dialog_msg=outbuffer;
             cout<<"open dialog for cpu"<<endl;
             dialog_edp(dialog_msg);
         }
    }

    for (iterCpu = mapProCpu.begin(); iterCpu != mapProCpu.end();)
    {
        if ((mapOneProCpu.find(iterCpu->first) == mapOneProCpu.end()) || (iterCpu->second == 0))
        {
            mapProCpu.erase(iterCpu++);
        }
        else
        {
            iterCpu++;
        }
    }

    map<string, int>::iterator iterMem = mapOneProMem.begin();
    for (iterMem = mapOneProMem.begin(); iterMem != mapOneProMem.end(); iterMem++)
    {
        int iTimes = 0;
        if (mapProMem.find(iterMem->first) == mapProMem.end())
        {
            iTimes = 1;
            mapProMem[iterMem->first] = iTimes;
        }
        else
        {
            mapProMem[iterMem->first]++;
            iTimes=mapProMem[iterMem->first];
        }

        if (iTimes >= atoi(g_pPolicyRunInforamtion->ProcessMemoryKeepTime.c_str()))
        {
            if ("1" == g_pPolicyRunInforamtion->ProcessPrompt) //report
            {
                string str = "进程" + iterMem->first + "的内存使用率连续" + g_pPolicyRunInforamtion->ProcessMemoryKeepTime + "秒超出指定阀值" + g_pPolicyRunInforamtion->ProcessMemoryPercent + "%" + "，告警成功！";
                Report_Audit_Info("311", str);
            }
            dialog_proc_mem = true;
            mapProMem[iterMem->first] = 0;
        }
    }

    if(dialog_proc_mem)
    {
        if ("1" == g_pPolicyRunInforamtion->ProcessInfo)
       {
            char outbuffer[129]="";
            int  out_len = 129 ;
            code_convert("gb2312","utf-8",const_cast<char *>(g_pPolicyRunInforamtion->ProcessPromptInfo.c_str()),g_pPolicyRunInforamtion->ProcessPromptInfo.length(),outbuffer,out_len);
            string dialog_msg=outbuffer;
            cout<<"open dialog for mem"<<endl;
            dialog_edp(dialog_msg);
       }
    }
    for (iterMem = mapProMem.begin(); iterMem != mapProMem.end();)
    {
        if ((mapOneProMem.find(iterMem->first) == mapOneProMem.end()) || (iterMem->second == 0))
        {
            mapProMem.erase(iterMem++);
        }
        else
        {
            iterMem++;
        }
    }

}

unsigned long long get_interval(unsigned long long prev_uptime, unsigned long long curr_uptime)
{
	unsigned long long itv;

	itv = curr_uptime - prev_uptime;

	if (!itv) 
	{
		itv = 1;
	}

	return itv;
}

void read_uptime(unsigned long long *uptime)
{
	FILE *fp = NULL;
	char line[128];
	unsigned long up_sec, up_cent;

	if ((fp = fopen(UPTIME, "r")) == NULL)
	{
		return;
	}

	if (fgets(line, sizeof(line), fp) == NULL) 
	{
		fclose(fp);
		return;
	}

	sscanf(line, "%lu.%lu", &up_sec, &up_cent);
	*uptime = (unsigned long long) up_sec * HZ + (unsigned long long) up_cent * HZ / 100;

	fclose(fp);

}

void check_disk_throughput()
{
    double read_speed;
    double write_speed;

    unsigned int ios_pgr, tot_ticks, rq_ticks, wr_ticks;
    unsigned long rd_ios, rd_merges_or_rd_sec, rd_ticks_or_wr_sec, wr_ios;
    unsigned long wr_merges, rd_sec_or_wr_ios, wr_sec;
    unsigned long long itv;
    FILE *fp=NULL;
    char line[256]={0};
    char dev_name[72]={0};
    int i;
    unsigned int major, minor;
    int fctr = 2048;
    long ticks;

    if((ticks = sysconf(_SC_CLK_TCK)) == -1)
    {
        //perror("sysconf");
        cout<<"sysconf error."<<endl;
        return;
    }
    hz = (unsigned int)ticks;
    if(hz == 0)
    {
        cout<<"get ticks error."<<endl;
        return;
    }
    cout<<"hz: "<<hz<<endl;

    new_time = 0;
    read_uptime(&new_time);
    itv = get_interval(old_time,new_time);

    old_time=new_time;

    if ((fp = fopen(DISKSTATS, "r")) == NULL)
    {
        cout<<"fopen error."<<endl;
        return; 
    } 
    while (fgets(line, sizeof(line), fp) != NULL) 
    {
        i = sscanf(line, "%u %u %s %lu %lu %lu %lu %lu %lu %lu %u %u %u %u",
			       &major, &minor, dev_name,
			       &rd_ios, &rd_merges_or_rd_sec, &rd_sec_or_wr_ios, &rd_ticks_or_wr_sec,
			       &wr_ios, &wr_merges, &wr_sec, &wr_ticks, &ios_pgr, &tot_ticks, &rq_ticks);
        if(strcmp(dev_name,"sda"))
        {
            continue;
        }

        new_rd_sectors = rd_sec_or_wr_ios;
        if(old_rd_sectors == 0)
        {
            old_rd_sectors = new_rd_sectors;
        }

        new_wr_sectors = wr_sec;
        if(old_wr_sectors == 0)
        {
            old_wr_sectors = new_wr_sectors;
        }
    }
    fclose(fp);

    read_speed=S_VALUE(old_rd_sectors, new_rd_sectors, itv) / fctr;

    write_speed=S_VALUE(old_wr_sectors, new_wr_sectors, itv) / fctr;

    old_rd_sectors=new_rd_sectors;
    old_wr_sectors=new_wr_sectors;

    if(g_pPolicyRunInforamtion->IOOutSpeed != "" && g_pPolicyRunInforamtion->IOOutSpeedKeepTime !="")
    {
        if(read_speed > (atoi(g_pPolicyRunInforamtion->IOOutSpeed.c_str())))
        {
            disk_rd_keep_times++;
        }
        else
        {
            disk_rd_keep_times=0;
        }

        if(disk_rd_keep_times> atoi(g_pPolicyRunInforamtion->IOOutSpeedKeepTime.c_str()))
        {
            if ("1" == g_pPolicyRunInforamtion->IOReport) //report
            {
                string str = "终端硬盘读取速度" + g_pPolicyRunInforamtion->IOOutSpeedKeepTime+ "秒超出指定阀值" + g_pPolicyRunInforamtion->IOOutSpeed+ "M/S" + "，告警成功！";
                Report_Audit_Info("302", str);
                disk_rd_keep_times= 0;
            }
            if ("1" == g_pPolicyRunInforamtion->IOClientPrompt)
            {
                char outbuffer[129]="";
                int  out_len = 129 ;
                code_convert("gb2312","utf-8",const_cast<char *>(g_pPolicyRunInforamtion->IOClientPromtInfo.c_str()),g_pPolicyRunInforamtion->IOClientPromtInfo.length(),outbuffer,out_len);
                string dialog_msg=outbuffer;
                dialog_edp(dialog_msg);
                disk_rd_keep_times = 0;
            }        
         }
    }

    if(g_pPolicyRunInforamtion->IOInSpeed != "" && g_pPolicyRunInforamtion->IOInSpeedKeepTime != "")
    {
        if(write_speed> (atoi(g_pPolicyRunInforamtion->IOInSpeed.c_str())))
        {
            disk_wr_keep_times++;
        }
        else
        {
            disk_wr_keep_times=0;
        }

        if(disk_wr_keep_times > atoi(g_pPolicyRunInforamtion->IOInSpeedKeepTime.c_str()))
        {
            if ("1" == g_pPolicyRunInforamtion->IOReport) //report
            {
                string str = "终端硬盘写入速度" + g_pPolicyRunInforamtion->IOInSpeedKeepTime+ "秒超出指定阀值" + g_pPolicyRunInforamtion->IOInSpeed+ "M/S" + "，告警成功！";
                Report_Audit_Info("302", str);
                disk_wr_keep_times= 0;
            }
            if ("1" == g_pPolicyRunInforamtion->IOClientPrompt)
            {
                char outbuffer[129]="";
                int  out_len = 129 ;
                code_convert("gb2312","utf-8",const_cast<char *>(g_pPolicyRunInforamtion->IOClientPromtInfo.c_str()),g_pPolicyRunInforamtion->IOClientPromtInfo.length(),outbuffer,out_len);
                string dialog_msg=outbuffer;
                dialog_edp(dialog_msg);
                disk_wr_keep_times = 0;
            }        
        }
    }
}

void check_disk_temp()
{
    if(g_pPolicyRunInforamtion->DiskTemperature == "" || g_pPolicyRunInforamtion->DiskTemperatureKeepTime == "")
    {
        return;
    }
    GetAllDisk();
    vector<string>::iterator iterDisk = vecDisk.begin();
    char cmd[256] = { 0 };
    char result[512] = { 0 };

    ///查看硬盘温度是否超标，超标的硬盘名称存入vecDiskOut
    for (iterDisk = vecDisk.begin(); iterDisk != vecDisk.end(); iterDisk++)
    {
        string strDisk = *iterDisk;
        sprintf(cmd, "smartctl -A %s | grep '194' | awk '{print $10}'", strDisk.c_str());
        FILE *fp = popen(cmd, "r");
        if (fp == NULL)
        {
            continue;
        }
        while (fgets(result, sizeof(result), fp))
        {
            ;
        }
        string str = result;
        pclose(fp);
        string strTemp = str;

        if (atoi(strTemp.c_str()) >= atoi(g_pPolicyRunInforamtion->DiskTemperature.c_str()))
        {
            vecDiskOut.push_back(strDisk);
        }
    }

    ///累计硬盘温度超标次数
    vector<string>::iterator iterOut = vecDiskOut.begin();
    map<string, int>::iterator iterTimes;
    for (iterOut = vecDiskOut.begin(); iterOut != vecDiskOut.end(); iterOut++)
    {
        string strDiskOut = *iterOut;
        iterTimes = mapDiskTimes.find(strDiskOut);
        if (iterTimes != mapDiskTimes.end())
        {
            iterTimes->second += 1;
        }
        else
        {
            mapDiskTimes[strDiskOut] = 1;
        }
    }

    ///反向查找，本次硬盘温度没有超标的硬盘信息从mapDiskTimes删除
    for (iterTimes = mapDiskTimes.begin(); iterTimes != mapDiskTimes.end();)
    {
        if (find(vecDiskOut.begin(), vecDiskOut.end(), iterTimes->first) == vecDiskOut.end())
        {
            mapDiskTimes.erase(iterTimes++);
        }
        else
        {
            iterTimes++;
        }
    }

    vecDiskOut.clear();

    ///判断硬盘温度超标次数是否达到服务器定义的上线，并做出相应处理
    for (iterTimes = mapDiskTimes.begin(); iterTimes != mapDiskTimes.end();)
    {
        if (iterTimes->second >= atoi(g_pPolicyRunInforamtion->DiskTemperatureKeepTime.c_str()))
        {
            if ("1" == g_pPolicyRunInforamtion->DISKPrompt)
            {
                char outbuffer[129]="";
                int  out_len = 129 ;
                code_convert("gb2312","utf-8",const_cast<char *>(g_pPolicyRunInforamtion->DISKPromptInfo.c_str()),g_pPolicyRunInforamtion->DISKPromptInfo.length(),outbuffer,out_len);
                string dialog_msg=outbuffer;
                dialog_edp(dialog_msg);
            }
            if ("1" == g_pPolicyRunInforamtion->DISKUpInfo)
            {
                //report
                string str = "终端硬盘温度连续" + g_pPolicyRunInforamtion->DiskTemperatureKeepTime + "秒超出指定阀值" + g_pPolicyRunInforamtion->DiskTemperature + "℃，告警成功！";
                Report_Audit_Info("302", str);
            }
            mapDiskTimes.erase(iterTimes++);
        }
        else
        {
            iterTimes++;
        }
    }
}

static void check_disk_space_avail()
{	
	char disk_path[128] = "/";
	struct statfs diskInfo;

	statfs(disk_path, &diskInfo);
	uint64_t blocksize = diskInfo.f_bsize;
	uint64_t availableDisk = diskInfo.f_bavail * blocksize;

	if(g_pPolicyRunInforamtion->MinSystemDiskSpace == "")
	{
		return;
	}

	if ((availableDisk>>20) <= atoi(g_pPolicyRunInforamtion->MinSystemDiskSpace.c_str()))
	{
		if ("1" == g_pPolicyRunInforamtion->DISKPrompt)
		{
			char outbuffer[129]="";
			int  out_len = 129 ;
			code_convert("gb2312","utf-8",const_cast<char *>(g_pPolicyRunInforamtion->DISKPromptInfo.c_str()),g_pPolicyRunInforamtion->DISKPromptInfo.length(),outbuffer,out_len);
			string dialog_msg=outbuffer;
			dialog_edp(dialog_msg);
		}
		if ("1" == g_pPolicyRunInforamtion->DISKUpInfo)
		{		//report 
			string str = "磁盘剩余空间不足" + g_pPolicyRunInforamtion->MinSystemDiskSpace + "M，告警成功！";
			Report_Audit_Info("302", str);
			cout << "剩余空间:" << (availableDisk>>20) << "M； == " << (availableDisk>>10) << "K" << endl;
		}
	}

}

void Disk_Info()
{
	check_disk_temp();
	check_disk_throughput();
	check_disk_space_avail();
}

void Mem_Info()
{
    if(g_pPolicyRunInforamtion->MEMPercent == "" || g_pPolicyRunInforamtion->MEMKeepTime == "")
    {
        cout<<"mem_info null"<<endl;
	  return;
    }
    FILE *fp=NULL;
    fp = popen("cat /proc/meminfo", "r");
    if (NULL == fp)
    {
        return;
    }
    char buffer[32] = { '\0' };
    char memtotal[16] = { '\0' };
    char total_size[16] = { '\0' };
    char memfree[16] = { '\0' };
    char free_size[16] = { '\0' };
    string str_total;
    string str_free;
    //static int mem_times = 0;
    int total, free;
    float memrate, mem_policy;
    int index;
    for (index = 0; index < 2; index++) //only need 'total' and 'free'
    {
        fgets(buffer, 31, fp);
        if (0 == index)
        {
            sscanf(buffer, "%s%s", memtotal, total_size);
            str_total.assign(total_size);
        }
        else if (1 == index)
        {
            sscanf(buffer, "%s%s", memfree, free_size);
            str_free.assign(free_size);
        }
    }
    pclose(fp);
    total = atoi(str_total.c_str());
    free = atoi(str_free.c_str());
    memrate = (float)(total - free) / (float)total;
    mem_policy = (float)atoi(g_pPolicyRunInforamtion->MEMPercent.c_str()) / 100.00;
    if (memrate > mem_policy)
    {
        mem_times++;
    }
    else
    {
        mem_times = 0;
    }
    if (mem_times > atoi(g_pPolicyRunInforamtion->MEMKeepTime.c_str()))
    {
        if ("1" == g_pPolicyRunInforamtion->MEMPrompt)
        {
            char outbuffer[129]="";
            int  out_len = 129 ;
            code_convert("gb2312","utf-8",const_cast<char *>(g_pPolicyRunInforamtion->MEMPromptInfo.c_str()),g_pPolicyRunInforamtion->MEMPromptInfo.length(),outbuffer,out_len);
            string dialog_msg=outbuffer;
            dialog_edp(dialog_msg);
            mem_times = 0;
        }
        if ("1" == g_pPolicyRunInforamtion->MEMUpInfo)
        {
            //report
            string str = "终端内存使用率连续" + g_pPolicyRunInforamtion->MEMKeepTime + "秒超出指定阀值" + g_pPolicyRunInforamtion->MEMPercent + "%" + "，告警成功！";
            Report_Audit_Info("301", str);
            mem_times = 0;
        }
    }
}

void check_cpu_temp()
{
    if(g_pPolicyRunInforamtion->CPUTemperature=="" || g_pPolicyRunInforamtion->CPUTempKeepTime=="")
    {
        cout<<"check_cpu_temp null"<<endl;
        return;
    }
    int cpu_temp = 0;
    cpu_temp = get_cputemp();
    if(cpu_temp == 0)
    {
        cout<<"check_cpu_temp cpu_temp =0"<<endl;
        return;
    }
    if(cpu_temp > (atoi(g_pPolicyRunInforamtion->CPUTemperature.c_str())))
    {
        cpu_temp_keep_times++;
    }
    else
    {
        cpu_temp_keep_times=0;
    }
    if(cpu_temp_keep_times > atoi(g_pPolicyRunInforamtion->CPUTempKeepTime.c_str()))
    {
        if ("1" == g_pPolicyRunInforamtion->CPUUpInfo) //report
        {
            string str = "终端CPU温度" + g_pPolicyRunInforamtion->CPUTempKeepTime + "秒超出指定阀值" + g_pPolicyRunInforamtion->CPUTemperature+ "℃" + "，告警成功！";
            Report_Audit_Info("300", str);
            cpu_temp_keep_times= 0;
        }
        if ("1" == g_pPolicyRunInforamtion->CPUPrompt)
        {
            char outbuffer[129]="";
            int  out_len = 129 ;
            code_convert("gb2312","utf-8",const_cast<char *>(g_pPolicyRunInforamtion->CPUPromptInfo.c_str()),g_pPolicyRunInforamtion->CPUPromptInfo.length(),outbuffer,out_len);
            string dialog_msg=outbuffer;
            dialog_edp(dialog_msg);
            cpu_temp_keep_times = 0;
        }        
    }
}
void check_cpu_usage()
{
    if(g_pPolicyRunInforamtion->CPUKeepTime == "" ||g_pPolicyRunInforamtion->CPUPercent == "")
    {
        cout<<"check_cpu_usage options is null."<<endl;
        return;
    }
    int cpuuse = 0;
    get_cpuoccupy((CPU_OCCUPY *)&newCpu);

    cpuuse = cal_cpuoccupy((CPU_OCCUPY *)&oldCpu, (CPU_OCCUPY *)&newCpu);

    cpNewToOld((CPU_OCCUPY *)&oldCpu, (CPU_OCCUPY *)&newCpu);

    if (cpuuse > (atoi(g_pPolicyRunInforamtion->CPUPercent.c_str()) * 100))
    {
        cpu_keep_times++;
    }
    else
    {
        cpu_keep_times = 0;
    }
    if (cpu_keep_times > atoi(g_pPolicyRunInforamtion->CPUKeepTime.c_str()))
    {
        if ("1" == g_pPolicyRunInforamtion->CPUUpInfo) //report
        {
            string str = "终端CPU使用率连续" + g_pPolicyRunInforamtion->CPUKeepTime + "秒超出指定阀值" + g_pPolicyRunInforamtion->CPUPercent + "%" + "，告警成功！";
            Report_Audit_Info("300", str);
            cpu_keep_times = 0;
        }
        if ("1" == g_pPolicyRunInforamtion->CPUPrompt)
        {
            char outbuffer[129]="";
            int  out_len = 129 ;
            code_convert("gb2312","utf-8",const_cast<char *>(g_pPolicyRunInforamtion->CPUPromptInfo.c_str()),g_pPolicyRunInforamtion->CPUPromptInfo.length(),outbuffer,out_len);
            string dialog_msg=outbuffer;
            dialog_edp(dialog_msg);
            cpu_keep_times = 0;
        }
    }
}
void Cpu_Info()
{
    check_cpu_usage();
    check_cpu_temp();
}

bool run_inforamtion_init() 
{
    cout<<"enter run_inforamtion_init() "<<endl;

    cout<<"leave run_inforamtion_init() "<<endl;

    return  true ;
}

bool run_inforamtion_worker(CPolicy * pPolicy, void * pParam) 
{
    cout<<"enter  run_inforamtion_worker()"<<endl;

    ///获取当前策略类型
    if(pPolicy->get_type() != RUN_INFOMATION) 
    {
        return false ;
    }

    g_pPolicyRunInforamtion = (CPolicyRunInforamtion*)pPolicy;
 
    if(old_crcvalue != g_pPolicyRunInforamtion->get_crc())
    {
        cout<<"init all vars..."<<endl;
        cpu_keep_times = 0;
        cpu_temp_keep_times = 0;
        disk_rd_keep_times = 0;
        disk_wr_keep_times = 0;
        old_rd_sectors=0;
        old_wr_sectors=0;
        old_time=0;
        read_uptime(&old_time);
        mem_times = 0;
        mapProCpu.clear();
        mapOneProCpu.clear();
        mapProMem.clear();
        mapOneProMem.clear();

        vecDisk.clear();
        vecDiskOut.clear();
        mapDiskTimes.clear();

        memset(&oldCpu,0,sizeof(CPU_OCCUPY));
        memset(&newCpu,0,sizeof(CPU_OCCUPY));

        get_cpuoccupy((CPU_OCCUPY *)&oldCpu);
        ///save policy crc
        old_crcvalue = g_pPolicyRunInforamtion->get_crc();
    }

    Cpu_Info();
    Mem_Info();
    Disk_Info();
    Process_Cpu_Mem_Info();
    cout<<"leave  run_inforamtion_worker()"<<endl;

    return true;
}

void run_inforamtion_uninit() 
{
    cout<<"enter run_inforamtion_uninit()"<<endl;

    cout<<"leave run_inforamtion_uninit()"<<endl;
    return;
}

