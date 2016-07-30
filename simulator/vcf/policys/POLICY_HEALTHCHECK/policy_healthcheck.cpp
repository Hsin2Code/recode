
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include "../../vrvprotocol/VRVProtocol.hxx"
#include "../../vrvprotocol/VRVProtocolEx.hxx"
#include "../../common/Commonfunc.h"
#include "../../vrcport_tool.h"
#include "../../VCFCmdDefine.h"
#include "../../../include/MCInterface.h"
#include "policy_healthcheck.h"
using namespace std;

static void policy_healthcheck_log_info(const char *log_content);

#define POLICY_HEALTHCHECK_CIGPATH "./gateway_cfg_dat/policy_healthcheck.cfg"
#define POLICY_HEALTHCHECK_WDIR "./gateway_cfg_dat/"

static unsigned int old_crcvalue;

static CPolicyHealthcheck *g_pPolicyHealthcheck=NULL;

struct healthcheck_policy_t
{
    int SITStart;
    int SITFile;
    int SITRDesk;
    int SITShare;
    int SITHidFile;
    int SITUser;
    int SITGpInfo;
    int SITURL; 
    int SITHosts;
    int SITVirus;
    int SITProc;
    int SITSrv;
    int SITSysFlaw;
    int SITPass;
    int SITIEProx;
};


int write_healthcheck_config()
{
    FILE *fp=NULL;
    int rnt_wr=0;
    char log_buf[128] = {0};

    policy_healthcheck_log_info("write healthcheck_config starting...");

    fp=fopen(POLICY_HEALTHCHECK_CIGPATH,"wb");
    if(fp == NULL)
    {
        snprintf(log_buf, sizeof(log_buf), "healthcheck_config,fopen err,code:%d", errno);
        policy_healthcheck_log_info(log_buf);
        return -1;
    }

    struct healthcheck_policy_t stHealthChpolicy;
    memset(&stHealthChpolicy,0,sizeof(struct healthcheck_policy_t));
    stHealthChpolicy.SITStart = atoi(g_pPolicyHealthcheck->SITStart.c_str());
    stHealthChpolicy.SITFile = atoi(g_pPolicyHealthcheck->SITFile.c_str());
    stHealthChpolicy.SITRDesk = atoi(g_pPolicyHealthcheck->SITRDesk.c_str());
    stHealthChpolicy.SITShare = atoi(g_pPolicyHealthcheck->SITShare.c_str());
    stHealthChpolicy.SITHidFile = atoi(g_pPolicyHealthcheck->SITHidFile.c_str());
    stHealthChpolicy.SITUser = atoi(g_pPolicyHealthcheck->SITUser.c_str());
    stHealthChpolicy.SITGpInfo = atoi(g_pPolicyHealthcheck->SITGpInfo.c_str());
    stHealthChpolicy.SITURL = atoi(g_pPolicyHealthcheck->SITURL.c_str()); 
    stHealthChpolicy.SITHosts = atoi(g_pPolicyHealthcheck->SITHosts.c_str());
    stHealthChpolicy.SITVirus =atoi(g_pPolicyHealthcheck->SITVirus.c_str());
    stHealthChpolicy.SITProc = atoi(g_pPolicyHealthcheck->SITProc.c_str());
    stHealthChpolicy.SITSrv = atoi(g_pPolicyHealthcheck->SITSrv.c_str());
    stHealthChpolicy.SITSysFlaw = atoi(g_pPolicyHealthcheck->SITSysFlaw.c_str());
    stHealthChpolicy.SITPass = atoi(g_pPolicyHealthcheck->SITPass.c_str());
    stHealthChpolicy.SITIEProx = atoi(g_pPolicyHealthcheck->SITIEProx.c_str());

    rnt_wr=fwrite(&stHealthChpolicy,sizeof(struct healthcheck_policy_t),1,fp);
    if(rnt_wr != 1)
    {
        snprintf(log_buf, sizeof(log_buf), "healthcheck_config,fwrite err,code:%d", errno);
        policy_healthcheck_log_info(log_buf);
        fclose(fp);
	    return -1;
    }

    fclose(fp);
    policy_healthcheck_log_info("write healthcheck_config succ.");
    return 0;
}

void cleanup_healthcheck_configfile()
{
    char cmdbuf[128] = {0};
    char log_buf[128] = {0};

    if( -1 != access(POLICY_HEALTHCHECK_CIGPATH,F_OK))
    {
        if(-1 == unlink(POLICY_HEALTHCHECK_CIGPATH))
        {
            snprintf(log_buf, sizeof(log_buf), "removing old policy file %s err", POLICY_HEALTHCHECK_CIGPATH);
            policy_healthcheck_log_info(log_buf);
        }
        else
        {
            snprintf(log_buf, sizeof(log_buf), "removing old policy %s ok", POLICY_HEALTHCHECK_CIGPATH);
            policy_healthcheck_log_info(log_buf);
        }
    }
}


void setworkpwd()
{
    char log_buf[128] = {0};
    char cmd_buf[128] = {0};
    int ret = 0;

    if(access(POLICY_HEALTHCHECK_WDIR,0))
    {
        mkdir(POLICY_HEALTHCHECK_WDIR,0777);        

        snprintf(log_buf, sizeof(log_buf), "%s dose not exist, created.", POLICY_HEALTHCHECK_WDIR);
        policy_healthcheck_log_info(log_buf);

        snprintf(cmd_buf, sizeof(cmd_buf), "chmod 777 %s", POLICY_HEALTHCHECK_WDIR);
        ret = system(cmd_buf);
        snprintf(log_buf, sizeof(log_buf), "%s file mode is changed with ret:%d.", POLICY_HEALTHCHECK_WDIR, ret);
        policy_healthcheck_log_info(log_buf);
    }
    else
    {
        snprintf(log_buf, sizeof(log_buf), "%s already exist.", POLICY_HEALTHCHECK_WDIR);
        policy_healthcheck_log_info(log_buf);
    }
}

bool policy_healthcheck_init() 
{
    policy_healthcheck_log_info("init starting.");

    old_crcvalue = 0;
    setworkpwd();

    policy_healthcheck_log_info("init end.");

    return  true ;
}

bool policy_healthcheck_worker(CPolicy * pPolicy, void * pParam) 
{
    if(pPolicy->get_type() != POLICY_HEALTHCHECK) 
    {
        policy_healthcheck_log_info("worker:policy type invalid.");
        return false ;
    }

    g_pPolicyHealthcheck = (CPolicyHealthcheck *)pPolicy;
 
    if(old_crcvalue != g_pPolicyHealthcheck->get_crc())
    {
        policy_healthcheck_log_info("worker:policy changed, saving policy.");
        cleanup_healthcheck_configfile();
        write_healthcheck_config();

        ///save policy crc
        old_crcvalue = g_pPolicyHealthcheck->get_crc();
    }

    return true;
}

void policy_healthcheck_uninit()
{
    policy_healthcheck_log_info("uninit starting.");

    cleanup_healthcheck_configfile();
    old_crcvalue = 0;

    policy_healthcheck_log_info("uninit end.");
    return;
}

static void policy_healthcheck_log_info(const char *log_content)
{
	char log_info[2048] = {0};

	if(NULL == log_content)
	{
		return ;
	}
	
	snprintf(log_info, sizeof(log_info), "health_check:%s\n", log_content);

	g_GetlogInterface()->loglog(log_info);
}
