#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <map>
#include "policy_client_set.h"

static int client_set_old_crc = 0;

bool  policy_client_set_init() {
    client_set_old_crc = 0;
    return true;
}


/*kind == 1100 SYNC_TIME*/
static void report_client_set_log(const std::string &log_des, int kind, CPolicy *policy) {

    if(policy == NULL) {
        g_GetlogInterface()->log_trace("report time policy is null");
        return;
    }
    std::map<int, std::string> base_desc_map;
    base_desc_map[1100] = "终端时间异常";

    std::string base_des = base_desc_map[kind];
    if(base_des.empty()) {
        return;
    }
    base_des.append(", ");
    base_des.append(log_des);

	char szTime[21]="";
	YCommonTool::get_local_time(szTime);
    char log_buf[2048] = {0};

	tag_Policylog * plog = (tag_Policylog *)log_buf;
	plog->what = 1;
	plog->type = 61;
	char * pTmp = plog->log ;
	std::string user;
	get_desk_user(user);

    sprintf(pTmp,"Body0=time=%s<>kind=%d<>policyid=%d<>policyname=%s<>KeyUserName=%s"
            "<>classaction=2<>riskrank=6<>context=%s: %s%s%s",
				szTime, kind, policy->get_id(),
				policy->get_name().c_str(),
				user.c_str(),
			    base_des.c_str(),
                STRITEM_TAG_END,"BodyCount=1",STRITEM_TAG_END);
    report_policy_log(plog);
}

static void sync_local_time(const std::string &server_time, CPolicy *policy) {
	//TIME=2016-06-05 12:31:31
    std::string real_time = server_time.substr(strlen("TIME="), server_time.length());
    int time_off_set = 3;
    time_t inner_sec = 0;
    /*no offset*/
    char org_time_buf[128] = {0};
    time_t org_time_t  = time(NULL);
    strftime(org_time_buf, 127, "%Y-%m-%d %T", localtime(&org_time_t));
    int sync_ret = YCommonTool::set_time(real_time, time_off_set, inner_sec);
    if(sync_ret < 0) {
        g_GetlogInterface()->log_trace("set time error ");
        return;
    } else if(sync_ret > 0){
        char buf[128] = {0};
        strftime(buf, 127, "%Y-%m-%d %T", localtime(&inner_sec));
        std::cout << "set time success " << buf <<std::endl;
        std::string log_desc;
		//同步为 2016-06-05 15:00, 异常时间: 2016-06-05 14:34
        log_desc.append("同步为 ");
        log_desc.append(buf);
        log_desc.append(", 异常时间: ");
        log_desc.append(org_time_buf);
        report_client_set_log(log_desc, 1100, policy);
        return;
    }
    std::cout << " the same time no need to sync " << org_time_buf <<std::endl;
}

bool  policy_client_set_worker(CPolicy * pPolicy, void * pParam) {
    if(pPolicy == NULL) {
        return false;
    }
	if(pPolicy->get_type() != POLICY_CLIENT_SET) {
		return false ;
	}
	PolicyClientSet * pset = (PolicyClientSet *)pPolicy ;
    if(pset->get_sync_time() == 1) {
        std::string server_time;
        g_GetlcfgInterface()->get_lconfig(lcfg_get_server_time, server_time);
        if(!server_time.empty()) {
            sync_local_time(server_time, pPolicy);
        }
    }
    return true;
}

void  policy_client_set_uninit() {
    client_set_old_crc = 0;
    return;
}


bool PolicyClientSet::import_xml(const char * pxml) {
	if(pxml == NULL) {
		return false ;
	}
	CMarkup  xml ;
	if(!xml.SetDoc(pxml)) {
		return false ;
	}
    std::cout << " policy xml is " << pxml <<std::endl;

	if(xml.FindElem("vrvscript")) {
		xml.IntoElem();
		while(xml.FindElem("item")) {
			m_sync_time = atoi(xml.GetAttrib("SyncTime").c_str());
			//weblist = xml.GetAttrib("WEBList");
			//m_Acmode = atoi(xml.GetAttrib("AccessMode").c_str());
			//httpslist = xml.GetAttrib("HttpsList").c_str();
			//m_httpsEnable = (atoi(xml.GetAttrib("HttpsAccessMode").c_str())==1);
		}
		xml.OutOfElem();
	}
	return CPolicy::import_xmlobj(xml) ;
}
void PolicyClientSet::copy_to(CPolicy * pDest)  {
    PolicyClientSet * _pDest = (PolicyClientSet *)pDest ;
    _pDest->m_sync_time = m_sync_time;
	CPolicy::copy_to(pDest);
}
