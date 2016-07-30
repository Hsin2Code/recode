#ifndef _NET_BD_CHK_H_
#define _NET_BD_CHK_H_
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <errno.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <fcntl.h>
#include "../../CVRVNetProtocol.h"
#include "../../vrvprotocol/VRVProtocol.hxx"
#include "../../vrvprotocol/VRVProtocolEx.hxx"
#include "../../common/Commonfunc.h"
#include "../../VCFCmdDefine.h"
#include "../../../include/MCInterface.h"
#include "../policysExport.h"


using namespace std;

#define NET_BD_CHK_INFO_PATH "/var/log/net_bd_chk_info"

extern int code_convert(const char *from_charset,const char *to_charset,char *inbuf,int inlen,char *outbuf,int &outlen);

extern bool net_bd_chk_init();
extern bool net_bd_chk_worker(CPolicy *, void *);
extern void net_bd_chk_uninit();

class CNetBdChk : public CPolicy
{
public:
    CNetBdChk() {
	enPolicytype type = NET_BD_CHK;
	set_type(type);
    }

    virtual bool import_xml(const char* pxml) {
	if(pxml == NULL) {
	    return false;
	}
	CMarkup xml;
	if(!xml.SetDoc(pxml)){
	    return false;
	}
	if(xml.FindElem("vrvscript")) {
	    xml.IntoElem();
	    while(xml.FindElem("item")) {
		proxycheck = atoi(xml.GetAttrib("proxycheck").c_str());
		Can_Proxy = atoi(xml.GetAttrib("Can_Proxy").c_str());
		Detection_Cycle = atoi(xml.GetAttrib("Detection_Cycle").c_str());
		AuditProxyServer = atoi(xml.GetAttrib("AuditProxyServer").c_str());
		RoutingProbe = atoi(xml.GetAttrib("RoutingProbe").c_str());
		Prompt = atoi(xml.GetAttrib("Prompt").c_str());
		SetAddress = xml.GetAttrib("SetAddress");
		proxyOnlyAllowsList = xml.GetAttrib("proxyOnlyAllowsList");
		OnlyAllowsList = xml.GetAttrib("OnlyAllowsList");
		NotAllowsList = xml.GetAttrib("NotAllowsList");
		DetectionList = xml.GetAttrib("DetectionList");
		PromptInfo = xml.GetAttrib("PromptInfo");
		PromptInfo1 = xml.GetAttrib("PromptInfo1 ");
	    }
	    xml.OutOfElem();
	}
	return import_xmlobj(xml);    
    }
    virtual void copy_to(CPolicy * dest) {
	if(dest->get_type() != NET_BD_CHK) {
	    return;
	}
	CNetBdChk *ctrl = (CNetBdChk *)dest;
	ctrl->proxycheck = proxycheck;
	ctrl->Can_Proxy = Can_Proxy;
	ctrl->Detection_Cycle = Detection_Cycle;
	ctrl->AuditProxyServer = AuditProxyServer;
	ctrl->RoutingProbe = RoutingProbe;
	ctrl->SetAddress = SetAddress;
	ctrl->proxyOnlyAllowsList = proxyOnlyAllowsList;
	ctrl->OnlyAllowsList = OnlyAllowsList;
	ctrl->NotAllowsList = NotAllowsList;
	ctrl->DetectionList = DetectionList;
	ctrl->Prompt = Prompt;
	ctrl->PromptInfo = PromptInfo;
	ctrl->PromptInfo1 = PromptInfo1;
	CPolicy::copy_to(dest);
    }
public:
    int proxycheck;
    int Can_Proxy;
    int Detection_Cycle;
    int AuditProxyServer;
    int RoutingProbe;
    int Prompt;
    string SetAddress;
    string proxyOnlyAllowsList;
    string OnlyAllowsList;
    string NotAllowsList;
    string DetectionList;
    string PromptInfo;
    string PromptInfo1;
};

#endif
