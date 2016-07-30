
#ifndef _PROTOCOL_FIRWALL_CTRL_
#define _PROTOCOL_FIRWALL_CTRL_


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>

#include "../../CVRVNetProtocol.h"
#include "../../vrvprotocol/VRVProtocol.hxx"
#include "../../vrvprotocol/VRVProtocolEx.hxx"
#include "../../common/Commonfunc.h"
#include "../../VCFCmdDefine.h"
#include "../../../include/MCInterface.h"
#include "../policysExport.h"

#include <string>
#include <vector>

using namespace std;

#define CHAIN_CUSTOM_OUTPUT "EDP-CHAIN-OUTPUT"
#define CHAIN_CUSTOM_INPUT "EDP-CHAIN-INPUT"
#define BUFFER_SIZE 1024
#define MARK_SIZE 32


extern bool protocol_firewall_ctrl_init();
extern bool protocol_firewall_ctrl_worker(CPolicy *, void *);
extern void protocol_firewall_ctrl_uninit();

struct control_data {
    string text;
    string kind;
    int drct;
    int mode;
};

class CProtocolFirewallCtrl : public CPolicy
{
public:
    CProtocolFirewallCtrl() {
	enPolicytype type = PROTOCOL_FIREWALL_CTRL;
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
	ctrl_data.clear();
	if(xml.FindElem("vrvscript")) {
	    xml.IntoElem();
	    while(xml.FindElem("item")) {
		struct control_data data;
		data.text = xml.GetAttrib("ControlText");
		data.kind = xml.GetAttrib("ControlKind");
		data.drct = atoi(xml.GetAttrib("Direction").c_str());
		data.mode = atoi(xml.GetAttrib("ControlMode").c_str());
		ctrl_data.push_back(data);
	    }
	    xml.OutOfElem();
	}
	return import_xmlobj(xml);    
    }
    virtual void copy_to(CPolicy * dest) {
	if(dest->get_type() != PROTOCOL_FIREWALL_CTRL) {
	    return;
	}
	CProtocolFirewallCtrl *ctrl = (CProtocolFirewallCtrl *)dest;
	ctrl->ctrl_data = ctrl_data;
	CPolicy::copy_to(dest);
    }
public:
    vector<struct control_data> ctrl_data;
};

#endif
