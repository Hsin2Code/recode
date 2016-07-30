#ifndef  IPMAC_BIND_CTRL_H_
#define  IPMAC_BIND_CTRL_H_

#include "../policysExport.h"

extern bool ipmac_bind_ctrl_init();
extern bool ipmac_bind_ctrl_worker(CPolicy * pPolicy, void * pParam);
extern void ipmac_bind_ctrl_uninit();

///10秒
#define  IPMAC_INTERVAL 10


#if defined(OEM_DP_DEEPIN) || defined(OEM_ZB_UKYLIN)
#include <iostream>
#include <vector>
#include <map>
using std::string;
using std::cout;
using std::endl;
using std::vector;
using std::map;
#endif

#if defined(OEM_DP_DEEPIN) || defined(OEM_ZB_UKYLIN)
typedef map<string, string> KEYPAIR;
typedef vector<KEYPAIR> INISUBITEMS;
typedef map<string, INISUBITEMS> INICONTENT;

class IniOpt {
    public:
        IniOpt(const string &filename);
        ~IniOpt();
        void getkeys(vector<string> &keys);
        const string getvalue(const string &sections, const string &key) const;
        int setvalue(const string &section, const string &key, const string &value);
        void writetofile();
        void dump();
    private:
        int _parse(std::stringstream &parsebuf);
    private:
        INICONTENT _content;
        int _can_moveon;
        string _filename;
};
#endif

class  CPolicyIPMacBindctrl : public CPolicy
{
public:
	CPolicyIPMacBindctrl()
	{
		enPolicytype  type = IPMAC_BIND_CTRL ;
		set_type(type);
	}

	virtual ~CPolicyIPMacBindctrl() {

	}

public:
	virtual  bool   import_xml(const char * pxml);
	virtual  void	copy_to(CPolicy * pDest);

	/*客户端IP获取方式*/
	property_def(IPGetDHCPMode, int);
	/*客户端IP,MAC绑定*/
	property_def(IPCombineMAC, int);

	property_def(IPMACDealMode , int);

	property_def(AutoResumeMaskAndGateway, int);

	property_def(IPMACInfo1, std::string);

	property_def(IPMACContinueAttack, int);

	property_def(PersistAttack, int);

	property_def(IPMACInfo2, std::string);

	property_def(IPMACInfo4, std::string);

	property_def(NotDealOnChangedInSubNetwork, int);

	/*绑定关系探测间隔*/
	property_def(IPMACCheckTime, int);

	property_def(IPMACBindValidIP, std::vector<std::string>);

	property_def(CombineGateWay, int);

	property_def(DisableSecondaryETH, int);

	property_def(LegalDnsIp, std::vector<std::string>);
private:
	void   transkey_to_utf8();
};

typedef struct ip_range_info
{
    char ip_begin[16];
    char ip_end[16];
}ip_range_info_s;


typedef struct network_info{
	char ip[16];
	char mac[16];
	char gateway[16];
	char sub_mask[16];
	char eth_name[16];
	//if need,added later
}network_info_s;

typedef struct ipmac_bind_info{
	int check_time;
	int check_interval;
	int get_ip_mode;
	char *log_buffer;
	network_info_s  *network_info;
	network_info_s  *change_network_info;
	CPolicyIPMacBindctrl *policy;
}ipmac_bind_info_s;

#endif
