#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/route.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <errno.h>

#include "ipmac_bind_ctrl.h"
#include "../../../include/MCInterface.h"
#include "../../vrvprotocol/VRVProtocol.hxx"
#include "../../common/MdyCfgFile.h"
#include "../../common/ping.h"


ipmac_bind_info_s g_ipmac_bind_info;
extern ILocalogInterface * g_GetlogInterface() ;

char g_network_script_name[1024]={0};//永久保存配置方案的文件名
///对提示信息进行转码
extern int code_convert(const char *from_charset,const char *to_charset,char *inbuf,int inlen,char *outbuf,int & outlen);


static int setnonblock(int sock) {
  int flags;
  flags = fcntl(sock, F_GETFL, 0);
  if (flags == -1) {
    return -1;
  }
  if (-1 == fcntl(sock, F_SETFL, flags | O_NONBLOCK)) {
    return -1;
  }
  return 0;
}

static std::string int2str(const int &i)
{
    std::string s;
    std::stringstream str(s);
    str << i;

    return str.str();
}

#if defined(OEM_DP_DEEPIN) || defined(OEM_ZB_UKYLIN)
static int alreadyget = 0;
static int first_get = 0;
static const char debian_config_dir[] = "/etc/NetworkManager/system-connections/";

void IniOpt::writetofile() {

    std::ofstream outfile(_filename.c_str());
    if(outfile.is_open()) {
        INICONTENT::iterator iter = _content.begin();
        for(; iter != _content.end(); iter++) {
            outfile << "[" << (*iter).first << "]" << endl;
            INISUBITEMS::iterator iteritem = (*iter).second.begin();
            for(; iteritem != (*iter).second.end(); iteritem++) {
                KEYPAIR::iterator iterkey = (*iteritem).begin();
                for(; iterkey != (*iteritem).end(); iterkey++) {
                    outfile << (*iterkey).first <<"="<< (*iterkey).second << endl;
                }
            }
            outfile << endl;
        }
    }
}

void IniOpt::getkeys(vector<string> &keys) {
    if(!_content.empty()) {
        INICONTENT::iterator iter = _content.begin();
        for(; iter != _content.end(); iter++) {
            keys.push_back((*iter).first);
        }
    }
}

const string IniOpt::getvalue(const string &sections, const string &key) const {
    if(key.empty()) {
        return "";
    }

    INICONTENT::const_iterator iter = _content.find(sections);
    if(iter != _content.end()) {
        INISUBITEMS::const_iterator itemiter = (*iter).second.begin();
        for(; itemiter != (*iter).second.end(); itemiter++) {
            KEYPAIR::const_iterator iterkey = (*itemiter).begin();
            for(; iterkey != (*itemiter).end(); iterkey++) {
                if((*iterkey).first == key) {
                    return (*iterkey).second;
                }
            }
        }
    }
    return "";
}

int IniOpt::setvalue(const string &section, const string &key, const string &value) {
    INICONTENT::iterator iter = _content.find(section);
    //only has section then can set value to it
    if(iter != _content.end()) {
        INISUBITEMS::iterator itemiter = (*iter).second.begin();
        for(; itemiter != (*iter).second.end(); itemiter++) {
            KEYPAIR::iterator iterkey = (*itemiter).begin();
            for(; iterkey != (*itemiter).end(); iterkey++) {
                if((*iterkey).first == key) {
                    (*iterkey).second.assign(value);
                }
            }
        }
    }

    return -1;
}

IniOpt::IniOpt(const string &filename) {
    _filename = filename;
    _can_moveon = -1;
    if(_filename.empty()) {
        _can_moveon = 0;
    }
    if(access(_filename.c_str(), F_OK) == 0) {
        std::ifstream infile(_filename.c_str());
        std::stringstream buf;
        if(infile.is_open()) {
            buf << infile.rdbuf();
            infile.close();
            _can_moveon = 1;
        }
        _parse(buf);
    }
}

// trim from start
static inline std::string &ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
    return s;
}

// trim from end
static inline std::string &rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
    return s;
}

// trim from both ends
static inline std::string &trim(std::string &s) {
    return ltrim(rtrim(s));
}

static inline bool startwith(std::string &s, std::string str) {
    return (s.find(str) == 0);
}

static inline bool endwith(std::string &s, std::string str) {
    return (s.rfind(str) == (s.length() - str.length()));
}

void splitstr(const std::string &s, std::vector<std::string> &v, const std::string &c) {
    std::string::size_type pos1, pos2;
    pos2 = s.find(c);
    pos1 = 0;
    while(std::string::npos != pos2)
    {
        v.push_back(s.substr(pos1, pos2-pos1));

        pos1 = pos2 + c.size();
        pos2 = s.find(c, pos1);
    }
    if(pos1 != s.length())
        v.push_back(s.substr(pos1));
}


int IniOpt::_parse(std::stringstream &parsebuf) {
    string line;
    string section;
    while(getline(parsebuf, line)) {
        line = trim(line);
        if(startwith(line, "[") && endwith(line, "]")) {
            line.erase(0, 1);
            line.erase(line.length() - 1, 1);
            section = line;
            _content[section].clear();
        } else {
            size_t secpos = line.find("=");
            if(secpos != 0 && secpos != line.length()) {
                vector<string> retvec;
                splitstr(line, retvec, "=");
                if(retvec.size() != 2) {
                    continue;
                }
                KEYPAIR keypair;
                keypair[retvec[0]] = retvec[1];
                _content[section].push_back(keypair);
            }
        }
    }
    return 0;
}


void IniOpt::dump() {
    INICONTENT::iterator iter = _content.begin();
    for(; iter != _content.end(); iter++) {
        cout << (*iter).first << endl;
        INISUBITEMS::iterator iteritem = (*iter).second.begin();
        for(; iteritem != (*iter).second.end(); iteritem++) {
            KEYPAIR::iterator iterkey = (*iteritem).begin();
            for(; iterkey != (*iteritem).end(); iterkey++) {
                cout << "key: " << (*iterkey).first << " " << "val: " << (*iterkey).second << endl;
            }
        }
    }
}

IniOpt::~IniOpt() {

}

int getdirfiles(const string &dirname, vector<string> &filelists) {
    if(dirname.length() <= 0 || dirname.empty()) {
        return -1;
    }
    struct stat st;
    memset(&st, 0, sizeof(struct stat));
    if(stat(dirname.c_str(), &st) == -1) {
        return -1;
    }
    if((st.st_mode & S_IFMT) == S_IFDIR) {
        DIR *dir = NULL;
        struct dirent *ens = NULL;
        if((dir = opendir(dirname.c_str())) == NULL) {
            cout << strerror(errno) << endl;
            return -1;
        }
        while((ens = readdir(dir)) != NULL) {
            if(strcmp(ens->d_name, ".") == 0 || strcmp(ens->d_name, "..") == 0 || 
                    ens->d_type == DT_DIR) {
                continue;
            }
            filelists.push_back(ens->d_name);
        }
        closedir(dir);
        return 0;
    }
    return -1;
}




int get_script_name_deepin(char dirname[], char ipaddr[], char name[]) {
    std::vector<std::string> filelist;
    getdirfiles(dirname, filelist);
    std::vector<std::string>::iterator iter = filelist.begin();
    for(; iter != filelist.end(); iter++) {
        /*find ip in that file*/
        std::string w_filename = dirname + (*iter);
        std::string file_content;
        std::ifstream file(w_filename.c_str());
        if(file.is_open() == 0) {
            return 0;
        }
        if(file) {
            std::stringstream buffer;
            buffer << file.rdbuf();
            file_content = buffer.str();
        }
        file.close();
        if(file_content.find(ipaddr) != std::string::npos) {
            strcpy(name, w_filename.c_str());
            return 1;
        }
    }
    return 0;
}

string gen_cfgstr(char *ipstr, int prefix, char *gateway) {
    if(ipstr != NULL && gateway != NULL) {
        string config_str;
        config_str.append(ipstr);
        config_str.append("/");
        config_str.append(int2str(prefix));
        config_str.append(",");
        config_str.append(gateway);
        return config_str;
    }
    return "";
}

#endif

void  CPolicyIPMacBindctrl:: transkey_to_utf8() {
    char buffer[512] = "";
    int  out_len = 512 ;

    if(m_IPMACInfo1.length()) {
        out_len = 512;
        char * p = const_cast<char *>(m_IPMACInfo1.c_str());
        if(code_convert("gb2312", "utf-8", p, m_IPMACInfo1.length(), buffer, out_len) == 0) {
            printf("printf: trans failed\n");
        }
        m_IPMACInfo1 = buffer ;
    }

    if(m_IPMACInfo2.length()) {
        out_len = 512;
        char * p = const_cast<char *>(m_IPMACInfo2.c_str());
        if(!code_convert("gb2312", "utf-8", p, m_IPMACInfo2.length(), buffer, out_len)) {
            printf("printf: trans failed\n");
        }
        m_IPMACInfo2 = buffer ;
    }

    if(m_IPMACInfo4.length()) {
        out_len = 512;
        char * p = const_cast<char *>(m_IPMACInfo4.c_str());
        if(!code_convert("gb2312", "utf-8", p, m_IPMACInfo4.length(), buffer, out_len)) {
            printf("printf: trans failed\n");
        }
        m_IPMACInfo4 = buffer ;
    }
}

bool CPolicyIPMacBindctrl::import_xml(const char *pxml)
{
    if(NULL == pxml)
    {
        return false;
    }

    CMarkup  xml ;
    if(!xml.SetDoc(pxml)) {
        return false ;
    }

    std::string IPMACBindValidIP;
    std::string LegalDnsIp;
    if(xml.FindElem("vrvscript")) {
        xml.IntoElem();
        while(xml.FindElem("item")) {
            m_IPGetDHCPMode = atoi(xml.GetAttrib("IPGetDHCPMode ").c_str());

            m_IPCombineMAC = atoi(xml.GetAttrib("IPCombineMAC ").c_str());

            m_IPMACDealMode = atoi(xml.GetAttrib("IPMACDealMode ").c_str());

            m_AutoResumeMaskAndGateway = atoi(xml.GetAttrib("AutoResumeMaskAndGateway ").c_str());

            m_IPMACInfo1 = xml.GetAttrib("IPMACInfo1 ").c_str();

            m_IPMACContinueAttack = atoi(xml.GetAttrib("IPMACContinueAttack ").c_str());

            m_PersistAttack = atoi(xml.GetAttrib("PersistAttack ").c_str());

            m_IPMACInfo2 = xml.GetAttrib("IPMACInfo2 ").c_str();

            m_IPMACInfo4 = xml.GetAttrib("IPMACInfo4 ").c_str();

            m_NotDealOnChangedInSubNetwork = atoi(xml.GetAttrib("NotDealOnChangedInSubNetwork ").c_str());

            m_IPMACCheckTime = atoi(xml.GetAttrib("IPMACCheckTime ").c_str());

            IPMACBindValidIP = xml.GetAttrib("IPMACBindValidIP ").c_str();

            m_CombineGateWay = atoi(xml.GetAttrib("CombineGateWay ").c_str());

            m_DisableSecondaryETH = atoi(xml.GetAttrib("DisableSecondaryETH ").c_str());

            LegalDnsIp = xml.GetAttrib("LegalDnsIp ").c_str();
        }
        xml.OutOfElem();
    }

    if(IPMACBindValidIP.size()!=0) {
        m_IPMACBindValidIP.clear();
        YCommonTool::split_new(IPMACBindValidIP,m_IPMACBindValidIP,";");
    }

    if(LegalDnsIp.size()) {
        m_LegalDnsIp.clear();
        YCommonTool::split_new(LegalDnsIp,m_LegalDnsIp,";");
    }

    transkey_to_utf8();

    return CPolicy::import_xmlobj(xml) ;
}

void CPolicyIPMacBindctrl::copy_to(CPolicy * pDest)
{
    CPolicyIPMacBindctrl * _pDest = (CPolicyIPMacBindctrl *)pDest ;

    _pDest->m_IPGetDHCPMode = m_IPGetDHCPMode ;
    _pDest->m_IPCombineMAC = m_IPCombineMAC;
    _pDest->m_IPMACDealMode = m_IPMACDealMode;
    _pDest->m_IPMACDealMode = m_IPMACDealMode;

    _pDest->m_AutoResumeMaskAndGateway = m_AutoResumeMaskAndGateway;
    _pDest->m_IPMACInfo1 = m_IPMACInfo1;

    _pDest->m_IPMACContinueAttack = m_IPMACContinueAttack;
    _pDest->m_PersistAttack = m_PersistAttack;
    _pDest->m_IPMACInfo2 = m_IPMACInfo2;
    _pDest->m_IPMACInfo4 = m_IPMACInfo4;
    _pDest->m_NotDealOnChangedInSubNetwork = m_NotDealOnChangedInSubNetwork;
    _pDest->m_IPMACCheckTime = m_IPMACCheckTime;
    _pDest->m_IPMACBindValidIP = m_IPMACBindValidIP;
    _pDest->m_CombineGateWay = m_CombineGateWay;
    _pDest->m_DisableSecondaryETH = m_DisableSecondaryETH;
    _pDest->m_LegalDnsIp = m_LegalDnsIp;

    CPolicy::copy_to(pDest);

    return;
}

/*读取网卡信息，并存储到数据库中*/
void get_network_card_info(network_info_s *network_info)
{
  
    std::string  eth_name ;
    char log[128]="";
    g_GetlcfgInterface()->get_lconfig(lcfg_regnic,eth_name);
    if(eth_name.length() == 0) {
        g_GetlogInterface()->log_trace("获取网卡失败\n");
        return ;
    }

    sprintf(network_info->eth_name, "%s", eth_name.c_str());

    sprintf(network_info->ip, "%s", YCommonTool::get_ip(eth_name).c_str());
    
    sprintf(log,"ip addr is %s\n", network_info->ip);
    g_GetlogInterface()->log_trace(log);

    sprintf(network_info->mac, "%s", YCommonTool::get_mac(eth_name).c_str());
    sprintf(log,"mac addr is %s\n", network_info->mac);
    g_GetlogInterface()->log_trace(log);

    sprintf(network_info->sub_mask, "%s", YCommonTool::get_subMask(eth_name).c_str());
    sprintf(log,"sub mask addr is %s\n", network_info->sub_mask);
    g_GetlogInterface()->log_trace(log);

    sprintf(network_info->gateway, "%s", YCommonTool::get_gatWay(eth_name).c_str());
    sprintf(log,"gateway is %s\n\n", network_info->gateway);
    g_GetlogInterface()->log_trace(log);
    
		printf("%s---%d\n", __func__, __LINE__);
}

int is_ip_mac_changed()
{
    int result;
    std::string network_ip;
    std::string network_name;
    network_info_s *network_info;

    network_info = g_ipmac_bind_info.network_info;

    network_name = network_info->eth_name;
    network_ip = YCommonTool::get_ip(network_name);
    if(!strcmp(network_info->ip, network_ip.c_str())) {
        /*未发生改变*/
        result = 0;
    } else {
        /*发生改变*/
        result = 1;
    }
    return result;
}

int find_start_end_ip(std::string buf, std::vector <ip_range_info_s> &ip_range, std::string network_ip)
{
    int result;
    char *index;
    char tmp_buffer[64];
    ip_range_info_s ip_ran;

    sprintf(tmp_buffer, "%s", buf.c_str());
    index = strstr(tmp_buffer, "-");
    if(index != NULL)
    {
        *index='\0';
        strncpy(ip_ran.ip_begin, tmp_buffer,16);
        strncpy(ip_ran.ip_end, index+1,16);
    }
    else
    {
        strncpy(ip_ran.ip_begin, tmp_buffer,16);
        strncpy(ip_ran.ip_end, tmp_buffer,16);
    }

    ip_range.push_back(ip_ran);

    if((ntohl(inet_addr(ip_ran.ip_begin)) <= ntohl(inet_addr(network_ip.c_str())))
            && (ntohl(inet_addr(ip_ran.ip_end)) >= ntohl(inet_addr(network_ip.c_str()))))
    {
        result = 1;
    }
    else
    {
        result = 0;
    }

    return result;
}

int is_ip_mac_effectivd()
{
    int result = 0;
    int ret;
    std::string network_name;
    std::string network_ip;
    network_info_s *network_info;
    std::vector <ip_range_info_s> ip_range;
    CPolicyIPMacBindctrl *policy;


    policy = g_ipmac_bind_info.policy;

    network_info = g_ipmac_bind_info.network_info;

    network_name = network_info->eth_name;
    network_ip = YCommonTool::get_ip(network_name);

    std::vector<std::string> niclst = policy->get_IPMACBindValidIP();
    std::vector<std::string>::iterator  iter = niclst.begin();

    if(niclst.size())
    {
        while(iter != niclst.end())
        {
            printf("ip addr is %s\n", iter->c_str());

            ret = find_start_end_ip(iter->c_str(), ip_range, network_ip);
            if(1 == ret)
            {
                result = 1;
                break;
            }

            iter++;
        }
    }
    else
    {
        result = 1;
    }


    return result;
}

void set_host_gateWay_addr(char *gateway)
{
    int fd;
    char *eth_name;
    struct ifreq ifr;
    struct sockaddr_in *sin;
    struct rtentry  rt;

    eth_name = g_ipmac_bind_info.network_info->eth_name;

    memset(&ifr,0,sizeof(ifr));
    memset(&rt, 0, sizeof(struct rtentry));

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    setnonblock(fd);
    if(fd < 0)
    {
        return ;
    }

    strcpy(ifr.ifr_name, eth_name);

    sin = (struct sockaddr_in*)(&ifr.ifr_addr);
    sin->sin_family = AF_INET;
    sin->sin_port = 0;

    cout << __LINE__ << " " << __func__ << "gateway " << gateway << endl;
    if(inet_aton(gateway, &sin->sin_addr)<0)
    {
        printf ( "inet_aton error\n" );
    }
    memcpy ( &rt.rt_gateway, sin, sizeof(struct sockaddr_in));
    ((struct sockaddr_in *)&rt.rt_dst)->sin_family = AF_INET;
    ((struct sockaddr_in *)&rt.rt_genmask)->sin_family = AF_INET;
    rt.rt_flags = RTF_GATEWAY;
    if (ioctl(fd, SIOCADDRT, &rt)<0)
    {
        printf("set gateWay ioctl error\n");
        close(fd);
        return ;
    }
    close(fd);

    return;
}

int del_host_gateWay_addr(char *eth,char *gateway)
{
    int fd;
    struct ifreq ifr;
    struct sockaddr_in *sin;
    struct rtentry  rt;

    memset(&ifr,0,sizeof(ifr));
    memset(&rt, 0, sizeof(struct rtentry));

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    setnonblock(fd);
    if(fd < 0)
    {
        return -1;
    }

    strcpy(ifr.ifr_name,eth);
    sin = (struct sockaddr_in*)&ifr.ifr_addr;

    sin->sin_family = AF_INET;
    sin->sin_port = 0;
    if(inet_aton(gateway, &sin->sin_addr)<0)
    {
        printf ( "inet_aton error\n" );
    }
    memcpy ( &rt.rt_gateway, sin, sizeof(struct sockaddr_in));
    ((struct sockaddr_in *)&rt.rt_dst)->sin_family=AF_INET;
    ((struct sockaddr_in *)&rt.rt_genmask)->sin_family=AF_INET;
    rt.rt_flags = RTF_GATEWAY;

    if (ioctl(fd, SIOCDELRT, &rt)<0)
    {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static void set_host_submask(char *sub_mask)
{
    int sockfd;

    char *eth_name;

    struct ifreq ifreq;
    struct sockaddr_in sin;

    eth_name = g_ipmac_bind_info.network_info->eth_name;

    memset(&ifreq,0,sizeof(ifreq));
    memset(&sin,0,sizeof(sin));

    if(0 > (sockfd = socket(AF_INET, SOCK_STREAM, 0)))
    {
        printf("socket error!!\n");
    }
    setnonblock(sockfd);
    strncpy(ifreq.ifr_name,eth_name,sizeof(ifreq.ifr_name));

    sin.sin_family = AF_INET;
    inet_aton(sub_mask,&sin.sin_addr);
    memcpy((char*)&ifreq.ifr_addr, (char*)&sin, sizeof(struct sockaddr_in));
    if(0 > ioctl(sockfd,SIOCSIFNETMASK,&ifreq))
    {
        close(sockfd);
    }
    ifreq.ifr_flags |= IFF_UP|IFF_RUNNING;
    if(0 > ioctl(sockfd,SIOCSIFFLAGS,&ifreq))
    {
        close(sockfd);
    }
    close(sockfd);

    return;
}

bool get_eth_status(char *eth_name) {
    if(eth_name == NULL || eth_name[0] == '\0') {
        return false;
    }
    struct ifreq ifs;
    memset(&ifs, 0, sizeof(ifs));
    strncpy(ifs.ifr_name, eth_name, sizeof(ifs.ifr_name));
    int socketfd = socket(AF_INET, SOCK_STREAM, 0);
    setnonblock(socketfd);
    if(socketfd < 0) {
        return false;
    }
    printf("get eth status %s\n", eth_name);
    int flags = 0;
    int ret = ioctl(socketfd, SIOCGIFFLAGS, &ifs);
    close(socketfd);
    if(ret < 0) {
        return false;
    } 
    return (ifs.ifr_flags & IFF_UP) && (ifs.ifr_flags & IFF_RUNNING);
}




static void set_network_ip(char *host_ip)
{
    int sockfd;
    char* eth_name;
    struct ifreq ifreq;
    struct sockaddr_in sin;

    eth_name = g_ipmac_bind_info.network_info->eth_name;

    memset(&ifreq,0,sizeof(ifreq));
    memset(&sin,0,sizeof(sin));
    if(0 > (sockfd = socket(AF_INET,SOCK_STREAM,0)))
    {
        printf("creak socket error\n");
    }
    setnonblock(sockfd);
    strncpy(ifreq.ifr_name, eth_name, sizeof(ifreq.ifr_name));

    sin.sin_family = AF_INET;
    inet_aton(host_ip, &sin. sin_addr);
    memcpy((char*)&ifreq.ifr_addr, (char*)&sin, sizeof(struct sockaddr_in));

    if(0 > ioctl(sockfd,SIOCSIFADDR,&ifreq))
    {
        close(sockfd);
        return;
    }
    ifreq.ifr_flags |= IFF_UP|IFF_RUNNING;
    if(0 > ioctl(sockfd,SIOCSIFFLAGS,&ifreq))
    {
        close(sockfd);
        return;
    }
    close(sockfd);

    return;
}

void ipmac_bind_soft_dialog(std::string content)
{
    char buffer[512] = "";
    tag_GuiTips * pTips = (tag_GuiTips *)buffer ;
    pTips->sign = en_TipsGUI_btnOK|en_TipsGUI_timeOut ;
    pTips->defaultret = en_TipsGUI_None;
    strncpy(pTips->szTitle,"信息提示",sizeof(pTips->szTitle));
    strncpy(pTips->szTips,content.c_str(),sizeof(pTips->szTips));
    pTips->pfunc = NULL;
    pTips->param.timeout = 5*1000;
    g_GetSendInterface()->sendto_Main(VCF_CMD_GUI_TIPS,buffer,sizeof(tag_GuiTips));
}

int modify_config_file(const char key[],const char value[],IfconfigFile &script)
{
    string item = script.ReadString(key);
#if 1
	cout << "key is :" << key << endl;
	cout << "item is: " << item << endl;
	cout << "OUT : value is: " << value << endl;
#endif
    if(0 != strcmp(item.c_str(),value))
    {
        script.WriteString(key,value);
    }
    return 0;
}

int modify_network_cfg_file(const char *ip, const char *netmask, int prefix, 
                            const char *gateway, const char *dev,  const char *name, 
                           IfconfigFile &script) {
    
    if(!(ip != NULL && netmask != NULL && gateway != NULL && dev != NULL && name != NULL)) {
        return -1;
    }
    script.AddKVPair("DEVICE", dev);
    script.AddKVPair("NAME", name);
    modify_config_file("IPADDR", ip, script);
    modify_config_file("NETMASK",netmask,script);
    modify_config_file("PREFIX",int2str(prefix).c_str(), script);
    modify_config_file("GATEWAY",gateway, script);
    return 0;
}

int get_mask_prefix(char netmask[])
{
    int i = 0;
    struct in_addr mask;
    mask.s_addr = inet_addr(netmask);
    while(0 != mask.s_addr)
    {
        if(1 == mask.s_addr%2)
        {
            i++;
        }
        mask.s_addr = mask.s_addr/2;
    }
    return i;
}


int interface_up(char *interface_name)
{
    int s;

    if(0 == strcmp(interface_name, "lo") )
    {
        return 0;
    }

    if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Socket");
        return -1;
    }
    setnonblock(s);

    struct ifreq ifr;
    strcpy(ifr.ifr_name, interface_name);

    short flag;
    flag = IFF_UP;
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
    {
        perror("ioctl");
        return -1;
    }

    ifr.ifr_ifru.ifru_flags |= flag;

    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0)
    {
        perror("ioctl");
        return -1;
    }

    close(s);

    return 0;

}

int interface_down(char *interface_name)
{
    if (strcmp(interface_name, "lo") == 0)
    {
        return 0;
    }

    int s;

    if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Socket");
        return -1;
    }
    
    setnonblock(s);

    struct ifreq ifr;
    strcpy(ifr.ifr_name, interface_name);

    short flag;
    flag = ~IFF_UP;
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
    {
        perror("ioctl");
        return -1;
    }

    ifr.ifr_ifru.ifru_flags &= flag;

    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0)
    {
        perror("ioctl");
        return -1;
    }

    close(s);

    return 0;
}



void exec_policy_recover_action()
{
    char *sub_mask;
    char *host_ip;
    char *gateway;
    int prefix;
    char *dev;
    char *dev_name;

#if defined(OEM_DP_DEEPIN) || defined(OEM_ZB_UKYLIN)
    IniOpt network_script_deepin(g_network_script_name);
    cout << __LINE__ << __func__ << " "<< g_network_script_name << endl;
#else
    IfconfigFile network_script(g_network_script_name);
#endif
    host_ip = g_ipmac_bind_info.network_info->ip;
    dev = g_ipmac_bind_info.network_info->eth_name;
    /*use dev as dev name */
    dev_name = g_ipmac_bind_info.network_info->eth_name;
    set_network_ip(host_ip);

#if 0
    g_GetlogInterface()->log_trace("name>>>>>??");
    g_GetlogInterface()->log_trace(g_network_script_name);
#endif

    if(1 == g_ipmac_bind_info.policy->get_AutoResumeMaskAndGateway())
    {
        sub_mask = g_ipmac_bind_info.network_info->sub_mask;
        set_host_submask(sub_mask);

        prefix = get_mask_prefix(sub_mask);
        cout<<"PREFIX= "<<prefix<<endl;

        gateway = g_ipmac_bind_info.network_info->gateway;
        cout << __LINE__ << endl;
        set_host_gateWay_addr(gateway);

#if defined(OEM_DP_DEEPIN) || defined(OEM_ZB_UKYLIN)
        string config_str = gen_cfgstr(host_ip, prefix, gateway);
        network_script_deepin.setvalue("ipv4", "address1", config_str);
        network_script_deepin.writetofile();
        cout << __LINE__ << __func__ << config_str << endl;
#else
        modify_network_cfg_file(host_ip, sub_mask, prefix, gateway, dev, dev_name, network_script);
#endif

    } else {
        sub_mask = g_ipmac_bind_info.change_network_info->sub_mask;
        set_host_submask(sub_mask);
        prefix = get_mask_prefix(sub_mask);
        cout<<"PREFIX= "<<prefix<<endl;
        gateway = g_ipmac_bind_info.change_network_info->gateway;
        set_host_gateWay_addr(gateway);
#if defined(OEM_DP_DEEPIN) || defined(OEM_ZB_UKYLIN)
        string currip = network_script_deepin.getvalue("ipv4", "address1");
        std::vector<string> splitstring;
        splitstr(currip,splitstring, "/");
        if(splitstring.size() > 0) {
            currip = splitstring.at(0);
        }
        string config_str = gen_cfgstr((char *)currip.c_str(), prefix, gateway);
        network_script_deepin.setvalue("ipv4", "address1", config_str);
        network_script_deepin.writetofile();
        cout << __LINE__ << __func__ << config_str << endl;
#else
        modify_network_cfg_file(host_ip, sub_mask, prefix, gateway, dev, dev_name, network_script);
#endif
    }
#if !(defined(OEM_DP_DEEPIN) || defined(OEM_ZB_UKYLIN))
    network_script.Update();
    //system("service network restart &>/dev/null");
#endif
    ipmac_bind_soft_dialog(g_ipmac_bind_info.policy->get_IPMACInfo1());

    return;
}


void exec_policy_closenet_action()
{
    tag_closeNet  tmp ;
    int cmd;

    tmp.policy = IPMAC_BIND_CTRL;
    if(g_ipmac_bind_info.policy->get_IPMACContinueAttack())
    {
        cmd = VCF_CMD_CALL_CLOSENET;
        tmp.bAlaways = false ; //非永久断网
    }
    else if(g_ipmac_bind_info.policy->get_PersistAttack())
    {
        cmd = VCF_CMD_CALL_CLOSENET;
        tmp.bAlaways = true ; //永久断网
    }
    else
    {
        cmd = VCF_CMD_CALL_CLOSENET;
        tmp.bAlaways = false ; //非永久断网
    }

    g_GetSendInterface()->sendto_Main(cmd, &tmp,sizeof(tag_closeNet));

    ipmac_bind_soft_dialog(g_ipmac_bind_info.policy->get_IPMACInfo2());

    return;
}

void exec_policy_action()
{
    int mode;

    mode = g_ipmac_bind_info.policy->get_IPMACDealMode();

    switch(mode)
    {
        case 0:/*不处理*/
            printf("Nothing to do\n");
            break;
        case 1:/*自动恢复*/ 
            printf("exec_policy_recover_action\n");
            exec_policy_recover_action();
            break;
        case 2:/*断开网络*/
            printf("exec_policy_closenet_action\n");
            exec_policy_closenet_action();
            break;
        case 4:/*仅提示*/
            ipmac_bind_soft_dialog(g_ipmac_bind_info.policy->get_IPMACInfo4());
            break;
        default:
            break;
    }

    return;
}

int is_ip_mac_in_same_subnet()
{
    int ret = 0;

    std::string network_name;
    std::string network_ip;
    network_info_s *network_info;
    CPolicyIPMacBindctrl *policy;

    policy = g_ipmac_bind_info.policy;

    network_info = g_ipmac_bind_info.network_info;

    network_name = network_info->eth_name;
    network_ip = YCommonTool::get_ip(network_name);

    if((NULL == network_info->ip) || (NULL == network_ip.c_str()) || (NULL == network_info->sub_mask))
    {
        return ret;
    }

    if(((ntohl(inet_addr(network_info->ip))) & (ntohl(inet_addr(network_info->sub_mask))))
            == ((ntohl(inet_addr(network_ip.c_str()))) & (ntohl(inet_addr(network_info->sub_mask)))))
    {
        //in range
        ret = 1;
    }
    else
    {
        //out of range
        ret = 0;
    }
    return ret;
}



bool    report_Auditlog(char *log_buffer, const char *warn_info)
{
    tag_Policylog * plog = (tag_Policylog *)log_buffer ;
    plog->what = 0;
    plog->type = 80;
    char * pTmp = plog->log;

    sprintf(pTmp,"%sActiveIPAddress=%s%sInfo=%s%sRouteIPAddress=%s%s", STRITEM_TAG_END,
            g_ipmac_bind_info.network_info->ip,STRITEM_TAG_END
            ,warn_info, STRITEM_TAG_END,g_ipmac_bind_info.network_info->gateway,STRITEM_TAG_END);

    report_policy_log_spec(plog);

    return true ;
}

std::string history_info = "";

void ipmac_bind_send_log()
{
    int mode;
    std::string warn_info = "";

    network_info_s *network_info;
    network_info_s *change_network_info;

    mode = g_ipmac_bind_info.policy->get_IPMACDealMode();
    network_info = g_ipmac_bind_info.network_info;
    change_network_info = g_ipmac_bind_info.change_network_info;

    switch(mode)
    {
        case 0:
            warn_info=warn_info+"IP地址由 "+ network_info->ip  +" 改变为 "+ change_network_info->ip+",不处理";
            break;
        case 1:
            warn_info=warn_info+"IP地址由 "+ network_info->ip +" 改变为 "+ change_network_info->ip +" ";
            if(1 == g_ipmac_bind_info.policy->get_AutoResumeMaskAndGateway())
            {
                if(inet_network(change_network_info->sub_mask) != inet_network(network_info->sub_mask))
                {
                    warn_info = warn_info+"子网掩码由 "+ network_info->sub_mask +" 改变为 "+ change_network_info->sub_mask +" ";
                }
                if(inet_network(change_network_info->gateway) != inet_network(network_info->gateway))
                {
                    warn_info =warn_info+ "网关由 "+ network_info->gateway  +" 改变为 "+ change_network_info->gateway +" ";
                }
            }
            warn_info = warn_info + ",还原成功";

            break;
        case 2:
            warn_info=warn_info+"IP地址由 "+ network_info->ip +" 改变为 "+ change_network_info->ip +",进行阻断";
            break;
        case 4:
            warn_info=warn_info+"IP地址由 "+ network_info->ip +" 改变为 "+ change_network_info->ip +",仅提示";
            break;
        default:
            break;
    }

    if(1 != mode)
    {
        if(history_info != warn_info)
        {
            report_Auditlog(g_ipmac_bind_info.log_buffer, warn_info.c_str());
            history_info = warn_info;
        }
    }
    else
    {
        report_Auditlog(g_ipmac_bind_info.log_buffer, warn_info.c_str());
    }

    return;
}

int get_script_name(char cmd[],char name[])
{
    char buf[1024];

    FILE *fp = popen(cmd,"r");
    if(fp == NULL)
    {
        return -1;
    }
    fgets(buf,sizeof(buf)-1,fp);
    sscanf(buf,"%[^\n]",name);
    cout << __LINE__ << " " << __func__ << name << endl;
    cout << __LINE__ << " " << __func__ << "buf " << buf << endl;
    pclose(fp);
    return 0;
}


static int getdir (string dir, vector<string> &files) {
    DIR *dp;
    struct dirent *dirp;
    if((dp  = opendir(dir.c_str())) == NULL) {
        return -1;
    }

    while ((dirp = readdir(dp)) != NULL) {
        files.push_back(string(dirp->d_name));
    }
    closedir(dp);
    return 0;
}


bool ipmac_bind_ctrl_init()
{
    memset(&g_ipmac_bind_info, 0, sizeof(g_ipmac_bind_info));

    if(NULL == g_ipmac_bind_info.network_info)
    {
        g_ipmac_bind_info.network_info = (network_info_s *)malloc(sizeof(network_info_s));
        if(g_ipmac_bind_info.network_info==NULL) {
            return false ;
        }
    }

    if(NULL == g_ipmac_bind_info.change_network_info)
    {
        g_ipmac_bind_info.change_network_info = (network_info_s *)malloc(sizeof(network_info_s));
        if(g_ipmac_bind_info.change_network_info == NULL){
            return false ;
        }
    }

    if(NULL == g_ipmac_bind_info.log_buffer)
    {
        g_ipmac_bind_info.log_buffer = (char *)malloc(4096);
        if(g_ipmac_bind_info.log_buffer == NULL) {
            return false ;
        }
    }

    return true;
}




void exec_combine_gateway()
{
    char *eth_name;
    char *gateway;
    char *change_gateway;

    change_gateway = g_ipmac_bind_info.change_network_info->gateway;
    gateway = g_ipmac_bind_info.network_info->gateway;
    eth_name = g_ipmac_bind_info.network_info->eth_name;

#if defined(OEM_DP_DEEPIN) || defined(OEM_ZB_UKYLIN)
    IniOpt network_script_deepin(g_network_script_name);
#else
    IfconfigFile network_script(g_network_script_name);
#endif

    if(0 != strcmp(change_gateway, ""))
    {
        if(0 != strcmp(change_gateway, gateway))
        {
            del_host_gateWay_addr(eth_name,change_gateway);
            set_host_gateWay_addr(gateway);
            cout << "exec gate 1" << __LINE__ << __func__ << gateway << endl;
#if defined(OEM_DP_DEEPIN) || defined(OEM_ZB_UKYLIN)
            char *sub_mask = g_ipmac_bind_info.network_info->sub_mask;
            int prefix = get_mask_prefix(sub_mask);
            string config_str = gen_cfgstr(g_ipmac_bind_info.network_info->ip, prefix, gateway);
            network_script_deepin.setvalue("ipv4", "address1", config_str);
            network_script_deepin.writetofile();
            cout << __func__ << __LINE__ << "config_str :" << config_str << endl;
#else
            char *sub_mask = g_ipmac_bind_info.network_info->sub_mask;
            int prefix = get_mask_prefix(sub_mask);
            char *host_ip = g_ipmac_bind_info.network_info->ip;

	    modify_network_cfg_file(host_ip, sub_mask, prefix, gateway, eth_name, eth_name, network_script);
	    cout << "up date " << __LINE__ << __func__ << endl;
	    network_script.Update();
	    //system("service network restart &>/dev/null");
#endif
        }
    } else {
        set_host_gateWay_addr(gateway);
        cout << "exec gate 2" << __LINE__ << __func__ << gateway << endl;
#if defined(OEM_DP_DEEPIN) || defined(OEM_ZB_UKYLIN)
        char *sub_mask = g_ipmac_bind_info.network_info->sub_mask;
        int prefix = get_mask_prefix(sub_mask);
        string config_str = gen_cfgstr(g_ipmac_bind_info.network_info->ip, prefix, gateway);
        network_script_deepin.setvalue("ipv4", "address1", config_str);
        network_script_deepin.writetofile();
        cout << __func__ << __LINE__ << "config_str :" << config_str << endl;
#else
	char *sub_mask = g_ipmac_bind_info.network_info->sub_mask;
	int prefix = get_mask_prefix(sub_mask);
	char *host_ip = g_ipmac_bind_info.network_info->ip;
	modify_network_cfg_file(host_ip, sub_mask, prefix, gateway, eth_name, eth_name, network_script);

	cout << "up date " << __LINE__ << __func__ << endl;
	network_script.Update();
	//system("service network restart &>/dev/null");
#endif
    }
    return;
}




int info_list()
{
    int len;
    char *ifreq_pointer;
    len = 10 * sizeof(struct ifreq);
    ifreq_pointer = (char *) malloc(len);
    if(ifreq_pointer == NULL) {
        return 0;
    }

    struct ifconf get_info;
    get_info.ifc_len = len;
    get_info.ifc_ifcu.ifcu_buf = ifreq_pointer;

    int sockfd;
    sockfd = socket(PF_INET, SOCK_STREAM, 0);
    setnonblock(sockfd);
    ioctl(sockfd, SIOCGIFCONF, &get_info);

    int count;
    count = get_info.ifc_len / sizeof(struct ifreq);

    struct ifreq *result = (struct ifreq *) ifreq_pointer;

    int i;
    unsigned  int mask = 0;
    unsigned  int ip = 0;

    std::string g_server_ip;
    std::string regnic;
    g_GetlcfgInterface()->get_lconfig(lcfg_srvip, g_server_ip);
    g_GetlcfgInterface()->get_lconfig(lcfg_regnic, regnic);
    unsigned  int serverIp = ntohl(inet_addr(g_server_ip.c_str()));

    std::string network_ip;
    std::string network_submask;
    std::string eth_name;
    for (i = 0; i < count; i++,result++)
    {
        eth_name = result->ifr_name;
        network_ip = YCommonTool::get_ip(eth_name);
        ip = ntohl(inet_addr(network_ip.c_str()));

        network_submask = YCommonTool::get_subMask(eth_name);
        mask = ntohl(inet_addr(network_submask.c_str()));

        if((ip & mask) != (serverIp & mask)) {
            if(regnic != result->ifr_name)
                interface_down(result->ifr_name);
        }
        else
        {
            interface_up(result->ifr_name);
        }

    }
    free(ifreq_pointer);

    close(sockfd);

    return 1;
}

std::string dns_history_info = "";
void dns_white_list_process()
{
#if defined(OEM_DP_DEEPIN) || defined(OEM_ZB_UKYLIN)

    IniOpt network_script_deepin(g_network_script_name);
    string dnsinfo = network_script_deepin.getvalue("ipv4", "dns");
    string realdns = dnsinfo.substr(0, dnsinfo.length() - 1);
    std::vector<std::string> niclst = g_ipmac_bind_info.policy->get_LegalDnsIp();
    vector<string>::iterator iter = niclst.begin();
    int findflag = 0;
    for(; iter != niclst.end(); iter++) {
        cout << (*iter) << endl;
        if((*iter) == realdns) {
            findflag = 1;
        }
    }

    if(findflag == 0) {
        string warn_info;
        warn_info += "DNS地址 ";
        warn_info += realdns + "未在白名单中";
        report_Auditlog(g_ipmac_bind_info.log_buffer, warn_info.c_str());
    }
    return;
#else
    int dns_find_flag;
    int send_log_flag = 0;
    char filename[] = "/etc/resolv.conf"; //文件名
    FILE *fp;
    char *server_name;
    char *end_server_name;
    char tmp_dns[32];
    char str_line[1024];             //每行最大读取的字符数
    string warn_info;

    string tmp_dns_name;
    string end_dns_name;


    std::vector<std::string> niclst = g_ipmac_bind_info.policy->get_LegalDnsIp();

    if(0 == niclst.size())
    {
        return;
    }

    if((fp = fopen(filename,"r")) == NULL) //判断文件是否存在及可读
    {
        return ;
    }

    dns_history_info = "";

    warn_info = "DNS地址 ";

    while (!feof(fp))
    {
        fgets(str_line,1024,fp);  //读取一行

        server_name = strstr(str_line, "nameserver");
        end_server_name = strstr(str_line, "\n");
        if(server_name == NULL) {
            continue;
        } else {
            memset(tmp_dns, 0, sizeof(tmp_dns));
            sprintf(tmp_dns, "%s", server_name + 11);
            tmp_dns[end_server_name - (server_name + 11)] = '\0';
        }
        std::vector<std::string>::iterator  iter = niclst.begin();
        dns_find_flag = 0;
        while(iter != niclst.end()) {
            if(!strcmp(iter->c_str(), tmp_dns)) {
                dns_find_flag = 1;
                break;
            }
            iter++;
        }

        if(!dns_find_flag) {
            tmp_dns_name = tmp_dns;
            if(tmp_dns_name != end_dns_name) {
                send_log_flag = 1;
                warn_info += tmp_dns_name;
                warn_info += " ";
                end_dns_name = tmp_dns_name;
            }
        }
    }

    warn_info += "未在白名单中";

    if(warn_info != dns_history_info)
    {
        dns_history_info = warn_info;
    }

    if(send_log_flag)
    {
        report_Auditlog(g_ipmac_bind_info.log_buffer, warn_info.c_str());
    }

    fclose(fp);
#endif
}

static void _sync_ipmac_cfg(size_t crc_val) {
    std::map<int, std::string> _dbcfg;
    bool get_ret = g_GetlcfgInterface()->get_lconfig(lcfg_bind_pcrc, _dbcfg[lcfg_bind_pcrc]);
    if(!get_ret || _dbcfg[lcfg_bind_pcrc] != int2str(crc_val)) {
        std::cout << "=---------------------- cvt crc " << int2str(crc_val) << std::endl;
        get_network_card_info(g_ipmac_bind_info.network_info);
        g_GetlcfgInterface()->set_lconfig(lcfg_bind_pcrc, int2str(crc_val));

        get_network_card_info(g_ipmac_bind_info.network_info);
        _dbcfg[lcfg_bind_ip].append(g_ipmac_bind_info.network_info->ip);
        _dbcfg[lcfg_bind_mac].append(g_ipmac_bind_info.network_info->mac);
        _dbcfg[lcfg_bind_gw].append(g_ipmac_bind_info.network_info->gateway);
        _dbcfg[lcfg_bind_mask].append(g_ipmac_bind_info.network_info->sub_mask);

        g_GetlcfgInterface()->set_lconfig(lcfg_bind_ip, _dbcfg[lcfg_bind_ip]);
        g_GetlcfgInterface()->set_lconfig(lcfg_bind_mac, _dbcfg[lcfg_bind_mac]);
        g_GetlcfgInterface()->set_lconfig(lcfg_bind_mask, _dbcfg[lcfg_bind_mask]);
        g_GetlcfgInterface()->set_lconfig(lcfg_bind_gw, _dbcfg[lcfg_bind_gw]);

        std::cout << "--------------------get config from native" << std::endl;
    } else {
        std::string nic_name;
        if(g_GetlcfgInterface()->get_lconfig(lcfg_bind_ip, _dbcfg[lcfg_bind_ip]) &&
                g_GetlcfgInterface()->get_lconfig(lcfg_bind_mac, _dbcfg[lcfg_bind_mac]) &&
                g_GetlcfgInterface()->get_lconfig(lcfg_bind_gw, _dbcfg[lcfg_bind_gw]) &&
                g_GetlcfgInterface()->get_lconfig(lcfg_bind_mask, _dbcfg[lcfg_bind_mask]) && 
                g_GetlcfgInterface()->get_lconfig(lcfg_regnic, nic_name)) {

            sprintf(g_ipmac_bind_info.network_info->ip, "%s", _dbcfg[lcfg_bind_ip].c_str());
            sprintf(g_ipmac_bind_info.network_info->mac, "%s", _dbcfg[lcfg_bind_mac].c_str());
            sprintf(g_ipmac_bind_info.network_info->gateway, "%s", _dbcfg[lcfg_bind_gw].c_str());
            sprintf(g_ipmac_bind_info.network_info->sub_mask, "%s", _dbcfg[lcfg_bind_mask].c_str());
            sprintf(g_ipmac_bind_info.network_info->eth_name, "%s", nic_name.c_str());
            g_GetlogInterface()->log_trace("get config from db");
            std::cout << "---------------------get config from db" << std::endl;
        }
    }
}

CPolicyIPMacBindctrl * g_CPolicyIPMacBindctrl;

bool ipmac_bind_ctrl_worker(CPolicy * pPolicy, void * pParam) {

    printf("%s---%d\n", __func__, __LINE__);
    g_GetlogInterface()->log_trace("ipmac_bind_ctrl_worker start");
    int ip_change_flag;
    int ip_effective_flag;
    int ip_in_subnet_flag;
    int is_subnet_change = 0;
    char log[128] = "";

    if(pPolicy->get_type() != IPMAC_BIND_CTRL) {
        return false ;
    }

    g_ipmac_bind_info.policy = (CPolicyIPMacBindctrl *)pPolicy;
    sprintf(log,"CheckTime is %d",g_ipmac_bind_info.policy->get_IPMACCheckTime());
    g_GetlogInterface()->log_trace(log);

    /*自动获取IP不处理、未开启IP/MAC绑定不处理*/
    if(2 == g_ipmac_bind_info.policy->get_IPGetDHCPMode() || 0 == g_ipmac_bind_info.policy->get_IPCombineMAC())
    {
        g_ipmac_bind_info.get_ip_mode = g_ipmac_bind_info.policy->get_IPGetDHCPMode();
        return false;
    }
    else
    {
        /*保持原有模式无变化*/
        if((0 == g_ipmac_bind_info.policy->get_IPGetDHCPMode()) && (2 == g_ipmac_bind_info.get_ip_mode))
        {
            return false;
        }

        g_ipmac_bind_info.get_ip_mode = g_ipmac_bind_info.policy->get_IPGetDHCPMode();
    }

    /*策略初始化*/
    if(NULL == g_CPolicyIPMacBindctrl) {
        g_CPolicyIPMacBindctrl = (CPolicyIPMacBindctrl *) create_policy(IPMAC_BIND_CTRL);
        if(NULL == g_CPolicyIPMacBindctrl) {
            return false ;
        }
        pPolicy->copy_to(g_CPolicyIPMacBindctrl);

        /*首次获取IP 、MAC对应关系*/
        size_t crc_val = pPolicy->get_crc();
        _sync_ipmac_cfg(crc_val);

        /*获取网卡配置文件*/
        char cmd[512]={0};
#if defined(OEM_DP_DEEPIN) || defined(OEM_ZB_UKYLIN)
        if(alreadyget == 0) {
            alreadyget = get_script_name_deepin((char *)debian_config_dir, 
                    g_ipmac_bind_info.network_info->ip, 
                    g_network_script_name);
            first_get = 1;
        }

#else
        sprintf(cmd,"find /etc/sysconfig/network-scripts/ -type f -name 'ifcfg-%s'",
                g_ipmac_bind_info.network_info->eth_name);
	cout << "cmd is :" << cmd << endl;
        //get_script_name(cmd, g_network_script_name);
	/*force create eth0 cfg file*/
	sprintf(g_network_script_name, "/etc/sysconfig/network-scripts/ifcfg-%s", g_ipmac_bind_info.network_info->eth_name);
	cout << "network config file bind name: " << g_ipmac_bind_info.network_info->eth_name << endl;
	cout << "network_scrpit name " << g_network_script_name << endl;
#endif


    }

    /*判断策略中，探测间隔是否发生改变*/
    if(g_ipmac_bind_info.policy->get_IPMACCheckTime() != g_ipmac_bind_info.check_time)
    {
        g_ipmac_bind_info.check_time = g_ipmac_bind_info.policy->get_IPMACCheckTime();
        g_ipmac_bind_info.check_interval = 0;
    }

    if(0 >= g_ipmac_bind_info.check_interval)
    {
        g_ipmac_bind_info.check_interval = (g_ipmac_bind_info.check_time / IPMAC_INTERVAL)  - 1;

        /*开始策略处理*/
        /*获取当前网卡信息*/
        /*CHECK ETH UP OR DOWN*/
        if(!get_eth_status(g_ipmac_bind_info.network_info->eth_name)) {
            g_GetlogInterface()->log_trace("eth not up worker return..\n");
            return true;
        }
        get_network_card_info(g_ipmac_bind_info.change_network_info);
        Ping ping;
        PingResult Result;
        /*check link*/
        if(!ping.ping(g_ipmac_bind_info.change_network_info->ip, Result)) {
             g_GetlogInterface()->log_trace("eth not connect worker return..\n");
             return true;
        }
#if defined(OEM_DP_DEEPIN) || defined(OEM_ZB_UKYLIN)
        /*force check but not bind at first time*/
        if(first_get == 1) {
            first_get = 0;
        } else {
            get_script_name_deepin((char *)debian_config_dir,
                    g_ipmac_bind_info.change_network_info->ip, 
                    g_network_script_name);
            printf("current script name is : %s\n", g_network_script_name);
        }

#endif

        /*IP和MAC比较，看是否发生变化，0：未发生改变，1：发生改变*/
        ip_change_flag = is_ip_mac_changed();

        /*有效的绑定范围判定，0：策略不处理，1：策略处理*/
        ip_effective_flag = is_ip_mac_effectivd();

        is_subnet_change = (strcmp(g_ipmac_bind_info.change_network_info->sub_mask, g_ipmac_bind_info.network_info->sub_mask) == 0) ? 0 : 1;

        if(1 == ip_effective_flag) {
            //DNS白名单处理
            dns_white_list_process();
        }

        cout << "ipchange :" << ip_change_flag << "ip_effective_flag : " << ip_effective_flag << endl;
        cout << "subnet change" << is_subnet_change << endl;
        /*根据返回值和策略要求执行不同的动作*/
        if((1 == ip_change_flag  || is_subnet_change) && 1 == ip_effective_flag) {
            /*开启IP改变后如果不处于原来网段范围内则不处理
                0:不需要处理该IP  1：需要处理该IP*/

            int not_deal_diff_subnet = g_ipmac_bind_info.policy->get_NotDealOnChangedInSubNetwork();
            ip_in_subnet_flag = is_ip_mac_in_same_subnet();
            /*
             * 如果在不在原来的子网范围内则不处理，ip在有效的IP处理范围内才处理
             * IP在有效范围内的处理优先级高于在子网内
             * */
            if(ip_in_subnet_flag || !not_deal_diff_subnet)
            {
                exec_policy_action();
                ipmac_bind_send_log();
            }
        } else {
            if(2 == g_ipmac_bind_info.policy->get_IPMACDealMode())
            {
                tag_openNet  tmp ;

                tmp.policy = IPMAC_BIND_CTRL;
                g_GetSendInterface()->sendto_Main(VCF_CMD_OPEN_NET,&tmp,sizeof(tag_openNet));
            }
        }

        /*禁止修改网关*/
        if(1 == g_ipmac_bind_info.policy->get_CombineGateWay())
        {
            exec_combine_gateway();
        }

        /*禁用冗余网卡*/
        if(1 ==  g_ipmac_bind_info.policy->get_DisableSecondaryETH())
        {
            info_list();
        }

        /*校验和不同*/
        if(pPolicy->get_crc() != g_CPolicyIPMacBindctrl->get_crc()) 
        {
            ///拷贝策略
            pPolicy->copy_to(g_CPolicyIPMacBindctrl);

            size_t crc_val = pPolicy->get_crc();
            /*更新IP、MAC绑定关系*/
            _sync_ipmac_cfg(crc_val);
        }
    }
    else
    {
        printf("interval -- %d\n", g_ipmac_bind_info.check_interval);
        g_ipmac_bind_info.check_interval--;
    }
    printf("%s---%d\n", __func__, __LINE__);
    return true;
}

void ipmac_bind_ctrl_uninit()
{

#if defined(OEM_DP_DEEPIN) || defined(OEM_ZB_UKYLIN)
    alreadyget = 0;
    first_get = 0;
#endif
    if(g_ipmac_bind_info.network_info)
    {
        free(g_ipmac_bind_info.network_info);
        g_ipmac_bind_info.network_info = NULL;
    }

    if(g_ipmac_bind_info.change_network_info)
    {
        free(g_ipmac_bind_info.change_network_info);
        g_ipmac_bind_info.change_network_info = NULL;
    }

    if(g_ipmac_bind_info.log_buffer)
    {
        free(g_ipmac_bind_info.log_buffer);
        g_ipmac_bind_info.log_buffer = NULL;
    }

    if(g_CPolicyIPMacBindctrl) {
        delete g_CPolicyIPMacBindctrl ;
        g_CPolicyIPMacBindctrl = NULL ;
    }

    return;
}
