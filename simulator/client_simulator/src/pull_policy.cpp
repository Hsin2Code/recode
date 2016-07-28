#include <time.h>
#include <sys/socket.h>
#include <fcntl.h>
#include "common.h"
#include "old_functions.h"
#include "pull_policy.h"
#include "run_policy_sfd.h"

///获取策略概述结构体
struct tag_S_GetPlockyGEN {
    void * pSendStr ;
    void * pGetStr;
    tag_S_GetPlockyGEN() {
        pSendStr = NULL;
        pGetStr = NULL ;
    }
};


///策略概述
struct tag_vrv_policyGen {
    int id   ;
    string func ;
    unsigned int crc ;
    int    type ;
    int flg  ;
    tag_vrv_policyGen() {
        id = 0 ;
        func = "";
        crc = 0 ;
        flg = 0 ;
    }
};


///策略类型
enum  enPolicytype {
    ///软件安装策略
    SOFT_INSTALL_CTRL,
    ///进程策略
    PROCESS_CTRL,
    ///ip绑定控制
    IPMAC_BIND_CTRL,
    ///
    SOFT_DOWN_CTRL,
    ///违规外联
    ONLINE_DEAL_CTRL,
    ///
    UDISK_ACT_CTRL,
    ///端口保护
    PORT_PROTECT_CTRL,
    ///设备安装控制
    DEV_INSTALL_CTRL,
    ///文件保护控制
    FILE_PROTECT_CTRL,
    ///上网访问审计
    HTTP_VISIT_CTRL,
    ///
    POLICY_SEC_BURN,
    ///文件操作控制
    FILE_OP_CTRL,
    ///策略加密
    POLICY_ENCRYPTION,
    ///HTTP接入控制
    HTTP_ACCESS_CTRL,
    ///
    POLICY_AUTO_SHUTDOWN,
    ///文件校验和
    FILE_CHECKSUM_EDIT,
    ///服务控制
    SERVICE_CTRL,
    ///链接监视
    SYSTEM_CONN_MONITOR,
    ///虚拟机检查
    VIRTUAL_MACHINE_CHECK,
    ///客户端流量控制
    CLI_FLOW_CTRL,
    ///用户权限策略
    USER_RIGHT_POLICY,
    ///主机配置策略
    HOST_CFG_EDIT,
    ///违规操作检查
    VIOLATION_ACT_CHK,
    ///运行信息
    RUN_INFOMATION,
    ///
    CONNECT_GATEWAY_AFFIRM,
    ///
    POLICY_HEALTHCHECK,
    en_policytype_count,
};


const char * policy_target[en_policytype_count] = {"SOFT-INSTALL-CONTROL","PROCESS-CONTROL","IPMAC-BIND-CONTROL",\
                                                   "SOFT-DOWN-CONTROL","ONLINE-DEAL-CONTROL","UDISK-ACTION-CONTROL",\
                                                   "PORT-PROTECT","DEVICE-INSTALL-CONTROL","FILE-PROTECT-CONTROL",\
                                                   "HTTP-VISITED-CONTROL","POLICY-SECURITY-BURN","FILE-OPERATOR-CONTROL",\
                                                   "POLICY-ENCRYPTION","HTTP-ACCESS-CONTROL","POLICY-AUTO-SHUTDOWN",
                                                   "FILE-CHECKSUM-EDIT","SERVICE-CONTROL","SYSTEM-CONNECT-MONITOR",\
                                                   "VIRTUAL-MACHINE-CHECK","CLIENT-FLOW-CONTROL","USERRIGHT-POLICY",\
                                                   "HOST-CONFIG-EDIT","VIOLATION-ACTION-CHECK","RUN-INFORAMTION","CONNECT-GATEWAY-AFFIRM",\
                                                   "POLICY-HEALTHCHECK"};



enPolicytype typefromTartget(std::string & type) {
    for(int i = SOFT_INSTALL_CTRL ; i < en_policytype_count ; i++) {
        if(type == policy_target[i]) {
            return (enPolicytype)i ;
        }
    }
    return en_policytype_count ;
}


static int  get_pkt_app_info(std::string  & info,
                             const std::string & nicName, const std::string  & regip, const string  & retmac) {

    info = info + "MACAddress0="+retmac+STRITEM_TAG_END;
    info = info + "IPAddress0="+regip+STRITEM_TAG_END;
    info = info + "MACCount=1\r\nIPCount=1"+STRITEM_TAG_END;

    net_info n_info;
    memset(&n_info,0,sizeof(net_info));
    strcpy(n_info.mac,retmac.c_str());
    strcpy(n_info.ip,regip.c_str());
    strcpy(n_info.eth_name,nicName.c_str());
    strcpy(n_info.sub_mask, "255.255.255.0");
    strcpy(n_info.gateway, "x.x.x.x");

    info = info +"IPReport="+retmac+"|"+n_info.ip+"|"+n_info.sub_mask+
        "|"+n_info.gateway+"*"+"84C9B2A7E124|8.8.8.8,8.8.4.4#" + STRITEM_TAG_END;

    info = info +"DeviceIdentify="+ g_dev_id +STRITEM_TAG_END;

    std::string _ulist = "fake_user";
    info = info + "SysUserName=" + _ulist + STRITEM_TAG_END;
    info = info + "LogonOnUserName=" + _ulist + STRITEM_TAG_END;
    info = info + "LangId=" + "zh_cn.UTF-8" + STRITEM_TAG_END;

    info = info +"ActiveIPAddress="+regip+STRITEM_TAG_END;
    return 1 ;
}


static bool _send_policy_genenral(tag_S_GetPlockyGEN &policy_gen) {

    int skt = socket(AF_INET,SOCK_STREAM,0);

    if(skt == -1) {
        return false;
    }
    ///主动链接服务器
    if(!conn_serv(skt)) {
        closeSocket(skt);
        return false ;
    }

    ///获取加密密钥
    unsigned int  pwd ;
    if(!get_pwd(skt,pwd)) {
        SM_ERROR() <<  "get pwd error and close socket ";
        closeSocket(skt);
        return false ;
    }

    tag_S_GetPlockyGEN * pGen = &policy_gen;
    std::string * psend = (std::string *)pGen->pSendStr ;
    std::string * pget = (std::string *)pGen->pGetStr ;
    char * pbuffer = const_cast<char *>(psend->c_str()) ;

    VRVPacket pkt;
    if(!pkt.SendPkt(skt,DOWNLOAD_POLICY,DETECT_POLICY,pwd,0,(BYTE*)pbuffer,psend->length())) {
        close_socket(skt, __LINE__);
        return false ;
    }

    if(!pkt.RecvPkt(skt,pwd)) {
        close_socket(skt, __LINE__);
        return false ;
    }

    *pget =  pkt.m_data ;

    close_socket(skt, __LINE__);
    return true;

}

#define POLICY_COUNT_TAG "_COUNT="

void  trimstring(string & str) {
    if(str[str.length()-1] == '\n') {
        str.erase(str.length()-1);
    }
    if(str[str.length()-1] == '\r') {
        str.erase(str.length()-1);
    }
}

std::string  get_tag_val(string & src,string & tag , int & max) {
    int npos = src.find(tag,max);
    if(npos== (int)string::npos) {
        return "" ;
    }
    int npos1 = src.find(".",npos);
    if(npos1 == (int)string::npos) {
        return "";
    }
    if(npos1 > max) {
        max = npos1 ;
    }
    ///后面有两个看不见的字符，所以+2
    std::string ret = src.substr(npos + tag.length() + 1,npos1 - (npos + tag.length()+strlen(STRITEM_TAG_END)));
    trimstring(ret);
    return ret;
}

int    get_policylist_fromGeneral(std::string & general ,
                                  std::vector<tag_vrv_policyGen> & _array)
{
    ///先获取数量
    int  cnt_tag_len = strlen(POLICY_COUNT_TAG);
    int npos = general.find(POLICY_COUNT_TAG,0);
    if(npos == (int)string::npos) {
        SM_ERROR() << "get_policylist_fromGeneral number failed ";
        return 0 ;
    }

    int npos1 = general.find(".",npos);
    if(npos1 == (int)string::npos) {
        SM_ERROR() << "get_policylist_fromGeneral failed 2";
        return 0 ;
    }

    string  strcount = general.substr(npos + cnt_tag_len,npos1-npos-1);
    int count = atoi(strcount.c_str());

    string  id_tag , func_tag , crc_tag , flg_tag ;
    string  id,      func ,     crc ,     flg ;
    char    sz[32] = "" ;
    string  tmp ;
    int max_idx = 0 ;
    tag_vrv_policyGen item;
    for(int i = 0 ; i < count ; i++) {
        sprintf(sz,"%d",i);
        tmp = sz ;
        id_tag = "_ID" + tmp ;
        id = get_tag_val(general,id_tag,max_idx);
        if(id.length() == 0)  {
            break ;
        }
        //printf("id_Tag = %s , val = %s\n",id_tag.c_str(),id.c_str());
        item.id = atoi(id.c_str());


        func_tag = "_FUNC" + tmp;
        func = get_tag_val(general,func_tag,max_idx);
        if(func.length()==0) {
            break ;
        }
        //printf("func_tag = %s , val = %s\n",func_tag.c_str(),func.c_str());
        item.func = func ;

        crc_tag = "_CRC" + tmp ;
        crc = get_tag_val(general,crc_tag,max_idx);
        if(crc.length()==0) {
            break ;
        }

        item.crc =(unsigned int)strtoul(crc.c_str(),NULL,10);

        flg_tag = "_FLG" + tmp ;

        flg = get_tag_val(general,flg_tag,max_idx);
        if(flg.length()==0) {
            break;
        }
        //printf("flg_tag = %s , val = %s\n",flg_tag.c_str(),flg.c_str());
        item.flg = atoi(flg.c_str());
        bool  bexsit = false ;
        for(int j = 0 ; j < (int)_array.size() ; j++) {
            if(item.func == _array[j].func) {
                if(item.flg > _array[j].flg) {
                    _array[j] = item ;
                    bexsit = true ;
                    break ;
                }
            }
        }
        if(!bexsit) {
            _array.push_back(item);
        }
    }

    return _array.size() ;
}


static bool _send_policy_detail(tag_S_GetPlockyGEN &pgen) {

    int skt = socket(AF_INET,SOCK_STREAM,0);

    if(skt == -1) {
        return false;
    }
    ///主动链接服务器
    if(!conn_serv(skt)) {
        closeSocket(skt);
        return false ;
    }

    ///获取加密密钥
    unsigned int  pwd ;
    if(!get_pwd(skt,pwd)) {
        SM_ERROR() << "get pwd error and close socket ";
        closeSocket(skt);
        return false ;
    }

    tag_S_GetPlockyGEN * pGen = &pgen;
    std::string * psend = (std::string *)pGen->pSendStr ;
    std::string * pget = (std::string *)pGen->pGetStr ;
    char * pbuffer = const_cast<char *>(psend->c_str()) ;

    VRVPacket pkt;
    if(!pkt.SendPkt(skt,DOWNLOAD_POLICY,GET_POLICY,pwd,0,(BYTE*)pbuffer,psend->length())) {
        close_socket(skt, __LINE__);
        return false ;
    }

    if(!pkt.RecvPkt(skt,pwd)) {
        close_socket(skt, __LINE__);
        return false ;
    }
    *pget =  pkt.m_data ;
    close_socket(skt, __LINE__);
    return true;
}

#define    POLICY_END_TAG  "</vrvscript>"

bool get_PolicyContent(int i, const std::string  & src , string & xml , int & startpos) {
    string tag = "P_CONTENT" ;
    char sz[20] = "";
    sprintf(sz,"%d",i);
    tag = tag + sz ;
    unsigned int  npos = src.find(tag,startpos);
    if(npos== string::npos) {
        return false ;
    }
    unsigned int  npos1 = src.find(POLICY_END_TAG,npos);
    if(npos1 == string::npos) {
        return false ;
    }
    if((int)npos1 > startpos) {
        startpos = npos1 ;
    }
    xml = src.substr(npos+tag.length()+1,npos1+strlen(POLICY_END_TAG) -(npos+tag.length()+1));
    trimstring(xml);
    return true ;
}

bool _contain_file_policy(void *pGenArray, const std::string & policy_str, std::vector<std::string> &xmlvt) {
    std::vector<tag_vrv_policyGen> * pArray = (std::vector<tag_vrv_policyGen> *)pGenArray;
    std::vector<tag_vrv_policyGen> & _array = *pArray ;
    int pos = 0 ;
    std::string  xml ;

    for(int i = 0 ; i < (int)_array.size() ; i++) {
        if(get_PolicyContent(i, policy_str, xml, pos)) {
            if(typefromTartget(_array[i].func) == SOFT_DOWN_CTRL) {
                xmlvt.push_back(xml);
                break;
            }
        }
    }
    if(xmlvt.size() >= 1) {
        return true;
    }
    return false;
}

void  _log_policy_breif(void *pGenArray, const std::string & policy_str) {
    std::vector<tag_vrv_policyGen> * pArray = (std::vector<tag_vrv_policyGen> *)pGenArray;
    std::vector<tag_vrv_policyGen> & _array = *pArray ;
    int pos = 0 ;
    std::string  xml ;

    for(int i = 0 ; i < (int)_array.size() ; i++) {
        if(get_PolicyContent(i, policy_str, xml, pos)) {
            if(typefromTartget(_array[i].func) != en_policytype_count) {
                std::string p_bref = "";
                p_bref += "type: " + _array[i].func;
                char _buf[128] = {0};
                sprintf(_buf, "%d", _array[i].id);
                p_bref += " id: "; p_bref.append(_buf);
                sprintf(_buf, "%u", _array[i].crc);
                p_bref += " crc: "; p_bref.append(_buf);
                SM_POLICY() << p_bref;
            } else {
                SM_POLICY() << "log policy brief error: " + _array[i].func;
                SM_ERROR() << "log policy brief error: " + _array[i].func;
            }
        }
    }
}

typedef struct file_thr_args {
    pthread_t *thread_id;
    std::string *policy_content;
    file_thr_args() {
        thread_id = NULL;
        policy_content = NULL;
    }
}file_thr_args_t;

pthread_t *g_running_file_tid_ptr = NULL;

int policy_pull_success_times = 0;
int policy_pull_falied_times = 0;

void *file_sfd_thr_cb(void *args) {
    file_thr_args_t *thr_args = (file_thr_args_t *)args;
    if(thr_args == NULL) {
        return NULL;
    }
    /*do policy file*/
    std::string content = "";
    if(thr_args->policy_content != NULL) {
        content = thr_args->policy_content->c_str();
    }
    run_policy_sfd(content);
    *(thr_args->thread_id) = 0;
    return NULL;
}


bool on_Update_pGeneral(std::string & pkt_info,std::string & str_pGeneral) {
    std::vector<tag_vrv_policyGen>   _array ;

    if(get_policylist_fromGeneral(str_pGeneral,_array)) {
        SM_LOG() << "get server policy number : " << _array.size();
        ///对所有的策略进行类型进行转化
        {
            for(int i = 0 ; i < (int)_array.size() ; i++) {
                _array[i].type = typefromTartget(_array[i].func);
            }
        }

        std::string  strPolicylist ;
        std::string  strflgList ;
        char sz[20] = "";
        ///拼接下载上报的字符串
        for(int i = 0 ; i < (int)_array.size() ; i++) {
            tag_vrv_policyGen & gen = _array[i];
            sprintf(sz,"%d,",gen.id);
            strPolicylist = strPolicylist + sz ;
            sprintf(sz,"%d,",gen.flg);
            strflgList = strflgList + sz ;
        }
        ///策略ID列表大于0
        if(strPolicylist.length()) {
            strPolicylist.erase(strPolicylist.length()-1,1);
            strflgList.erase(strflgList.length()-1,1);

            strPolicylist ="Policys=" + strPolicylist + STRITEM_TAG_END;
            strflgList ="FLG=" + strflgList + STRITEM_TAG_END;

            SM_LOG() << "policy list : " << strPolicylist;

            std::string app_info = pkt_info + strPolicylist + strflgList ;

            tag_S_GetPlockyGEN getGen ;
            std::string  policy_str;
            getGen.pSendStr = &app_info;
            getGen.pGetStr =  &policy_str;

            {
                std::string get_policy_content = "GET_POLICY_CONTENT:" + g_dev_id;
                TIMED_SCOPE(timer, get_policy_content.c_str());
                if(!_send_policy_detail(getGen)) {
                    SM_ERROR() << "get policy detail error";
                    return false;
                }

            }

            SM_POLICY() << "PULL FAILED TIMES: " << policy_pull_falied_times <<
                " PULL SUCCESS_TIMES: " << policy_pull_success_times <<
                " POLICY COUNT: " << _array.size();
            _log_policy_breif(&_array, policy_str);

            static std::vector <std::string> xmlvt;
            xmlvt.clear();

            if(_contain_file_policy(&_array,policy_str, xmlvt)) {
                SM_LOG() << "contain softdown policy and perpare to run";
                static pthread_t rf_thr = 0;
                g_running_file_tid_ptr = &rf_thr;
                if(rf_thr == 0 && g_sfd_flag == 1) {
                    static file_thr_args_t thr_args;
                    thr_args.thread_id = &rf_thr;
                    thr_args.policy_content = &(xmlvt.at(0));
                    int  ret = pthread_create(&rf_thr, NULL, file_sfd_thr_cb, (void*)&thr_args);
                    if(ret != 0) {
                        SM_ERROR() << "run policy: start software down thread error";
                        rf_thr = 0;
                    }
                }
            }
            SM_LOG() << " policy detail is: " << policy_str;
        }
    } else {
        SM_LOG() << "get policy general number is zero";
    }
    return true ;
}


static bool _get_policy_info() {
    SM_LOG() << "start to pull policy";
    ///获取附加上报信息
    std::string app_sys_info;

    std::string eth_name = "ethx";
    get_pkt_app_info(app_sys_info, eth_name, g_self_ipaddr, g_mac_addr);
    SM_LOG() << " prepend get poilicy general : " << app_sys_info;
    /**
     * 先获取概况，然后比对，再判断是否需要更新
     */
    tag_S_GetPlockyGEN getGen;
    std::string  str_pGeneral;
    getGen.pSendStr = &app_sys_info;
    getGen.pGetStr = &str_pGeneral ;

    {
        std::string get_policy_gen = "GET_POLICY_GENERAL:" + g_dev_id;
        TIMED_SCOPE(timer, get_policy_gen.c_str());
        if(!_send_policy_genenral(getGen)) {
            SM_ERROR() << "**** get policy general failed";
            return false;
        }
    }
    SM_LOG() <<  "get policy general content is: " << str_pGeneral;
    return on_Update_pGeneral(app_sys_info,str_pGeneral);
}




void *pull_policy_worker(void *args) {
    (void)(args);
    SM_LOG() <<  "pull policy worker start ";
    int _inner_count = 0;
    while(1) {
        SM_LOG() <<  "start pull policy .....";
        {
            std::string pull_policy = "PULL_POLICY:" + g_dev_id;
            TIMED_SCOPE(timer, pull_policy.c_str());
            if(_get_policy_info()) {
                policy_pull_success_times++;
            } else {
                policy_pull_falied_times++;
            }
        }
        SM_LOG() << "pull policy finish";
        usleep(g_policy_interval * 1000000);
        _inner_count++;
        if(_inner_count >= g_run_times) {
            pthread_exit(NULL);
        }
    }
    return NULL;
}
