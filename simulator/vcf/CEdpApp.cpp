/*
 * CEdpApp.cpp
 *
 *  Created on: 2015-5-20
 *      Author: sharp
 */

#include <sstream>
#include "CEdpApp.h"
#include "vrcport_tool.h"
#include "../include/msgpack-c/msgpack.hpp"
#include "../include/MCInterface.h"


///升级间隔
const int   c_iClientUpgrade_interval = 2*3600*1000;
/*offset with others*/
const int   c_check_protect = 7 * 1000;

CEdpApp::~CEdpApp() {
	// TODO Auto-generated destructor stub
}

CEdpApp::CEdpApp() {
    m_nClientUpgradeTimer = -1;
    m_check_protect_id = -1;
    _msg_proc_cmd_map[VAS_CFG_DESC] = lcfg_ui_desc;
    _msg_proc_cmd_map[VAS_CFG_PHONE] = lcfg_ui_phone;
    _msg_proc_cmd_map[VAS_CFG_EMAIL] = lcfg_ui_email;
    _msg_proc_cmd_map[VAS_CFG_USER_NAME] = lcfg_ui_username;
    _msg_proc_cmd_map[VAS_CFG_COMP_NAME] = lcfg_ui_compname;
    _msg_proc_cmd_map[VAS_CFG_DEP_NAME] = lcfg_ui_depname;
    _msg_proc_cmd_map[VAS_CFG_MACH_LOC] = lcfg_ui_machloc;
    _msg_proc_cmd_map[VAS_CFG_ASSERT_NO] = lcfg_ui_assertno;
    _msg_proc_cmd_map[VAS_CFG_SERVER_IP] = lcfg_srvip;
    _msg_proc_cmd_map[VAS_CFG_IS_REG] = lcfg_ui_is_reg;
    _ipmac_cfg_map.clear();
}

bool CEdpApp::InitInstances() {
	return CVCFApp::InitInstances();
}

int          CEdpApp::ExitInstances(int extid) {
	return CVCFApp::ExitInstances(extid);
}

/**
* 定时器处理函数， 可以在这里驱动一些周期性的操作
* 所有定义的定时器到了固定时间，都会在此处相应
* 此函数和主线程通道函数在一个线程。
*/
bool         CEdpApp::timer_proc(int id) {
    if(m_nClientUpgradeTimer == id)
    {
        printf("m_nClientUpgradeTimer=%d\n",id);
        sendto_pl4Exec(VCF_CMD_CLIENT_UPGRADE,NULL,0);
        return true;
    } else if(m_check_protect_id == id) {
        do_protect();
        return true;
    }
	return CVCFApp::timer_proc(id);
}
/**
*  主线程消息处理函数
*/
bool         CEdpApp::msg_proc(unsigned short cmd , PVOID buffer, int len,unsigned int id) {
    switch(cmd)
    {
        case VCF_CMD_REGISTER_SUCC: {
            if(m_nClientUpgradeTimer == -1) {
                m_nClientUpgradeTimer = set_Timer(c_iClientUpgrade_interval,0,true);
            }
            if(m_check_protect_id == -1) {
                m_check_protect_id = set_Timer(c_check_protect, 0, true);
            }
            break;
        }
        case VCF_CMD_MAIN_SRUNING: {
            if((m_nClientUpgradeTimer == -1) && m_bRegister) {
                m_nClientUpgradeTimer = set_Timer(c_iClientUpgrade_interval,0,true);
            }
            if(m_check_protect_id == -1) {
                m_check_protect_id = set_Timer(c_check_protect, 0, true);
            }
            break;
        }
        ///IPMAC存储消息响应
        case VCF_CMD_SET_IPMAC_CFG: {
            tag_ipmac_info *pinfo = (tag_ipmac_info *)buffer;
            if(pinfo == NULL) {
                break;
            }
            //if(pinfo->type >= lcfg_invalid || pinfo->info[0] == '\0') {
            if(pinfo->type >= lcfg_invalid) {
                break;
            }
            std::cout << "||||||||||||||||| set " << pinfo->type <<std::endl;
            std::cout << "||||||||||||||||| set " << pinfo->info <<std::endl;
            std::string cfg_name = type_to_cfg_name((en_lcfg_key)pinfo->type);
            char data_buf[1024] = {0};
            tag_LDBexec *pdbExec = (tag_LDBexec *)data_buf;
            pdbExec->tbl = tbl_config;
            pdbExec->cbop = dbop_modify;
            pdbExec->cnt = 1;
            T_localcfg *pcfg = (T_localcfg *)pdbExec->data;
            pcfg->name = cfg_name.c_str();
            pcfg->vals = pinfo->info;
            /*check here*/
            if(!sendmsg(m_nlogChannelID, VCF_CMD_LDB_OPERATOR, pdbExec,
                        sizeof(tag_LDBexec) + sizeof(T_localcfg) * pdbExec->cnt)) {
                std::cout << "||||MODIFY FALIED" << std::endl;
            } 
            break;
        }
        case VCF_CMD_GET_IPMAC_CFG: {
            tag_ipmac_info *pinfo = (tag_ipmac_info *)buffer;
            if(pinfo == NULL) {
                break;
            }
            if(pinfo->type >= lcfg_invalid) {
                break;
            }
            switch(pinfo->type) {
                case lcfg_bind_gw:
                case lcfg_bind_mac:
                case lcfg_bind_mask:
                case lcfg_bind_pcrc:
                case lcfg_bind_ip: {
                    std::cout << "q form db" << std::endl;
                    get_ipmac_db_cfg((en_lcfg_key)pinfo->type, 
                                _ipmac_cfg_map[pinfo->type]);
                    break;
                }
                default:
                break;
            }
            break;
        }
        default:
            break;
    }
    return CVCFApp::msg_proc(cmd,buffer,len,id);
}

static void * pull_up_gui_in_system(void *args) {
    pthread_detach(pthread_self());
    if(args == NULL) {
        return NULL;
    }
    std::string path = (char *)args;
    free(args);
    args = NULL;
    if(!path.empty()) {
        system(path.c_str());
    }
    return NULL;
}



///进程间消息通道执行函数
bool        CEdpApp::IMC_msg_proc(unsigned short cmd , PVOID buffer , int len,unsigned int id) {
	//消息接收加这里
    switch(cmd) {
        case VCF_CMD_VAS_GUI_TIPS: {
            printf("pub msg to tray and return\n");
            m_imcSrv.pub_msg_4tray(MC_CMD_S2C_NOTIFY_MESSAGE, buffer, len);
            return true;
        }
        case VCF_CMD_VAS_PULL_UP_SYSTRAY: {
            printf("PULL UP SYSTRAY......\n");
            std::string install_path = "./";
            install_path.append(EDP_GUIAPP_TRAY);
            std::string curr_user = "";
            get_loginUser(curr_user);
            if(curr_user != "root") {
                char *str_path = (char *)malloc(install_path.length() + 1);
                memset(str_path, 0, install_path.length() + 1);
                strcpy(str_path, install_path.c_str());
                pthread_t tmp_id;
                pthread_create(&tmp_id, NULL, pull_up_gui_in_system, str_path);
                LOG_INFO("PULL UP SYSTRAY END USE SYSTEM......");
            }
            return true;
        }
        default:
            break;
    }
	return CVCFApp::IMC_msg_proc(cmd,buffer,len,id);
}
///审计日志消息
bool        CEdpApp::Upload_msg_proc(unsigned short cmd , PVOID buffer , int len,unsigned int id) {
	//消息接收加这里

	return CVCFApp::Upload_msg_proc(cmd,buffer,len,id);
}
///策略执行消息通道
bool        CEdpApp::Policy_msg_proc(unsigned short cmd , PVOID buffer , int len,unsigned int id) {
	//消息接收加这里
    switch(cmd)
    {
        case VCF_CMD_CLIENT_UPGRADE:
        {
            return on_Client_Upgrade();
        }
    }
	return CVCFApp::Policy_msg_proc(cmd,buffer,len,id);
}


///
bool  CEdpApp::on_Client_Upgrade()
{
    return m_NetEngine.sendnetmsg(S_CMD_CLIENT_UPGRADE,NULL,0);
}


bool CEdpApp::get_lconfig(en_lcfg_key key, std::string &val) {
    switch(key) {
        case lcfg_bind_mask:
        case lcfg_bind_gw:
        case lcfg_bind_mac:
        case lcfg_bind_pcrc:
        case lcfg_bind_ip: {
                tag_ipmac_info ipmac_info;
                ipmac_info.type = key;

                _ipmac_cfg_map[key].clear();
                sendto_Main(VCF_CMD_GET_IPMAC_CFG, &ipmac_info, sizeof(tag_ipmac_info), true);
                std::cout << " -d-d-d-d-d-d- get lcfg : " << _ipmac_cfg_map[key] << std::endl;
                if(_ipmac_cfg_map[key].empty()) {
                    std::cout << "get ip mac db config failed" << std::endl;
                    return false;
                }
                val = _ipmac_cfg_map[key];
                return true;
            }
            break;
        case lcfg_ui_username ... lcfg_ui_desc: {
            _get_config_from_db((en_lcfg_key)key, val);
            return true;
        }
        case lcfg_ui_is_reg: {
            _get_config_from_db((en_lcfg_key)key, val);
            return true;
        }
        /*WE CATCH SERVER IP CFG GET HERE NOT IN CVCFApp ANY MORE*/
        case lcfg_srvip: {
            if(m_strSrvIp.empty()) {
                _get_config_from_db((en_lcfg_key)key, val);
                /*sync to m_server ip*/
                m_strSrvIp = val;
            } else {
                val = m_strSrvIp;
            }
            return true;
        }
        case lcfg_regip: {
            if(m_strRegiP.empty()) {
                _get_config_from_db((en_lcfg_key)key, val);
                m_strRegiP = val;
            } else {
                val = m_strRegiP;
            }
            return true;
        }
        case lcfg_regmac: {
            if(m_strRegMac.empty()) {
                _get_config_from_db((en_lcfg_key)key, val);
                m_strRegMac = val;
            } else {
                val = m_strRegMac;
            }
            return true;
        }
        default:
            break;
    }
    return CVCFApp::get_lconfig(key, val);
}

bool CEdpApp::set_lconfig(en_lcfg_key key, const std::string &val) {
    switch(key) {
        case lcfg_bind_mask:
        case lcfg_bind_gw:
        case lcfg_bind_mac:
        case lcfg_bind_pcrc:
        case lcfg_bind_ip: {
                tag_ipmac_info ipmac_info;
                ipmac_info.type = key;
                strncpy(ipmac_info.info, val.c_str(), sizeof(ipmac_info.info) - 1);
                sendto_Main(VCF_CMD_SET_IPMAC_CFG, &ipmac_info, sizeof(ipmac_info));
                return true;
            }
        case lcfg_ui_username ... lcfg_ui_desc: {
                if(!_set_config_to_db((en_lcfg_key)key, val, false)) {
                    return false;
                }
                return true;
            }
            /*标志UI注册*/
        case lcfg_ui_is_reg: {
                if(!_set_config_to_db((en_lcfg_key)key, val, true)) {
                    return false;
                }
                return true;
            }
        case lcfg_srvip: {
                if(!_set_config_to_db((en_lcfg_key)key, val)) {
                    return false;
                }
                m_strSrvIp = val;
                return true;
            }
        case lcfg_regip: {
                if(!_set_config_to_db((en_lcfg_key)key, val)) {
                    return false;
                }
                m_strRegiP = val;
                return true;
            }
        case lcfg_regmac: {
                if(!_set_config_to_db((en_lcfg_key)key, val)) {
                    return false;
                }
                m_strRegMac = val;
                return true;
            }
        case lcfg_regnic: {
                if(!_set_config_to_db((en_lcfg_key)key, val)) {
                    return false;
                }
                m_strRegNic = val;
                return true;
            }
        default:
            break;
    }
    return CVCFApp::set_lconfig(key, val);
}

std::string CEdpApp::type_to_cfg_name(en_lcfg_key key) {
    switch(key) {
        case lcfg_bind_ip: {
            return LDB_BIND_IP;
        }
        case lcfg_bind_gw: {
            return LDB_BIND_GW;
        }
        case lcfg_bind_mac: {
            return LDB_BIND_MAC;
        }
        case lcfg_bind_mask: {
            return LDB_BIND_MASK;
        }
        case lcfg_bind_pcrc: {
            return LDB_BIND_PCRC;
        }
        /*TODO: add other config*/
        case lcfg_ui_username:
            return LDB_VAS_CFG_USER_NAME;
        case lcfg_ui_compname:
            return LDB_VAS_CFG_COMP_NAME;
        case lcfg_ui_depname:
            return LDB_VAS_CFG_DEP_NAME;
        case lcfg_ui_phone:
            return LDB_VAS_CFG_PHONE;
        case lcfg_ui_machloc:
            return LDB_VAS_CFG_MACH_LOC;
        case lcfg_ui_email:
            return LDB_VAS_CFG_EMAIL;
        case lcfg_ui_assertno:
            return LDB_VAS_CFG_ASSERT_NO;
        case lcfg_ui_desc:
            return LDB_VAS_CFG_DESC;
        case lcfg_ui_is_reg:
            return LDB_VAS_CFG_IS_REG;
            /*CATCH BEFORE IN TO CVCFApp*/
        case lcfg_srvip:
            return LDB_SRVIP;
        case lcfg_regip:
            return LDB_REGIP;
        case lcfg_regmac:
            return LDB_REGMAC;
        case lcfg_regnic:
            return LDB_REGNIC;
        default:
            break;
    }
    return "";
}

void CEdpApp::get_ipmac_db_cfg(en_lcfg_key key, std::string &val) {
    /*no need to verify key param*/
	std::string dbfile = getMoudlepath() + LDB_NAME;
    if(m_localDB.db_isOpen()) {
        m_localDB.db_Attach();
    }

    std::string cfg_name = type_to_cfg_name(key);
    if(cfg_name.empty()) {
        if(m_localDB.db_isOpen()) {
            m_localDB.db_Dettch();
        }
        return;
    }
	std::vector<T_localcfg> cfgvt ;
	char szQuery[64] = "";
	sprintf(szQuery,"name = '%s'",cfg_name.c_str());
    std::cout << "QQQQ:: -> " << szQuery <<std::endl;
	if(m_localDB.select(tbl_config,&cfgvt,szQuery)) {
        val = cfgvt[0].vals;
    }
    if(m_localDB.db_isOpen()) {
        m_localDB.db_Dettch();
    }
	return;
}

void CEdpApp::_get_config_from_db(en_lcfg_key key, std::string &val) {
    //no need to verify key param
	std::string dbfile = getMoudlepath() + LDB_NAME;
    if(m_localDB.db_isOpen()) {
        m_localDB.db_Attach();
    }

    std::string cfg_name = type_to_cfg_name(key);
    if(cfg_name.empty()) {
        if(m_localDB.db_isOpen()) {
            m_localDB.db_Dettch();
        }
        return;
    }
	std::vector<T_localcfg> cfgvt ;
	char szQuery[64] = "";
	sprintf(szQuery,"name = '%s'",cfg_name.c_str());
    LOG_DEBUG("DB QUERY %s", szQuery);
	if(m_localDB.select(tbl_config,&cfgvt,szQuery)) {
        val = cfgvt[0].vals;
    }
    if(m_localDB.db_isOpen()) {
        m_localDB.db_Dettch();
    }
	return;
}

bool CEdpApp::_set_config_to_db(en_lcfg_key key, const std::string &val, bool check_value_empty) {
    if(key == lcfg_invalid) {
        return false;
    }
    if(check_value_empty && val.empty()) {
        return false;
    }
    std::string cfg_name = type_to_cfg_name(key);
    if(cfg_name.empty()) {
        return false;
    }
    char buffer[1024] = {0};
    tag_LDBexec *  pdbExec = (tag_LDBexec *)buffer ;
    pdbExec->tbl = tbl_config ;
    pdbExec->cbop  = dbop_modify ;
    pdbExec->cnt = 1;
    T_localcfg * pcfg = (T_localcfg *)pdbExec->data ;
    pcfg->name = cfg_name.c_str();
    pcfg->vals = val.c_str();
    if(!sendmsg(m_nlogChannelID, VCF_CMD_LDB_OPERATOR, pdbExec,
                sizeof(tag_LDBexec) + sizeof(T_localcfg) * pdbExec->cnt)) {
        LOG_ERR("save user info to local db error");
        return false;
    } 
    LOG_INFO("save user info to db success: key : %s cfg: %s", cfg_name.c_str(), pcfg->vals);
    return true;
}



#define UNPACK_MARCO(target_type, t_var_name) \
    msgpack::unpacked ret; \
    msgpack::unpack(ret, (char *)pbuffer, len); \
    target_type t_var_name; \
    msgpack::object obj = ret.get(); \
    obj.convert(&t_var_name);

#define PACK_AND_SEND(MSG, org_object) \
    std::stringstream ss; \
    msgpack::pack(ss, org_object); \
    m_imcSrv.sendData(MSG , (void *)ss.str().data(), ss.str().size()); \

/*TODO: SPLIT THIS BIG FUNCTION!!!!!! FIXME*/
void CEdpApp::Sinkmsg_proc(unsigned short cmd,void * pbuffer,int len,int pid) {

    switch(cmd) {
        case MC_CMD_C2S_GET_VAS_CFG: {
            UNPACK_MARCO(vas_trans_cfg_t, cfg);
            if(cfg.key == VAS_CFG_INVALID) {
                m_imcSrv.sendData(MC_CMD_S2C_EXPORT_CFG_NG, NULL, 0);
                return;
            }
            std::string value;
            switch(cfg.key) {
                case VAS_CFG_USER_NAME ... VAS_CFG_DESC: {
                    get_lconfig((en_lcfg_key)_msg_proc_cmd_map[cfg.key], value);
                }
                    break;
                /*CACTCH SERVER IP CONFIG IN EDPAPP NOT IN CVCFApp*/
                case VAS_CFG_SERVER_IP:
                    get_lconfig((en_lcfg_key)_msg_proc_cmd_map[cfg.key], value);
                    break;
                case VAS_CFG_IS_REG:
                    get_lconfig((en_lcfg_key)_msg_proc_cmd_map[cfg.key], value);
                    break;
                default:
                    m_imcSrv.sendData(MC_CMD_S2C_EXPORT_CFG_NG, NULL, 0);
                    return;
            }
            vas_trans_cfg_t ret_cfg;
            ret_cfg.key = cfg.key;
            ret_cfg.value = value;
            PACK_AND_SEND(MC_CMD_S2C_EXPORT_CFG_OK, ret_cfg);
            return;
        }
        case MC_CMD_C2S_SET_VAS_CFG: {
            UNPACK_MARCO(vas_trans_cfg_t, cfg);
            if(cfg.key == VAS_CFG_INVALID) {
                m_imcSrv.sendData(MC_CMD_S2C_SET_CFG_NG, NULL, 0);
                return;
            }
            switch(cfg.key) {
                case VAS_CFG_SERVER_IP:
                case VAS_CFG_USER_NAME ... VAS_CFG_DESC: {
                    if(cfg.value.empty()) {
                        m_imcSrv.sendData(MC_CMD_S2C_SET_CFG_NG, NULL, 0);
                        break;
                    }
                    if(set_lconfig((en_lcfg_key)_msg_proc_cmd_map[cfg.key], 
                                cfg.value)) {
                        PACK_AND_SEND(MC_CMD_S2C_SET_CFG_OK, cfg);
                        LOG_DEBUG("send set msg ok");
                    } else {
                        m_imcSrv.sendData(MC_CMD_S2C_SET_CFG_NG, NULL, 0);
                        LOG_DEBUG("send set msg error");
                    }
                }
                break;
                default:
                break;
            }
            return;
        }
        case MC_CMD_C2S_DETECT_SERVER: {
            UNPACK_MARCO(vas_c2s_common_t, check_target);
            vas_c2s_common_t check_ret;
            check_ret.ctx.clear();
            check_ret.ctx.push_back("0");
            if(check_target.ctx.size() != 1) {
                PACK_AND_SEND(MC_CMD_S2C_DETECT_SERVER, check_ret);
                return;
            }
            std::string check_ip = check_target.ctx.at(0);
            if(check_ip.empty()) {
                PACK_AND_SEND(MC_CMD_S2C_DETECT_SERVER, check_ret);
                return;
            }
            /*ret list is ip and result*/
            check_ret.ctx.at(0) = check_ip;
            if(detect_vas_server(check_ip)) {
                check_ret.ctx.push_back("1");
                PACK_AND_SEND(MC_CMD_S2C_DETECT_SERVER, check_ret);
                return;
            }
            check_ret.ctx.push_back("0");
            PACK_AND_SEND(MC_CMD_S2C_DETECT_SERVER, check_ret);
            return;
        }
        case MC_CMD_C2S_REG_AFTER_INSTALL: {
            LOG_DEBUG_IMP("RECIVE REGISTER AGSIN MSG FROM CLEINT....");
            if(register_after_install()) {
                /*success*/
                m_imcSrv.sendData(MC_CMD_S2C_REG_OK, NULL, 0);
                set_lconfig(lcfg_ui_is_reg, "1");
                std::string _server_ip;
                get_lconfig(lcfg_srvip, _server_ip);
                if(!_server_ip.empty()) {
                    sendto_pl4Exec(VCF_CMD_GET_ASSEET,NULL,0);
                }
                return;
            } else {
				std::string key = VRVNETPRO_ERROR ;
				std::string error = m_NetEngine.get_Param(key);
                set_lconfig(lcfg_ui_is_reg, "0");
				m_imcSrv.sendData(MC_CMD_S2C_REG_NG,error.c_str(),error.length());
            }
            return;
        }
        default:
            break;
    }
    return CVCFApp::Sinkmsg_proc(cmd, pbuffer, len, pid);
}

bool CEdpApp::register_after_install() {
    if(m_strSrvIp.empty()) {
        LOG_WARN("NO SERVER IP JUST RETURN");
        return false;
    }
    std::map<int, std::string> ui_client_info;
    for(int i = lcfg_ui_username; i <= lcfg_ui_desc; i++) {
        std::string value;
        get_lconfig((en_lcfg_key)i, value);
        ui_client_info[i] = value;
    }
    std::map<int, std::string> reg_key_map;
    reg_key_map[lcfg_ui_username] = "UserName";
    reg_key_map[lcfg_ui_compname] = "DeptName";
    reg_key_map[lcfg_ui_depname] = "OfficeName";
    reg_key_map[lcfg_ui_machloc] = "RoomNumber";
    reg_key_map[lcfg_ui_email] = "Email";
    reg_key_map[lcfg_ui_phone] = "Tel";
    reg_key_map[lcfg_ui_assertno] = "DeviceCode";
    reg_key_map[lcfg_ui_desc] = "FloorNumber";

    std::map<int, std::string>::iterator iter = ui_client_info.begin();
    int filed_count = 0;
    std::string reginfo = "";
    char buf[1024] = {0};
    for(; iter != ui_client_info.end(); iter++) {
		snprintf(buf, sizeof(buf)-1, "DBField%d=%s\r\n", 
                filed_count, reg_key_map[iter->first].c_str());
		reginfo += buf;
		snprintf(buf, sizeof(buf)-1, "DBValue%d=%s\r\n", 
                filed_count, iter->second.c_str());
		reginfo += buf;
        memset(buf, 0, sizeof(buf));
        filed_count++;
    }
    memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf)-1, "DBFieldCount=%d\r\n", (int)ui_client_info.size());
	reginfo += buf;

#if 0
         *DBField0=UserName
         *DBValue0=
         *DBField1=DeptName
         *DBValue1=
         *DBField2=OfficeName
         *DBValue2=
         *DBField3=RoomNumber
         *DBValue3=
         *DBField4=Tel
         *DBValue4=
         *DBField5=Email
         *DBValue5=
         *DBField6=Reserved2
         *DBValue6=2:Windows笔记本
         *DBField7=FloorNumber
         *DBValue7=
         *DBFieldCount=8
         *SelectNicInfo=192.168.131.115/000c29d6b5d9
         *WebServerIP=192.168.131.94
#endif

    /*1.get local nic info
     *2.select one live nic ? NOT?
     *3.get the reg ip */

    /*first time*/
    if(m_strRegMac.empty()) {
        std::list<std::string> niclist ;
        get_Nicinfo(niclist);
        std::list<std::string>::iterator  iter = niclist.begin();
        std::string ip, mac, nic_name;
        while(iter != niclist.end()) {
            mac = YCommonTool::get_mac(*iter);
            ip = YCommonTool::get_ip(*iter);
            nic_name = *iter;
            if(!mac.empty()) {
                break;
            }
            iter++ ;
        }
        if(!mac.empty()) {
            if(!set_lconfig(lcfg_regmac, mac)) {
                LOG_ERR("set reg mac address to db error");
            }
            if(m_strDevid.empty()) {
                char buffer_idp[32]="";
                if(get_device_indetify(buffer_idp,32, m_strRegMac) > 0) {
                    m_strDevid = buffer_idp ;
                }
            }
        }
        if(!ip.empty() && m_strRegiP.empty()) {
            if(!set_lconfig(lcfg_regip, ip)) {
                LOG_ERR("set reg ip addresss to db error");
            }
        }
        /*nic name not store in db*/
        if(!nic_name.empty() && m_strRegNic.empty()) {
            m_strRegNic = nic_name;
        }
    }

    if(m_strRegMac.empty()) {
        LOG_ERR("Can't get the Reg MAC we try best");
        return false;
    }

    std::string reg_info_ex = "";
    reg_info_ex = reg_info_ex + "MACAddress0="+ m_strRegMac +STRITEM_TAG_END;
    reg_info_ex = reg_info_ex + "IPAddress0="+ m_strRegiP+STRITEM_TAG_END;
    reg_info_ex = reg_info_ex + "MACCount=1" + STRITEM_TAG_END;
    reg_info_ex = reg_info_ex + "IPCount=1"  + STRITEM_TAG_END;

    /*check again while in app start we lost the devid*/
    if(m_strDevid.empty()) {
        char buf[256]={0};
        get_device_indetify(buf, 256, m_strRegMac);
        m_strDevid = buf;
    }
    if(m_strDevid.empty()) {
        LOG_ERR("Device ID is null we try our best");
        return false;
    }
    reg_info_ex = reg_info_ex + "DeviceIdentify=" + m_strDevid + STRITEM_TAG_END;
    reg_info_ex = reg_info_ex + reginfo;
    reg_info_ex.append("\n");

    char computer_name[256]= {0};
    gethostname(computer_name, 256);
    reg_info_ex = reg_info_ex + "ComputerName="+computer_name+STRITEM_TAG_END;

    char os[1204]={0};
    extern int get_os_type(char *buf,int bufsize,bool hasR);
    get_os_type(os,1204,false);
    reg_info_ex = reg_info_ex + "EdpRegVersion=" + CLIENT_VERSION  + STRITEM_TAG_END;
    reg_info_ex = reg_info_ex + "OSVersion=" + os+ STRITEM_TAG_END;
    reg_info_ex = reg_info_ex + "OSType=MacOS"+ STRITEM_TAG_END;

    LOG_DEBUG("reg = %s",reg_info_ex.c_str());


    if(!m_NetEngine.sendnetmsg(S_CMD_USER_REGISTER, 
                (void *)(reg_info_ex.c_str()),reg_info_ex.length())) {
        LOG_ERR("Send Reg info to neteng error");
        return false;
    } 
    return true;
}

bool CEdpApp::onLogon(int id, bool btray,const char * pUser) {
    return CVCFApp::onLogon(id, btray, pUser);
}

void CEdpApp::onLogout(int id) {
    return CVCFApp::onLogout(id);
}

void CEdpApp::do_protect() {
    return;
    /*
    //return;
    char preload_path[] = "/etc/ld.so.preload";
    char lib_path[] = "/opt/edp_vrv/lib/libunlink.so";
    char read_buf[1024] = {0};
    bool change_flag = false;
    FILE *fp = fopen(preload_path, "r+");
    if(fp == NULL) {
        fp = fopen(preload_path, "w+");
    }
    if(fp == NULL) {
        return;
    }
    char *pread = fgets(read_buf, sizeof(read_buf) - 1, fp);
    if(pread == NULL) {
        fputs(lib_path, fp);
        change_flag = true;
    } else if(strncmp(lib_path, pread, strlen(lib_path)) != 0) {
        fclose(fp);
        fp = fopen(preload_path, "w+");
        if(fp == NULL) {
            return;
        }
        fclose(fp);
        fp = fopen(preload_path, "r+");
        if(fp == NULL) {
            return;
        }
        fputs(lib_path, fp);
        change_flag = true;
    } 
    fclose(fp);
    if(change_flag) {
        (void)system("ldconfig");
    }
    */
}

#if 0
static void _kill_mismatch_dog(int uid) {
    std::vector<active_process_info_t> pinfo_list;
    std::vector<int> may_2_kill;
    if(YCommonTool::get_process_status_ext(TRAY_DOG, pinfo_list) > 0) {
        for(size_t i = 0; i < pinfo_list.size(); i++) {
            if(pinfo_list.at(i).uid == uid) {
                may_2_kill.push_back(pinfo_list.at(i).pid);
                continue;
            }
            kill(pinfo_list.at(i).pid, SIGKILL);
        }
    }
    /*keep one*/
    if(may_2_kill.size() > 1) {
        for(size_t i = 0; i < may_2_kill.size() - 1; i++) {
            kill(may_2_kill.at(i), SIGKILL);
        }
    }
}

static void check_kill_ui_dog_pid_match() {
    std::vector<active_user_info_t> curr_user_info;
    /*don't skip gdm user*/
    if(!YCommonTool::get_active_user(curr_user_info, false)) {
        return;
    }
    for(size_t i = 0; i < curr_user_info.size(); i++) {
        if(curr_user_info.at(i).user_name == "gdm") {
            system("pkill vas_systray; pkill vas_ui_watchdog;");
            LOG_DEBUG_IMP("Send to systray to quit");
        } else {
            _kill_mismatch_dog(curr_user_info.at(i).uid);
        } 
    }
}
#endif
