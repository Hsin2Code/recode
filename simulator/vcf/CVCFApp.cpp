/*
 * CVCFApp.cpp
 *
 *  Created on: 2014-12-1
 *      Author: sharp
 */

#include "CVCFApp.h"
#include "common/Commonfunc.h"
#include "VCFCmdDefine.h"
#include "vrcport_tool.h"
#include "CSoftInstallHelper.h"
#include <string.h>
#include "CDeviceinfoHelper.h"
#include "../include/Netko.h"
#include "../include/cli_config.h"
#include <arpa/inet.h>
#include <stdint.h>
#include <iostream>

#ifdef __APPLE__
#include <libgen.h>
#endif


/*in ONLINE_DEAL_CTRL not be here*/
//extern  std::string   g_closeNetPromptFile ;
std::string   g_closeNetPromptFile = "closeNetPromptFile";

extern  int  get_os_type(char *buf,int bufsize,bool hasR);
const char * g_watchv_name = "watchE";

unsigned int g_srvWebPort = 8080 ;
static void  get_srvWebPort() {
    FILE * fp = fopen("webport","r");
    if(fp==NULL) {
        return ;
    }
    char port[100]="";
    fgets(port,100,fp);
    fclose(fp);
    g_srvWebPort = atoi(port);
}

void  rc_prelog(const  char * plog) {
    char szTime[23]="";
    YCommonTool::get_local_time(szTime);
    FILE * fp = fopen("prelog","a+");
    if(fp) {
        fprintf(fp,"%s >> %s\n",szTime,plog);
        fclose(fp);
    }
}

bool  ldb_tbl_remove(CYlocaldb & db ,en_localTbl  refT , void * buffer , int len) {
    int * pID = (int *)buffer ;
    if(len == 0) {
        db.remove(refT,(const char *)NULL);
    } else {
        int   count = len /sizeof(unsigned int);
        char  szfilter[32] = "" ;
        for(int i = 0 ; i < count ; i++) {
            sprintf(szfilter,"id = %d",*(pID+i));
            db.remove(refT,szfilter);
        }
    }
    db.commit();
    return true ;
}

///进程间通讯使用
bool     IMC_msg_helper(unsigned short cmd , PVOID buffer , int len , void  * param,unsigned int id) {
    CVCFApp * pApp = (CVCFApp *)param ;
    return pApp->IMC_msg_proc(cmd,buffer,len,id);
}

///上报日志通讯使用
bool     Upload_msg_helper(unsigned short cmd , PVOID buffer , int len , void  * param,unsigned int id) {
    CVCFApp * pApp = (CVCFApp *)param ;
    return pApp->Upload_msg_proc(cmd,buffer,len,id);
}

///策略执行消息通道
bool     policy_msg_helper(unsigned short cmd , PVOID buffer , int len , void  * param,unsigned int id) {
    CVCFApp * pApp = (CVCFApp *)param ;
    return pApp->Policy_msg_proc(cmd,buffer,len,id);
}

///=======================================================================
static  int   g_tipsid = 10000 ;
//创建注册的XML
int   buildXml_tip(tag_GuiTips * tip,char * xml);
//创建提示的XML
void  buildXml_reg(char * xml);
//========================================================================

void checkWatchV() {
    char buf[512]={0};
    char ps[128]={0};
    sprintf(ps, "pgrep %s", g_watchv_name);
    FILE *fp = popen(ps, "r");
    if(NULL == fp) {
        return ;
    }
    fgets(buf, sizeof(buf) - 1, fp);
    pclose(fp);

    if(strlen(buf)==0) {
        char cmd[128] = "./";
        strcat(cmd, g_watchv_name);
        strcat(cmd,"&");
        system(cmd);
    }
    return ;

}
CVCFApp::CVCFApp() {
    m_bisRegister = false ;
    m_nIMCChannelID = -1   ;
    m_bofflineAlaways = false ;
    m_bcurOffline = false ;
    m_bCloseNetFromSrv = false ;

    m_nlogChannelID = -1   ;
    m_nUploadTimer = -1;
    m_nUpdatePolicyTimer = -1 ;
    m_nPolicyExeChannle = -1;
    m_nUpdatePolicyTimer = -1;
    memset(m_policyTimer,-1,sizeof(m_policyTimer));
    memset(m_bTimerLoop,0,sizeof(m_bTimerLoop));
    memset(m_bCloseNet,0,sizeof(m_bCloseNet));
    memset(m_badvCfgEnable,1,sizeof(m_badvCfgEnable));

    m_nTipsGui = -1;
    m_nHistoryTipGui = -1 ;
    m_nNeedRetTips = -1 ;
    m_bTimerForCloseNet = -1;
    m_nHeartBeatTimer = -1 ;
    m_nCheckWatchv = -1 ;

    m_startTime = YCommonTool::get_Startsec();


    ///根据不同的策略设置定时器是否循环
    m_bTimerLoop[HTTP_VISIT_CTRL] = true ;
    m_bTimerLoop[POLICY_AUTO_SHUTDOWN] = true ;
    m_bTimerLoop[PROCESS_CTRL] = true;
    m_bTimerLoop[POLICY_SEC_BURN] = true;
    m_bTimerLoop[FILE_OP_CTRL] = true;
    m_bTimerLoop[SERVICE_CTRL] = true;
    m_bTimerLoop[RUN_INFOMATION] = true;
    m_bTimerLoop[HTTP_ACCESS_CTRL] = true;
    m_bTimerLoop[SOFT_INSTALL_CTRL] = true ;
    m_bTimerLoop[IPMAC_BIND_CTRL] = true ;
    m_bTimerLoop[ONLINE_DEAL_CTRL] = true ;
    m_bTimerLoop[SOFT_DOWN_CTRL] = true;
    m_bTimerLoop[DEV_INSTALL_CTRL] = true;
    m_bTimerLoop[UDISK_ACT_CTRL] = true;
    m_bTimerLoop[USER_RIGHT_POLICY] = true;
    m_bTimerLoop[FILE_CHECKSUM_EDIT] = true;
    m_bTimerLoop[SYSTEM_CONN_MONITOR] = true;
    m_bTimerLoop[CONNECT_GATEWAY_AFFIRM] = true;
    m_bTimerLoop[POLICY_HEALTHCHECK] = true;
    m_bTimerLoop[NET_BD_CHK] = true;
    m_bTimerLoop[PROTOCOL_FIREWALL_CTRL] = true;
    m_bTimerLoop[POLICY_CLIENT_SET] = true;
    m_bLoginDeskTop = 0 ;

    m_bisSave = false ;
    m_bwinSrv = true ;
    ///默认监听端口
    m_strlistenPort = "22105" ;
}

CVCFApp::~CVCFApp() {

}

bool CVCFApp::registerEvent(enNotifyerEvent event , pNotify_func pfunc) {
    return m_eventNotifyer.registerEvent(event,pfunc);
}

void CVCFApp::UnregisterEvent(enNotifyerEvent event , pNotify_func pfunc) {
    m_eventNotifyer.UnregisterEvent(event,pfunc);
}

bool CVCFApp::InitInstances()
{
    std::string str ;
    get_loginUser(str);
    str = "当前登录用户: "+ str + "\n" ;
    rc_prelog(str.c_str());
    if(getlogin()) {
        rc_prelog(getlogin());
    }
    get_srvWebPort();
    /**
     *  日志初始化
     */
    if(!m_runlog.init(YCommonTool::enlog_trace,"runlog",getMoudlepath().c_str(),false)){
        rc_prelog("runlog 打开失败\n");
        return false ;
    }

    for(int i = enlog_debug ; i < enlog_count ; i++) {
        if(!m_log[i].init((enlogType)i,logTypeName[i].c_str(),getMoudlepath().c_str(),false)) {
            char szlog[128]="";
            sprintf(szlog,"%s日志初始化失败\n",logTypeName[i].c_str());
            loglog(szlog);
            return false ;
        }
    }

    /*父类初始化*/
    if(!CYApp::InitInstances()) {
        m_runlog.log_log("父类InitInstances失败");
        return false ;
    }

    /**
     * 用户权限 -》 工作路径 -》本地环境检查 >>系统配置读取
     */
    if(!checkandset_Env()) {
        m_runlog.log_log("运行环境检测失败\n");
        return false  ;
    }

    /**
     *  本地配置获取
     */
    if(!get_Localconfig()) {
        m_runlog.log_log("获取本地配置失败\n");
        return false  ;
    }

    /**
     * 进去APP主线程执行操作,同步进行。
     */
    if(!startAllCmdChannel()) {
        m_runlog.log_log("startAllCmdChannel 消息处理通道启动失败\n");
        return false ;
    }

    /**
     * 启动网络管理
     */
    if(!m_NetEngine.create_Engine(static_cast<INetEngineSinkinterface *>(this))) {
        m_runlog.log_log("网络管理启动失败\n");
        return false ;
    }

    ///启动进程间通讯服务器
    if(!m_imcSrv.Create("sharp.young",static_cast<IMCSrvsinkinterface *>(this))) {
        m_runlog.log_log("进程通讯服务器启动失败\n");
        return false ;
    }

    ///启动守护进程
    checkWatchV();

    rc_prelog("VCF_CMD_MAIN_SRUNING\n");
    return sendto_Main(VCF_CMD_MAIN_SRUNING,NULL,0) ;
}

bool  CVCFApp::get_lconfig(en_lcfg_key key , std::string & val) {
    switch(key) {
    case lcfg_regip: {
        val = YCommonTool::get_ip(m_strRegNic);//m_strRegiP ;
        break ;
    }
    case lcfg_regmac: {
        val = m_strRegMac ;
        break ;
    }
    case lcfg_devid: {
        val = m_strDevid ;
        break ;
    }
    case lcfg_srvip: {
        val  = m_strSrvIp ;
        break ;
    }
    case lcfg_regnic: {
        val = m_strRegNic ;
        break ;
    }
    case lcfg_listenPort: {
        val = m_strlistenPort ;
        break ;
    }
    case lcfg_reguiStr: {
        val = m_strReginfo ;
        break ;
    }
    case lcfg_get_server_time: {
        val = get_server_time();
        break;
    }
    default:
        return false ;
    }
    return true ;
}

bool  CVCFApp::set_lconfig(en_lcfg_key key , const std::string & val) {
    switch(key) {
    case lcfg_listenPort: {
        m_strlistenPort = val;
        break ;
    }
    default:
        return false ;
    }
    return true ;
}

bool  CVCFApp::startAllCmdChannel() {
    /**
     * 启动进程间消息处理通道
     */
    std::string  strMc = "进程间通讯";
    m_nIMCChannelID = registerDispatcher(strMc.c_str()
                                         ,IMC_msg_helper
                                         ,1,this);
    if(m_nIMCChannelID < 0) {
        m_runlog.log_log("进程间通讯通道启动失败\n");
        return false ;
    }

    /**
     *   因为本地数据库实例一份，所以此通道启动一个线程，避免竞争。
     */
    strMc = "本地数据库处理";
    m_nlogChannelID = registerDispatcher(strMc.c_str()
                                         ,Upload_msg_helper
                                         ,1,this);
    if(m_nlogChannelID < 0) {
        m_runlog.log_log("本地数据库通道启动失败\n");
        return false ;
    }

    /**
     * 策略处理通道， 启动5个线程执行。 所有消息都由消息通道线程调度执行。
     */
    strMc = "策略处理";
    m_nPolicyExeChannle = registerDispatcher(strMc.c_str()
                                             ,policy_msg_helper
                                             ,5,this);
    if(m_nPolicyExeChannle < 0) {
        m_runlog.log_log("策略处理通道启动失败\n");
        return false ;
    }

    return true ;
}

void  CVCFApp::stopAllcmdChannel() {
    stopDispatcher(m_nIMCChannelID);
    stopDispatcher(m_nPolicyExeChannle);
    stopDispatcher(m_nlogChannelID);
}

///发送审计日志到Upload_msg_proc执行上传或者记录到本地
bool  CVCFApp::sendto_Uplog(unsigned short cmd,void * pdata, int len,bool bsync) {
    if(m_nlogChannelID < 0) return false ;
    if(bsync) {
        return sendmsg(m_nlogChannelID,cmd,pdata,len);
    } else
        return postmsg(m_nlogChannelID,cmd,pdata,len);
}

///发送消息到IMC_msg_proc 执行
bool  CVCFApp::sendto_Imc(unsigned short cmd,void * pdata, int len,bool bsync) {
    if(m_nIMCChannelID < 0) return false ;
    if(bsync) {
        return sendmsg(m_nIMCChannelID,cmd,pdata,len);
    }
    else
        return postmsg(m_nIMCChannelID,cmd,pdata,len);
}

///发送消息到主线程通道
bool  CVCFApp::sendto_Main(unsigned short cmd,void * pdata, int len,bool bsync) {
    if(bsync) {
        return sendmsg(m_nMainChannel,cmd,pdata,len);
    }
    else
        return postmsg(m_nMainChannel,cmd,pdata,len);
}

///发送消息到策略处理通道
bool  CVCFApp::sendto_pl4Exec(unsigned short cmd,void * pdata, int len,bool bsync) {
    if(m_nPolicyExeChannle < 0) return false;
    if(bsync) {
        return sendmsg(m_nPolicyExeChannle,cmd,pdata,len);
    } else
        return postmsg(m_nPolicyExeChannle,cmd,pdata,len);
}

bool  CVCFApp::IMC_msg_proc(unsigned short cmd , PVOID buffer , int len,unsigned int id)  {
    switch(cmd) {
        ///测试进程
    case VCF_CMD_MCMSG_TEST: {
        std::string str = getMoudlepath() ;
        str = "/home/sharp/workspace/testImc/Release/testImc" ;
        m_imcSrv.exec_Cli(str.c_str(),NULL) ;
        break;
    }
    case VCF_CMD_GUI_TIPS_RET: {
        std::string  xml = "" ;
        int    tipsid = 0 ;
        {
            std::map<int,std::string>::iterator iter = m_tipXmlMap.begin();
            if( iter != m_tipXmlMap.end() ) {
                xml = iter->second ;
                tipsid = iter->first ;
                m_tipXmlMap.erase(iter);
            }
        }
        if(xml.length()) {
            tag_C2S_TipsUpdate uptips;
            uptips.tipsid = tipsid;
            strcpy(uptips.xml,xml.c_str());
            m_imcSrv.pub_msg_4tray(MC_CMD_C2S_TIPSUPDATE,&uptips,sizeof(uptips)-sizeof(uptips.xml) + strlen(uptips.xml));
        } else {
            m_nNeedRetTips = -1;
        }
        break ;
    }
        ///注册界面
    case VCF_CMD_REGISTER_GUI: {
        std::string str = getMoudlepath() ;
        str = str + EDP_GUIAPP_REGISTER;
        char xml[512] = "";
        buildXml_reg(xml);
        sleep(1);/*sleep 1s,waiting for regist.xml to be ready.*/
        m_nRegGui = m_imcSrv.exec_Cli(str.c_str(),xml) ;
        break ;
    }
        ///提示界面
    case VCF_CMD_GUI_TIPS: {
        tag_GuiTips * pTips = (tag_GuiTips *)buffer ;
        ///没有进入桌面环境
        if(m_bLoginDeskTop <= 0) {
            g_GetlogInterface()->log_trace("提示框 没有进入桌面环境 返回");
            if(pTips->pfunc) { ///由返回值的
                (*(pTips->pfunc))(0);
            }
            break ;
        }
        log_trace("桌面环境，调用GUI\n");

        tag_C2S_TipsUpdate uptips;
        uptips.tipsid = buildXml_tip(pTips,uptips.xml);
        ///历史提示框
        if(pTips->pfunc) { ///需要返回值的，一个一个来。
            {
                CLockHelper helper(&m_funcmapLocker);
                m_funcMap[uptips.tipsid] = pTips->pfunc ;
            }
            if(m_nNeedRetTips == -1) {
                m_nNeedRetTips = uptips.tipsid ;
                char log[128]="";
                sprintf(log,"tips = %d\n",m_nNeedRetTips);
                log_trace(log);
                m_imcSrv.pub_msg_4tray(MC_CMD_C2S_TIPSUPDATE,&uptips,sizeof(uptips)-sizeof(uptips.xml) + strlen(uptips.xml)+1);
            } else {
                char log[128]="";
                sprintf(log,"下次调用启动 tips = %d\n",m_nNeedRetTips);
                log_trace(log);
                m_tipXmlMap[uptips.tipsid] = uptips.xml ;
            }
        } else {
            char log[512]="";
            if(strlen(uptips.xml) < 384) {
                sprintf(log,"没有返回值，直接调用  %s\n",uptips.xml);
                log_trace(log);
            }

            if(!m_imcSrv.pub_msg_4tray(MC_CMD_C2S_TIPSUPDATE,&uptips,sizeof(uptips)-sizeof(uptips.xml) + strlen(uptips.xml)+1)) {
                sprintf(log,"发送错误 %d\n",errno);
                log_trace(log);
            }
        }
        break ;
    }
    }

    return true ;
}

void  CVCFApp::on_Tipui(unsigned short cmd,void * pbuffer,int len) {
    switch(cmd) {
    case MC_CMD_C2S_TIPSRETURN: {
        tag_C2S_TipsReturn * pRet = (tag_C2S_TipsReturn *)pbuffer ;
        pTips_retfunc pfunc = NULL ;
        char log[128] = "";
        sprintf(log,"提示框返回 tip = %d",pRet->tipsid);
        log_trace(log);
        {
            CLockHelper locker(&m_funcmapLocker);
            std::map<int,pTips_retfunc>::iterator iter = m_funcMap.find(pRet->tipsid);
            if(iter != m_funcMap.end()) {
                pfunc = iter->second ;
                m_funcMap.erase(iter);
            }
        }
        sprintf(log,"提示框返回 tip = %d, pfunc = %p",pRet->tipsid, pfunc);
        log_trace(log);
        if(pfunc) {
            (*pfunc)(pRet->signret);
        }
        m_imcSrv.sendData(MC_CMD_S2C_UNKNOWN,NULL,0);
        ///告诉下一个对话框启动
        sendto_Imc(VCF_CMD_GUI_TIPS_RET,NULL,0);
        break;
    }
    }
}

bool  CVCFApp::on_Update_pGeneral(std::string & pkt_info,std::string & str_pGeneral) {
    std::vector<tag_vrv_policyGen>   _array ;

    if(get_policylist_fromGeneral(str_pGeneral,_array)) {
        log_trace("获取策略概况，策略数不为零\n");
        ///对所有的策略进行类型进行转化
        {
            for(int i = 0 ; i < (int)_array.size() ; i++) {
                _array[i].type = m_policyMgr.typefromTartget(_array[i].func);
            }
        }
        /**
         * 对策略概况进行过滤，区分出要下载的和要停止的策略
         */
        std::vector<unsigned int> delArray ;     ///删除的策略
        std::vector<unsigned int> unApplyArray ; ///取消的策略
        std::map<unsigned int ,int> crcmap ;
        std::map<unsigned int ,int> crcmapEx ;
        m_policyMgr.get_CrcMap(crcmap);
        m_policyMgr.get_CrcMapEx(crcmapEx);
        filter_PolicyGen(crcmap,crcmapEx,_array,delArray,unApplyArray);

        ///取消删除的策略
        if(unApplyArray.size() || delArray.size()) {
            unsigned int  del[512] = {0};
            for(int i = 0 ; i < (int)unApplyArray.size() ; i++) {
                del[i] = unApplyArray[i];
            }

            char szlog[128]="";
            sprintf(szlog,"删除：%lu, 取消删除：%lu\n",delArray.size(),unApplyArray.size());
            log_trace(szlog);

            tag_PApplyChange change ;
            change.pDelArray = &delArray ;
            change.pDelUnApply = &unApplyArray ;
            sendmsg(getMainChannelID(),VCF_CMD_POLICY_UNAPPLY,&change,sizeof(tag_PApplyChange));
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

            log_trace(strPolicylist.c_str());

            std::string app_info = pkt_info + strPolicylist + strflgList ;

            tag_S_GetPlockyGEN getGen ;
            std::string  policy_str;
            getGen.pSendStr = &app_info;
            getGen.pGetStr =  &policy_str;
            if(!m_NetEngine.sendnetmsg(S_CMD_GET_POLICY_INFO,&getGen,sizeof(getGen))) {
                log_error("m_NetEngine.sendnetmsg(S_CMD_GET_POLICY_INFO,&getGen,sizeof(getGen) 失败\n");
            } else {
                /*TODO:1.NEED CODE CONVERT HERE FROM gb2312 to utf8
                 *     2.add server detect
                 *     3.TMP TREAT ALL AS WINSERVER*/
                std::string code_convert_content = "";
#if 0
                if(g_GetlcfgInterface()->is_WinSrv()) {
                    int dst_buf_len = policy_str.length() * 2 + 1;
                    int org_buf_len = dst_buf_len;
                    char *dst_buf = (char *)malloc(dst_buf_len);
                    memset(dst_buf, 0, dst_buf_len);
                    /*utf-8 3 byte can encode need more space than gb2312*/
                    extern int code_convert(const char *from_charset,
                                            const char *to_charset,char *inbuf,int inlen,char *outbuf,int & outlen);
                    (void)code_convert("gb2312","utf-8//IGNORE",
                                       (char *)policy_str.c_str(), policy_str.length(),
                                       dst_buf, dst_buf_len);
                    if((org_buf_len - dst_buf_len) >= policy_str.length()) {
                        code_convert_content.append(dst_buf);
                    }
                    if(dst_buf) {
                        free(dst_buf);
                        dst_buf = NULL;
                    }

                }
#endif
                if(!On_Update_Policy(&_array,
                                     code_convert_content.empty() ? policy_str : code_convert_content)) {
                    log_error("!OnUpdatePolicy(policy_str) 失败\n");
                }
            }
        }
    } else {
        log_trace("获取策略概况，策略数为零\n");
        ///停止所有的策略
        sendto_Main(VCF_CMD_POLICY_UNAPPLY_ALL,NULL,0);
    }

    m_policyMgr.set_Updateing(false);
    return true ;
}

///策略升级
bool  CVCFApp::on_Update_pGeneral(){
    log_trace("start更新策略====================================");
    ///获取附加上报信息
    string app_sys_info;
    if(m_strRegNic.length() == 0){
        findRegNic();
    }
    string ip = YCommonTool::get_ip(m_strRegNic) ;
    if(!get_pkt_app_info(app_sys_info,m_strRegNic,ip,m_strRegMac)) {
        log_error("get_pkt_app_info is failed\n");
        m_policyMgr.set_Updateing(false);
        g_GetlogInterface()->log_trace("获取策略概况失败,结束更新策略====================================\n");
        return true ;
    }
    g_GetlogInterface()->log_trace(app_sys_info.c_str());
    /**
     * 先获取概况，然后比对，再判断是否需要更新
     */
    tag_S_GetPlockyGEN getGen ;
    std::string  str_pGeneral ;
    getGen.pSendStr = &app_sys_info;
    getGen.pGetStr = &str_pGeneral ;
    if(!m_NetEngine.sendnetmsg(S_CMD_GET_POLICY_GENERAL,&getGen,sizeof(getGen))) {
        log_error("获取策略概况失败 ");
        m_policyMgr.set_Updateing(false);
        g_GetlogInterface()->log_trace("获取策略概况失败,结束更新策略====================================\n");
        return true ;
    }
    g_GetlogInterface()->log_trace(str_pGeneral.c_str());
    return on_Update_pGeneral(app_sys_info,str_pGeneral);
}

///处理策略初始化
bool  CVCFApp::on_policy_Init(void * buffer ,int len) {
    tag_PolicyExecinit  * pinit = (tag_PolicyExecinit  *)buffer ;
    if(pinit->type >= en_policytype_count) {
        return false ;
    }
    policy_pInit pfunc = g_PolicyExecHelper[pinit->type].pInit;
    if(pfunc == NULL) {
        return false ;
    }
    ///执行初始化
    if(!(*pfunc)()) {
        return false ;
    }
    ///高级状态置为TRUE
    m_badvCfgEnable[pinit->type] = true ;
    return  sendto_Main(VCF_CMD_POLICYEXECINIT_SUCC,pinit,sizeof(tag_PolicyExecinit));
}

///处理策反初始化
bool  CVCFApp::on_Policy_Uninit(void * buffer ,int len) {
    int  * pType = (int *)buffer ;

    char _buf[128] = {0};
    sprintf(_buf, "policy type : %d", *pType);
    log_trace(_buf);

    int stat = get_pl4Status(*pType);
    if(stat != pstat_uinit && stat != pstat_noexsit) {
        log_trace("policy none eixtst error return ");
        return false ;
    }

    m_policyMgr.update_policyStat((enPolicytype)*pType,pstat_noexsit);
    policy_pUninit pfunc = g_PolicyExecHelper[*pType].pUninit;
    if(pfunc == NULL) {
        log_trace("======== >policy none eixtst error return ");
        return false ;
    }

    log_trace("call uninit begin");
    (*pfunc)();
    log_trace("call uninit end");

    return true ;
}

///处理策略执行
bool  CVCFApp::on_Policy_Exec(void * buffer ,int len) {
    tag_CallPolicyExec * pExec = (tag_CallPolicyExec *)buffer ;
    if(pExec->pType >= en_policytype_count) {
        return false ;
    }
#if 0
    /*clear fail times*/
    char zbuf[128] = {0};
    sprintf(zbuf, "%s %d", "reset dismiss_cnt for policy : ", pExec->pType);
    log_trace(zbuf);
    m_policyMgr.set_dismiss_cnt((enPolicytype)pExec->pType, 0);
#endif
    char log[128]="";
    sprintf(log,"on_Policy_Exec = %d",pExec->pType);
    log_trace(log);
    ///如果不是空闲状态，取消执行
    en_policy_stat stat = (en_policy_stat)get_pl4Status(pExec->pType) ;
    if(stat != pstat_willrun
       && stat != pstat_free) {
        return false ;
    }
    m_policyMgr.update_policyStat((enPolicytype)pExec->pType,pstat_runing);

    sprintf(log,"on_Policy_Exec = %d  设置状态",pExec->pType);
    log_trace(log);

    policy_pworker pworker = g_PolicyExecHelper[pExec->pType].pworker;
    if(pworker == NULL) {
        return false ;
    }

    ///获取策略当前执行的策略
    CPolicy * pPolicy =  m_policyMgr.get_CurExecpolicy((enPolicytype)pExec->pType);
    if(pPolicy == NULL) {  ///此策略没有被应用
        ///呼叫停止
        sendto_Main(VCF_CMD_CALL_POLICY_STOP,&pExec->pType,sizeof(pExec->pType));
        sprintf(log,"on_Policy_Exec = %d  pPolicy == NULL",pExec->pType);
        log_trace(log);
        return false ;
    }

    bool bpass = check_policy_validate(pPolicy);
    if(bpass != m_badvCfgEnable[pExec->pType]) {
        ///发送高级配置状态改变消息
        m_eventNotifyer.sendEvent(enNotifyer_policyAdvcfg_statChange,&bpass);
        m_badvCfgEnable[pExec->pType] = bpass ;
    }
    ///检查策略高级设置
    if(bpass) {
        g_GetlogInterface()->log_trace("高级设置检测通过\n");
        ///执行策略
        if(!(*pworker)(pPolicy,NULL)) {
            tag_pExecFailed failed ;
            failed.type = pExec->pType ;
            failed.err =  policy_noexsit ;
            sendto_Main(VCF_CMD_POLICYEXEC_FAILED,&failed,sizeof(failed));
        }
    } else {
        g_GetlogInterface()->log_trace("高级设置检测 未通过\n");
    }


    if(get_pl4Status(pExec->pType) == pstat_runing) {
        m_policyMgr.update_policyStat((enPolicytype)pExec->pType,pstat_free);
    } else {
        ///呼叫停止
        /*force status to free*/
        m_policyMgr.update_policyStat((enPolicytype)pExec->pType,pstat_free);
        sendto_Main(VCF_CMD_CALL_POLICY_STOP,&pExec->pType,sizeof(pExec->pType));
    }

    return true;
}

///获取软硬件资产并上报
bool  CVCFApp::on_Get_Asset() {
    CSoftinstallmap  oldsoftmap;
    std::vector<tag_SoftInstallEx> vt_add ; //增加软件列表
    std::vector<tag_SoftInstallEx> vt_modify; //改变的软件列表
    std::vector<tag_SoftInstallEx> vt_del ;   //删除的软件列表

    CDeviceInfoMap   oldhardmap ;
    CDeviceInfoMap   map_add ;
    CDeviceInfoMap   map_modify;
    CDeviceInfoMap   map_del ;

    ///获取数据库中信息
    tag_ldbGetAsset  get ;
    get.pSoftMap = &oldsoftmap ;
    get.pHardMap = &oldhardmap ;
    sendto_Uplog(VCF_CMD_LDB_GET_ASSET,&get,sizeof(get),true);

    ///先处理软件资产
    CSoftInstallHelper install_helper ;
    if(install_helper.Init()) {
        install_helper.Check(oldsoftmap,vt_add,vt_del,vt_modify);

        tag_S_Soft_Asset send ;
        send.pAdd = &vt_add ;
        send.pDel = &vt_del ;
        send.pModify = &vt_modify ;
        if(oldsoftmap.size() == 0) {
            send.bFirst = true ;
        } else {
            send.bFirst = false ;
        }

        if(vt_add.size() || vt_del.size() || vt_modify.size()) {
            if(!m_NetEngine.sendnetmsg(S_CMD_SOFT_ASSET,&send,sizeof(send))) {
                log_error("m_NetEngine.sendnetmsg(S_CMD_SOFT_ASSET,&send,sizeof(send)  failded!");
            }

            tag_ldbUpdatasAsset update ;
            update.pAdd = &vt_add ;
            update.pDel = &vt_del ;
            update.pModify = &vt_modify ;
            ///更新到数据库
            sendto_Uplog(VCF_CMD_LDB_UPDATA_SASSET,&update,sizeof(update),true);
        }
    } else {
        log_error("install_helper.Init()  failded!");
    }


    ///处理硬件资产
    CDeviceinfoHelper  hard_Helper ;
    if(hard_Helper.init()) {
        CDeviceInfoMap   oldhardmap1 =  oldhardmap;
        hard_Helper.check(oldhardmap,map_add,map_del,map_modify);

        tag_S_Hard_Asset sendEx;
        sendEx.pAdd = &map_add ;
        sendEx.pDel = &map_del ;
        sendEx.pModify = &map_modify ;
        sendEx.pFrontstr = &hard_Helper.getfront();
        sendEx.pOld = &oldhardmap1 ;
        sendEx.pMap = &hard_Helper.getMap();
#if 1
        printf("---------------------> %lu %lu %lu\n", map_add.size(), map_del.size(), map_modify.size());
#endif

        if(map_add.size() || map_del.size() || map_modify.size()) {

            if(!m_NetEngine.sendnetmsg(S_CMD_HARD_ASSET,&sendEx,sizeof(sendEx))) {
                log_error("m_NetEngine.sendnetmsg(S_CMD_HARD_ASSET,&send,sizeof(send)  failded!");
            }

            tag_ldbUpdatasAsset update ;
            update.pAdd = &map_add ;
            update.pDel = &map_del ;
            update.pModify = &map_modify ;
            ///更新到数据库
            sendto_Uplog(VCF_CMD_LDB_UPDATA_HASSET,&update,sizeof(update),true);
        }
    } else {
        log_trace("hardware init failed");
    }
    return true ;
}


/**
 * 策略执行消息通道
 */
bool  CVCFApp::Policy_msg_proc(unsigned short cmd , PVOID buffer , int len,unsigned int id) {
    switch(cmd) {
	///获取上报资产信息
    case VCF_CMD_GET_ASSEET: {
        return on_Get_Asset();
    }
	///策略更新消息
    case  VCF_CMD_POLICY_UPDATA_GENERAL: {
        return on_Update_pGeneral();
    }
	///策略执行
    case  VCF_CMD_CALL_POLICYEXEC : {
        return on_Policy_Exec(buffer,len);
    }
    case  VCF_CMD_POLICY_EXEC_INIT: {
        return on_policy_Init(buffer,len);
    }
    case VCF_CMD_POLICY_EXEC_UINIT: {
        return on_Policy_Uninit(buffer,len);
    }
    case VCF_CMD_HEART_BEAT: {
        return on_Heart_Beat();
    }
    }
    return true ;
}

///
bool  CVCFApp::on_Heart_Beat() {
    return m_NetEngine.sendnetmsg(S_CMD_HEART_BEAT,NULL,0);
}


bool CVCFApp::detect_vas_server(const std::string &server_ip) {
    return m_NetEngine.sendnetmsg(S_CMD_DETECT_SERVER,
                                  (void *)&server_ip, (int)server_ip.length());
}

///启动本地策略,再程序启动的时候调用
bool  CVCFApp::startLocalPolicy() {
    for(int i = 0 ; i < en_policytype_count; i++) {
        if(m_policyMgr.get_policyStat((enPolicytype)i) == pstat_rdy) {
            if(!start_pl4(i,g_PolicyExecHelper[i].interval,!m_bTimerLoop[i])) {
                log_error("启动策略定时器失败\n");
                return false ;
            }
        }
    }
    return true ;
}

///策略更新处理函数
bool  CVCFApp::On_Update_Policy(void * pGenArray,std::string & content) {
    std::vector<tag_vrv_policyGen> * pArray = (std::vector<tag_vrv_policyGen> *)pGenArray;
    std::vector<tag_vrv_policyGen> & _array = *pArray ;
    int pos = 0 ;
    std::string  xml ;

    char buffer[2048] = "";
    tag_LDBexec * pExec = (tag_LDBexec *)buffer ;
    pExec->tbl  = tbl_policy ;
    pExec->cbop = dbop_add ;
    T_policy * pPolicy = (T_policy *)pExec->data;
    pExec->cnt = 0 ;

    std::vector<std::string> xmlvt ;
    for(int i = 0 ; i < (int)_array.size() ; i++) {
        if(get_PolicyContent(i,content,xml,pos)) {
            T_policy & tmp =  *(pPolicy+pExec->cnt);
            tmp.pid = _array[i].id;
            tmp.type = m_policyMgr.typefromTartget(_array[i].func);
            ///判断是否找不到类型
            if(tmp.type == en_policytype_count) {
                log_error("OnUpdatePolicy - if(tmp.type == en_policytype_count)\n");
                continue ;
            }

            tmp.crc = _array[i].crc ;
            xmlvt.push_back(xml);
            tmp.pContent = xmlvt[xmlvt.size()-1].c_str();
            log_trace(tmp.pContent);

            en_policy_stat cur_stat = m_policyMgr.get_policyStat((enPolicytype)tmp.type);

            CPolicy  * p =  m_policyMgr.importFromXml(tmp.pid,tmp.type,tmp.crc,tmp.pContent);
            if(p == NULL) {
                std::string error = "解析XML失败，该策略丢弃 xml = ";
                error = error + tmp.pContent ;
                log_error(error.c_str());
                continue ;
            }
            p->set_id(tmp.pid);
            p->set_crc(tmp.crc);

            cur_stat = m_policyMgr.get_policyStat((enPolicytype)tmp.type);

            ///由不存在进入准备状态，启动
            if(cur_stat == pstat_rdy) {
                ///启动策略执行
                if(!start_pl4(tmp.type,g_PolicyExecHelper[tmp.type].interval,!m_bTimerLoop[tmp.type])) {
                    log_error("OnUpdatePolicy - start_pl4(tmp.type,g_PolicyExecHelper[tmp.type].interval,m_bTimerLoop[tmp.type])\n");
                    continue ;
                }
            } else {
                ///可能正在运行中，循环的不用特殊处理
                if(cur_stat > pstat_rdy) {
                    ///对于只运行一次的， 直接发送运行消息
                    if(!m_bTimerLoop[tmp.type]) {
                        tag_CallPolicyExec Exec ;
                        Exec.pType = tmp.type;
                        sendto_pl4Exec(VCF_CMD_CALL_POLICYEXEC,&Exec,sizeof(Exec));
                    }
                }
            }
            pExec->cnt++ ;
        } else {
            log_error("get_xml error\n");
        }
    }

    ///同步执行插入数据
    return sendmsg(m_nlogChannelID,VCF_CMD_LDB_OPERATOR,pExec,sizeof(tag_LDBexec) + pExec->cnt * sizeof(T_policy));
}


///ldb资产处理
bool  CVCFApp::ldb_Op_assert(en_DBOp op,void * pData , int len) {
    switch(op) {
    case dbop_add: {
        break ;
    }
    case dbop_modify:
    case dbop_del:
        return  ldb_tbl_remove(m_localDB,tbl_asset,pData,len);
    default:
        return false ;
    }
    return true ;
}
///ldb配置处理
bool  CVCFApp::ldb_Op_config(en_DBOp op,void * pData , int len) {
    switch(op) {
    case dbop_add:
    case dbop_modify: {
        T_localcfg * pcfg = (T_localcfg *)pData;
        int cnt = len / sizeof(T_localcfg);
        for(int i = 0 ; i < cnt ; i++) {
            if(!m_localDB.update(tbl_config,pcfg + i)) {
                return false ;
            }
        }
        m_localDB.commit();
        break ;
    }
    case dbop_del:
        return ldb_tbl_remove(m_localDB,tbl_config,pData,len);
    default:
        return false ;
    }
    return true ;
}
///ldb策略处理
bool  CVCFApp::ldb_Op_policy(en_DBOp op,void * pData , int len) {
    switch(op) {
    case dbop_add: {
        T_policy * pPolicy = (T_policy *)pData ;
        int count = len / sizeof(T_policy);
        char buffer[64] = "";
        std::vector<T_policy> vt ;
        for(int i = 0 ; i < count ; i++) {
            ///先查询在不在，不在的话再更新
            sprintf(buffer,"pid = %d and type = %d",(pPolicy+i)->pid,(pPolicy+i)->type);
            if(m_localDB.select(tbl_policy,&vt,buffer) > 0) {
                (pPolicy+i)->id = vt[0].id ;
                if(!m_localDB.update(tbl_policy,pPolicy+i)) {
                    log_error("更新本地策略失败\n");
                }
            } else {
                if(m_localDB.insert(tbl_policy,pPolicy+i) < 0) {
                    log_error("本地数据库插入策略失败\n");
                }
            }
        }
        m_localDB.commit();
        break ;
    }
    case dbop_modify:
    case dbop_del: {
        int * pID = (int *)pData ;
        if(len == 0) {
            m_localDB.remove(tbl_policy,(const char *)NULL);
        } else {
            int   count = len /sizeof(unsigned int);
            char  szfilter[64] = "" ;
            for(int i = 0 ; i < count ; i++) {
                sprintf(szfilter,"crc = %d",*(pID+i));
                m_localDB.remove(tbl_policy,szfilter);
            }
        }
        m_localDB.commit();
        break ;
    }
    default:
        return false ;
    }
    return true ;
}

///本地数据库提示log处理
bool  CVCFApp::ldb_Op_tiplog(en_DBOp op,void * pData , int len) {
    switch(op) {
    case dbop_add:{
        T_Tipslog * pPolicy = (T_Tipslog *)pData ;
        int count = len / sizeof(T_Tipslog);
        std::vector<T_policy> vt ;
        for(int i = 0 ; i < count ; i++) {
            if(m_localDB.insert(tbl_tipslog,pPolicy+i) < 0) {
                log_error("本地数据库插入提示日志失败\n");
            }
        }
        m_localDB.commit();
        break ;
    }
    case dbop_modify: {
        /**
         * 提示日志不用修改，直接删除。
         */
        break ;
    }
    case dbop_del: {
        return ldb_tbl_remove(m_localDB,tbl_tipslog,pData,len);
    }
    default:
        return false ;
    }
    return true ;
}

///本地数据库软件资产处理
bool  CVCFApp::ldb_op_softAsset(en_DBOp op,void * pData , int len) {
    switch(op) {
    case dbop_add:{
        T_lasset_soft * pPolicy = (T_lasset_soft *)pData ;
        int count = len / sizeof(T_lasset_soft);
        std::vector<T_lasset_soft> vt ;
        for(int i = 0 ; i < count ; i++) {
            if(m_localDB.insert(tbl_asset_soft,pPolicy+i) < 0) {
                log_error("本地数据库插入软件安装信息失败\n");
            }
        }
        m_localDB.commit();
        break ;
    }
    case dbop_modify: {
        T_lasset_soft * pPolicy = (T_lasset_soft *)pData ;
        int count = len / sizeof(T_lasset_soft);
        std::vector<T_lasset_soft> vt ;
        for(int i = 0 ; i < count ; i++) {
            if(!m_localDB.update(tbl_asset_soft,pPolicy+i)) {
                log_error("本地数据库更新软件安装信息失败\n");
            }
        }
        m_localDB.commit();
        break ;
    }
    case dbop_del: {
        return ldb_tbl_remove(m_localDB,tbl_asset_soft,pData,len);
    }
    default:
        return false ;
    }
    return true ;
}

///本地数据库执行函数
bool  CVCFApp::ldb_Operator(void * pData , int len) {
    tag_LDBexec * pExec = (tag_LDBexec *)pData ;
    if(len < (int)sizeof(tag_LDBexec)) {
        return false ;
    }
    switch(pExec->tbl) {
    case tbl_asset: {//资产
        return ldb_Op_assert((en_DBOp)pExec->cbop,pExec->data,len - sizeof(tag_LDBexec));
    }
    case tbl_config: {//配置
        return ldb_Op_config((en_DBOp)pExec->cbop,pExec->data,len - sizeof(tag_LDBexec));
    }
    case tbl_policy: { //策略
        return ldb_Op_policy((en_DBOp)pExec->cbop,pExec->data,len - sizeof(tag_LDBexec));
    }
    case tbl_asset_soft: {
        return ldb_op_softAsset((en_DBOp)pExec->cbop,pExec->data,len - sizeof(tag_LDBexec));
    }
    case tbl_tipslog: {
        return ldb_Op_tiplog((en_DBOp)pExec->cbop,pExec->data,len - sizeof(tag_LDBexec));
    }
    default:
        return false ;
    }
    return  true ;
}

///获取资产
bool  CVCFApp::ldb_get_Asset(void * pData , int len) {
    tag_ldbGetAsset * pAsset = (tag_ldbGetAsset *)pData ;
    CSoftinstallmap & Map = *((CSoftinstallmap *)pAsset->pSoftMap);
    CDeviceInfoMap & MapEx = *((CDeviceInfoMap *)pAsset->pHardMap);

    ///查询软件
    std::vector<T_lasset_soft> _vt ;
    if(m_localDB.select(tbl_asset_soft,&_vt) > 0) {
        tag_SoftInstall install ;
        std::vector<T_lasset_soft>::iterator iter = _vt.begin();
        while(iter != _vt.end()) {
            install.version = iter->pVer ;
            install.time = iter->pTime ;
            Map[iter->pName] = install;
            iter++ ;
        }
    }

    ///查询硬件
    std::vector<T_localasset> _vtEx ;
    if(m_localDB.select(tbl_asset,&_vtEx) > 0) {
        std::vector<T_localasset>::iterator iterEx = _vtEx.begin();
        while(iterEx != _vtEx.end()) {
            MapEx[iterEx->type] = iterEx->pContent;
            iterEx++ ;
        }
    }

    return true ;
}
///更新本地数据库的硬件资产
bool  CVCFApp::on_Update_HAsset(void * buffer ,int len) {
    tag_ldbUpdatasAsset * pAsset = (tag_ldbUpdatasAsset *)buffer ;
    CDeviceInfoMap * pAdd = (CDeviceInfoMap *)pAsset->pAdd ;
    CDeviceInfoMap * pDel = (CDeviceInfoMap *)pAsset->pDel ;
    CDeviceInfoMap * pModify = (CDeviceInfoMap *)pAsset->pModify ;

    char  buff[256] = "";
    T_localasset tmp;
    ///新增
    if(pAdd->size()) {
        CDeviceInfoMap::iterator iter = pAdd->begin();
        while(iter != pAdd->end()) {
            tmp.type = iter->first ;
            tmp.pContent = iter->second.c_str();
            if(!m_localDB.insert(tbl_asset,&tmp)) {
                std::string log = "插入硬件资产失败: ";
                log = log + g_asset_desc[iter->first]  ;
                log_error(log.c_str());
            }
            iter++ ;
        }
        sprintf(buff,"插入硬件资产: %lu",pAdd->size());
        log_trace(buff);
    }

    ///删除
    if(pDel->size()) {
        CDeviceInfoMap::iterator iter = pDel->begin();
        while(iter != pDel->end()) {
            sprintf(buff,"type=%d",iter->first);
            m_localDB.remove(tbl_asset,buff);
            iter++ ;
        }
    }
    sprintf(buff,"删除硬件资产: %lu\n",pDel->size());
    log_trace(buff);
    ///更新
    if(pModify->size()) {
        CDeviceInfoMap::iterator iter = pModify->begin();
        while(iter != pModify->end()) {
            tmp.type = iter->first ;
            tmp.pContent = iter->second.c_str();
            sprintf(buff,"type=%d",iter->first);
            if(!m_localDB.update(tbl_asset,&tmp,buff)) {
                std::string log = "更新硬件资产失败: " ;
                log = log  +  g_asset_desc[iter->first] ;
                log_error(log.c_str());
            }
            iter++ ;
        }
    }
    sprintf(buff,"修改硬件资产: %lu\n",pModify->size());
    log_trace(buff);
    if(pModify->size() || pDel->size() || pAdd->size()) {
        m_localDB.commit();
    }
    return true ;
}

/**
 * 更新本地数据的软件资产
 */
bool  CVCFApp::on_Update_SAsset(void * buffer ,int len) {
    tag_ldbUpdatasAsset * pAsset = (tag_ldbUpdatasAsset *)buffer ;

    if(pAsset == NULL) {
        return false;
    }
    std::vector<tag_SoftInstallEx> * pAdd = (std::vector<tag_SoftInstallEx> *)pAsset->pAdd ;
    std::vector<tag_SoftInstallEx> * pDel = (std::vector<tag_SoftInstallEx> *)pAsset->pDel ;
    std::vector<tag_SoftInstallEx> * pModify = (std::vector<tag_SoftInstallEx> *)pAsset->pModify ;
    if(pAdd == NULL || pDel == NULL || pModify == NULL) {
        log_trace("add del or moidify is null");
        return false;
    }
    char  buff[256] = "";
    T_lasset_soft  t_tmp ;
    ///新增
    if(pAdd->size()) {
        std::vector<tag_SoftInstallEx>::iterator iter = pAdd->begin();
        while(iter != pAdd->end()) {
            t_tmp.pName = iter->name.c_str();
            t_tmp.pVer = iter->version.c_str();
            t_tmp.pTime = iter->time.c_str();
            if(!m_localDB.insert(tbl_asset_soft,&t_tmp)) {
                std::string log = "插入软件资产失败: " + iter->name ;
                log_error(log.c_str());
            }
            iter++ ;
        }
        sprintf(buff,"插入软件资产: %lu\n",pAdd->size());
        log_trace(buff);
    }
    ///删除
    if(pDel->size()) {
        std::vector<tag_SoftInstallEx>::iterator iter = pDel->begin();
        while(iter != pDel->end()) {
            sprintf(buff,"pName='%s'",iter->name.c_str());
            m_localDB.remove(tbl_asset_soft,buff);
            iter++ ;
        }
    }
    sprintf(buff,"删除软件资产: %lu\n",pDel->size());
    log_trace(buff);
    ///更新
    if(pModify->size()) {
        std::vector<tag_SoftInstallEx>::iterator iter = pModify->begin();
        while(iter != pModify->end()) {
            t_tmp.pName = iter->name.c_str();
            t_tmp.pVer = iter->version.c_str();
            t_tmp.pTime = iter->time.c_str();
            sprintf(buff,"pName='%s'",iter->name.c_str());
            if(!m_localDB.update(tbl_asset_soft,&t_tmp,buff)) {
                std::string log = "更新软件资产失败: " + iter->name ;
                log_error(log.c_str());
            }
            iter++ ;
        }

    }
    sprintf(buff,"修改软件资产: %lu\n",pModify->size());
    log_trace(buff);
    if(pModify->size() || pDel->size() || pAdd->size()) {
        m_localDB.commit();
    }
    return true ;
}

/**
 *  由于VRV的网络交互流程必须每次都连接，所以日志先过来后先保存在本地，上传通过定时器驱动批量上传。
 */
bool  CVCFApp::Upload_msg_proc(unsigned short cmd , PVOID buffer , int len,unsigned int id) {

    switch(cmd) {
        ///数据库操作
    case VCF_CMD_LDB_OPERATOR: {
        return ldb_Operator(buffer,len);
    }
    case VCF_CMD_LDB_GET_ASSET:{
        return ldb_get_Asset(buffer,len);
    }
    case VCF_CMD_LDB_UPDATA_SASSET: {
        return on_Update_SAsset(buffer,len);
    }
    case VCF_CMD_LDB_UPDATA_HASSET: {
        return on_Update_HAsset(buffer,len);
    }
        ///定时上报的日志
    case VCF_CMD_LOG_NORMAL: {
        /*先做日志合并*/
        tag_Policylog * plog  = (tag_Policylog *)buffer ;
        ///日志过滤，不符合条件的直接丢弃
        if(!m_logFilter.filter_log(plog->type,plog->what,plog->time,plog->log)) {
            break;
        }

        T_localog log ;
        log.type = plog->type ;
        log.what = plog->what ;
        log.time = plog->time ;
        log.pContent = plog->log;
        if(!m_localDB.insert(tbl_log,&log)) {
            std::string log = "插入日志失败:=>  ";
            log = log + plog->log ;
            log_error(log.c_str());
        }
        break;
    }
        ///立即上报的日志
    case VCF_CMD_LOG_ALERT: {
        /*是否先做日志合并 ？*/
        tag_Policylog * plog  = (tag_Policylog *)buffer ;
        T_localog log;
        log.type = plog->type;
        log.what = plog->what ;
        log.time = plog->time ;
        log.pContent = plog->log;
        if(!m_NetEngine.sendnetmsg(S_CMD_UPLOAD_LOG_NOW,&log,sizeof(log)))  {
            m_runlog.log_log("上报即时日志失败！");
            if(!m_localDB.insert(tbl_log,&log)) {
                std::string log = "插入即时日志失败:=>  ";
                log = log + plog->log ;
                log_error(log.c_str());
            }
        } else { ///记录到本地
            Upload_msg_proc(VCF_CMD_LOG_NORMAL,buffer,0,0);
        }
        break ;
    }
        ///理解上报的特殊日志
    case VCF_CMD_LOG_ALERT_SPEC: {
        tag_Policylog * plog  = (tag_Policylog *)buffer ;
        T_localog log;
        log.type = plog->type;
        log.what = plog->what ;
        log.time = plog->time ;
        log.pContent = plog->log;

        if(!m_NetEngine.sendnetmsg(S_CMD_UPLOAD_LOG_NOWEX,&log,sizeof(log)))  {
            log_trace("上报即时日志失败！");
            if(!m_localDB.insert(tbl_log,&log)) {
                std::string log = "插入即时日志失败:=>  ";
                log = log + plog->log ;
                log_error(log.c_str());
            }
        }
        break ;
    }
        ///定时上传
    case VCF_CMD_BATCH_UPLOAD: {
        ///先在本地查询出日志
        std::vector<T_localog>  _array ;
        if(!m_localDB.select(tbl_log,&_array)) {
            break ;
        }
        char loclog[128]="";
        sprintf(loclog,"上报日志: %lu\n",_array.size());
        log_trace(loclog);
        ///上传
        int curid = 0 ;
        tag_S_UPLOAD_LOGS logs ;
        logs.curid =  &curid ;
        logs.pArray = &_array ;
        ///发送
        if(!m_NetEngine.sendnetmsg(S_CMD_UPLOAD_LOG,&logs,sizeof(logs)))  {
            m_runlog.log_log("发送日志失败，发送: %d条，成功: %d条",_array.size(),curid);
        }
        sprintf(loclog,"上报日志成功: %d\n",curid);
        log_trace(loclog);
        /**
         * 清理本地数据库
         */
        for(int i = 0 ; i < curid ; i++) {
            m_localDB.remove(tbl_log,_array[i].id);
        }

        ///如果由发送成功的，数据库同步
        if(curid) {
            m_localDB.commit();
        }
        break;
    }
    }

    return true ;
}

void  CVCFApp::closeNet() {
#if 0
#if defined(HW_X86) && defined (OEM_ZB_KYLIN)
    ctrl_EdpNetKo(netko_closeNet);
#else
    m_myIptables.closeNet();
#endif
#endif
    m_myIptables.closeNet();
}

void  CVCFApp::openNet() {
#if 0
#if defined(HW_X86) && defined(OEM_ZB_KYLIN)
    ctrl_EdpNetKo(netko_openNet);
#else
    m_myIptables.openNet();
#endif
#endif
    m_myIptables.openNet();

}

void report_status_to_server(int status);

bool  CVCFApp::msg_proc(unsigned short cmd , PVOID buffer, int len,unsigned int id) {
    switch(cmd) {
        ///锁屏
    case VCF_CMD_LOCK_SCREEN: {
        m_imcSrv.pub_msg_4tray(MC_CMD_S2C_LOCKSCREEN, NULL, 0);
        break ;
    }
        ///关机
    case VCF_CMD_CALL_SHUTDOWN: {
        ///系统启动前30S，不受理关机命令
        if(YCommonTool::get_Startsec() - m_startTime < 30) {
            log_trace("收到关机 命令，离启动时间不到30S，所以不关机");
            break ;
        }
        log_trace("收到关机 命令，关机");
        ///退出系统
        quit();
        char  cmd[128] = "";
        sleep(1); ///延迟1秒
        sprintf(cmd,"shutdown -h now");
        system(cmd);
        break ;
    } ///
    case VCF_CMD_OPEN_NET: {
        tag_openNet * pOpen = (tag_openNet *)buffer ;
        if(pOpen->policy < en_policytype_count) {
            m_bCloseNet[pOpen->policy] = false ;
        } else { ///服务器要求打开网络
            m_bCloseNetFromSrv = false  ;
            m_bofflineAlaways = false  ;
            for(int i = 0 ; i < en_policytype_count ; i++) {
                m_bCloseNet[i] = false ;
            }
        }
        ///如果是持续断网的情况，直接跳出
        if(m_bofflineAlaways) {
            log_trace("持续断网， 打开网络请求忽略！");
            break ;
        }
        int cnt = 0 ;
        for(int i = 0 ; i < en_policytype_count ; i++) {
            if(m_bCloseNet[i])
                cnt++ ;
        }
        //如果还有一个模块请求断网，则不打开网络,如果是服务器要求打开网络，则打开网络
        if(cnt || m_bCloseNetFromSrv) {
            log_trace("还有其他策略断网，或者服务器断网！");
            break ;
        }
        openNet();
        m_bcurOffline = false ;
        break ;
    }
    case VCF_CMD_CALL_CLOSENET: {
        tag_closeNet * pClose = (tag_closeNet * )buffer;
        if(pClose->policy < en_policytype_count) {
            m_bCloseNet[pClose->policy] = true;
        } else {
            m_bCloseNetFromSrv = true ;
        }

        if(!m_bcurOffline) {
            m_bcurOffline = true ;
            closeNet();
        }

        if(pClose->bAlaways && !m_bofflineAlaways) {
            log_trace("永久断网。。。。。。。。。。。。。。");
            m_bofflineAlaways  = true;
            char buffer[128] = "";
            tag_LDBexec *  pdbExec = (tag_LDBexec *)buffer ;
            pdbExec->tbl   =  tbl_config ;
            pdbExec->cbop  =  dbop_modify ;
            pdbExec->cnt   =  1  ;
            T_localcfg * pcfg = (T_localcfg *)pdbExec->data ;
            pcfg->name     =  LDB_OFFL_ALAWAYS ;
            pcfg->vals     =  "1" ;
            if(!sendmsg(m_nlogChannelID,VCF_CMD_LDB_OPERATOR,pdbExec,sizeof(tag_LDBexec) + sizeof(T_localcfg) * pdbExec->cnt)) {
                log_error("更改一直断网状态失败");
            }
        }
        break ;
    }
    case VCF_CMD_CALL_RESTART: {
        ///退出系统
        quit();
        break ;
    }
        ///调用提示框
    case   VCF_CMD_GUI_TIPS: {
        ///启动注册界面
        sendto_Imc(VCF_CMD_GUI_TIPS,buffer,len);
        break ;
    }
        ///策略全部取消
    case VCF_CMD_POLICY_UNAPPLY_ALL: {
        ///判断策略条数
        log_trace("VCF_CMD_POLICY_UNAPPLY_ALL start");
        if(m_policyMgr.get_PolicyCount()==0) {
            break ;
        }
        char  buf[64]="";
        tag_LDBexec * pExec = (tag_LDBexec *)buf;
        pExec->tbl  = tbl_policy ;
        pExec->cbop = dbop_del   ;
        ///清空本地缓存
        sendto_Uplog(VCF_CMD_LDB_OPERATOR,pExec,sizeof(tag_LDBexec));
        ///停止策略运行
        for(int i = 0 ; i < en_policytype_count ; i++) {
            ///因为是在主线程中， 直接调用。
            msg_proc(VCF_CMD_CALL_POLICY_STOP,&i,sizeof(int),0);
        }
        m_policyMgr.clean_Map();
        log_trace("VCF_CMD_POLICY_UNAPPLY_ALL end\n");
        break ;
    }
        ///策略取消应用
    case VCF_CMD_POLICY_UNAPPLY: {
        log_trace("VCF_CMD_POLICY_UNAPPLY start\n");
        ///判断策略条数
        if(m_policyMgr.get_PolicyCount()==0) {
            break ;
        }
        tag_PApplyChange * pChange = (tag_PApplyChange *)buffer ;
        std::vector<unsigned int> * pDel = (std::vector<unsigned int> *)pChange->pDelArray;
        std::vector<unsigned int> * pUnApply = (std::vector<unsigned int> *)pChange->pDelUnApply;
        int   i = 0 ;
        char  buf[2100]="";

        sprintf(buf,"VCF_CMD_POLICY_UNAPPLY 删除：%lu, 取消删除：%lu\n",pDel->size(),pUnApply->size());
        log_trace(buf);

        tag_LDBexec * pExec = (tag_LDBexec *)buf;
        ///通知本地数据库删策略缓存
        pExec->tbl  = tbl_policy ;
        pExec->cbop = dbop_del ;
        int count = 0 ;
        unsigned int * pID = (unsigned int *)pExec->data;
        if(pDel->size()) {
            for(i = 0 ; i < (int)pDel->size() ; i++) {
                *(pID+count++)  = (*pDel)[i];
            }
        }
        if(pUnApply->size()) {
            for(i = 0 ; i < (int)pUnApply->size() ; i++) {
                *(pID+count++)  = (*pUnApply)[i];
            }
        }

        sendto_Uplog(VCF_CMD_LDB_OPERATOR,buf,sizeof(tag_LDBexec) + sizeof(unsigned int) * count);

        ///删除本地这些策略
        char  tpye_cnt[en_policytype_count] = {0};
        for(i = 0 ; i < (int)pUnApply->size() ; i++) {
            CPolicy  * p  = m_policyMgr.get_PolicyFromCrc((*pUnApply)[i]);
            if(p) {
                tpye_cnt[p->get_type()]++ ;
            }
        }

        ///停止策略运行
        for(i = 0 ; i < en_policytype_count ; i++) {
            if(tpye_cnt[i]) {
                ///因为是在主线程中， 直接调用。
                msg_proc(VCF_CMD_CALL_POLICY_STOP,&i,sizeof(int),0);
            }
        }

        ///删除本地缓存
        for(i = 0 ; i < count ; i++) {
            m_policyMgr.del_PolicyFromCrc(*(pID+i));
        }

        break ;
    }
        ///注册成功
    case VCF_CMD_REGISTER_SUCC: {
        ///启动上传日志定期器，定为1分钟
        if(m_nUploadTimer==-1) {
            m_nUploadTimer = set_Timer(c_iUploadlog_interval,0,true);
        }
        if(m_nUpdatePolicyTimer == -1) {
            ///启动更新策略服务器,1分钟更新一次
            m_nUpdatePolicyTimer = set_Timer(c_iUploadPolicy_interval,0,true);
        }
        if(m_nHeartBeatTimer == -1)
            m_nHeartBeatTimer = set_Timer(c_iHeartbeat_interval,0,true);
#if 0
#if defined(HW_X86) && defined(OEM_ZB_KYLIN)
        ctrl_EdpNetKo(netko_addspecIp);
#endif
#endif
        addSpecRule();
        ///更新策略
        m_policyMgr.set_Updateing(true);
        sendto_pl4Exec(VCF_CMD_POLICY_UPDATA_GENERAL,NULL,0);
        ///获取资产信息
        std::string _server_ip;
        get_lconfig(lcfg_srvip, _server_ip);
        if(!_server_ip.empty()) {
            sendto_pl4Exec(VCF_CMD_GET_ASSEET,NULL,0);
        }
        break ;
    }
        ///系统开始运行
    case VCF_CMD_MAIN_SRUNING : {
        if(m_bcurOffline == false) {
            openNet();
        }

#ifdef SELF_DEBUG
        m_nCheckSelf = set_Timer(c_iCheckSelf_interval,0,true);
#endif
        m_nCheckWatchv = set_Timer(c_iCheckWatchV,0,true);
        if(!m_bRegister) { ///没有注册
            ///启动注册界面
            //sendto_Imc(VCF_CMD_REGISTER_GUI,NULL,0);
        } else {
            ///启动上传日志定期器，定为1分钟
            m_nUploadTimer = set_Timer(c_iUploadlog_interval,0,true);
            ///启动更新策略服务器,1分钟更新一次
            m_nUpdatePolicyTimer = set_Timer(c_iUploadPolicy_interval,0,true);
            ///启动心跳定时器
            m_nHeartBeatTimer = set_Timer(c_iHeartbeat_interval,0,true);

            ///寻找注册网卡
            findRegNic();
            addSpecRule();

            m_policyMgr.set_Updateing(true);
            ///更新策略
            sendto_pl4Exec(VCF_CMD_POLICY_UPDATA_GENERAL,NULL,0);
            ///获取资产信息
            std::string _server_ip;
            get_lconfig(lcfg_srvip, _server_ip);
            if(!_server_ip.empty()) {
                sendto_pl4Exec(VCF_CMD_GET_ASSEET,NULL,0);
            }

            ///启动本地策略
            if(!startLocalPolicy()) {
                log_error("启动本地策略失败\n");
            }
        }
        //sendto_Imc(VCF_CMD_VAS_PULL_UP_SYSTRAY, NULL, 0);

        /*1 -- client start in VRVPROTOCOLXXX DEFINE we don't want include here*/
        report_status_to_server(1);
        break;
    }
    case VCF_CMD_CALL_POLICYUPDATE : {
        ///先判断是否已经启动策略更新
        log_trace("VCF_CMD_CALL_POLICYUPDATE start");
        if(m_policyMgr.isUpdateing()) {
            log_trace("VCF_CMD_CALL_POLICYUPDATE 正在更新中  end , ");
            break ;
        }
        ///调用策略执行线程执行策略更新概况
        sendto_pl4Exec(VCF_CMD_POLICY_UPDATA_GENERAL,NULL,0);
        log_trace("VCF_CMD_CALL_POLICYUPDATE end");
        break ;
    }
        ///初始化执行成功
    case VCF_CMD_POLICYEXECINIT_SUCC: {

        tag_PolicyExecinit * pinit = (tag_PolicyExecinit *)buffer;
        ///再进行一次判断状态，
        en_policy_stat stat =  m_policyMgr.get_policyStat((enPolicytype)pinit->type);
        if(stat == pstat_noexsit) { ///被取消
            if(m_policyTimer[pinit->type] != -1) {
                kill_timer(m_policyTimer[pinit->type]);
                m_policyTimer[pinit->type] = -1;
            }
            break ;
        }

        if(stat == pstat_init) {
            ///启动执行定时器 ，设置策略执行状态, 只执行一次的，不用启动定时器
            if(pinit->bloop) {
                int timer_id = set_Timer(pinit->interval,pinit->pdata,pinit->bloop);
                m_bTimerLoop[pinit->type] = pinit->bloop ;
                m_policyTimer[pinit->type] = timer_id ;
            }

            /**
             * 先执行一次
             */
            tag_CallPolicyExec Exec ;
            m_policyMgr.update_policyStat((enPolicytype)pinit->type,pstat_willrun);
            Exec.pType = pinit->type;
            sendto_pl4Exec(VCF_CMD_CALL_POLICYEXEC,&Exec,sizeof(Exec));
        }
        break ;
    }
        ///策略执行失败
    case VCF_CMD_POLICYEXEC_FAILED : {
        //tag_pExecFailed * pfail = (tag_pExecFailed *)buffer ;

        break ;
    }
        ///呼叫策略启动
    case VCF_CMD_CALL_POLICY_START: {
        tag_CallPolicyStart * pStart = (tag_CallPolicyStart *)buffer ;
        if(pStart->type >= en_policytype_count ) {
            break ;
        }

        ///定时器如果已经启动，不用重新启动，证明该类型策略已经运行，只要更新配置，
        ///下次就使用新的策略运行。
        if(m_policyTimer[pStart->type] != -1) {
            break ;
        }

        ///先判断策略当前的状态,
        if(m_policyMgr.get_policyStat((enPolicytype)pStart->type) !=  pstat_rdy) {
#if 0
            char _buf[128] = {0};
            sprintf(_buf, "%s stats : %d", "VCF_CMD_CALL_POLICY_START",
                    m_policyMgr.get_policyStat((enPolicytype)pStart->type));
            log_trace(_buf);
#endif
            break;
        }

        ///置为初始化状态
        m_policyMgr.update_policyStat((enPolicytype)pStart->type,pstat_init);

        tag_PolicyExecinit init ;
        init.type = pStart->type ;
        init.interval = pStart->interval ;
        init.bloop = !pStart->once ;
        init.pdata = NULL ;
        ///发送初始化消息
        sendto_pl4Exec(VCF_CMD_POLICY_EXEC_INIT,&init,sizeof(init));
        break ;
    }
        ///策略执行提示，告诉管理者现在要执行策略了
    case VCF_CMD_POLICYEXEC_NOW: {
        int  * pType = (int *)buffer ;
        char zalog[128] = "";
        sprintf(zalog,"策略运行hujiao yunxing : %d",*pType);
        log_trace(zalog);
        tag_CallPolicyExec Exec ;
        en_policy_stat  stat =	m_policyMgr.get_policyStat((enPolicytype)*pType);
        ///只运行一次的定时器，杀掉。
        if(!m_bTimerLoop[*pType]) {
            kill_timer(m_policyTimer[*pType]);
            m_policyTimer[*pType] = -1;
        }

        if(stat == pstat_free) { ///空闲状态
            m_policyMgr.update_policyStat((enPolicytype)*pType,pstat_willrun);
            Exec.pType = *pType;
            sendto_pl4Exec(VCF_CMD_CALL_POLICYEXEC,&Exec,sizeof(Exec));
        } else {
            char zalog1[128] = "";
            sprintf(zalog1,"exe thread busy stat is  %d", stat);
            log_trace(zalog1);
#if 0
            m_policyMgr.inc_dismiss_cnt((enPolicytype)*pType);
            sprintf(zalog1, "policy type is: %d, dismiss_cnt is: %d", *pType, m_policyMgr.get_dismiss_cnt((enPolicytype)*pType));
            log_trace(zalog1);

            if(m_policyMgr.get_dismiss_cnt((enPolicytype)*pType) > 10) {
                sendto_pl4Exec(VCF_CMD_POLICY_EXEC_UINIT, pType, sizeof(int));
                sprintf(zalog1, "%s", "--------------------restart policy-----------------------");
                log_trace(zalog1);
                m_policyMgr.set_dismiss_cnt((enPolicytype)*pType, 0);
                if(!start_pl4(*pType, g_PolicyExecHelper[*pType].interval, !m_bTimerLoop[*pType])) {
                    log_trace("restart policy error");
                } else {
                    log_trace("restart policy succcess");
                }
            }
#endif
        }
        break ;
    }
        ///呼叫策略停止
    case VCF_CMD_CALL_POLICY_STOP: {
        int  * pType = (int *)buffer ;
        en_policy_stat stat = m_policyMgr.get_policyStat((enPolicytype)*pType);
        if(stat == pstat_runing) {
            m_policyMgr.update_policyStat((enPolicytype)*pType,pstat_uinit);
            break;
        }

        if(*pType >= en_policytype_count) {
            break ;
        }
        char zalog[128] = "";
        sprintf(zalog,"策略呼叫停止 : %d",*pType);
        log_trace(zalog);
        ///循环执行的定时器
        if(m_bTimerLoop[*pType]) {
            ///定时器不存在
            if(m_policyTimer[*pType] == -1) {
                break ;
            }
            ///杀掉定时器
            kill_timer(m_policyTimer[*pType]);
            m_policyTimer[*pType] = -1 ;
        }

        stat = m_policyMgr.get_policyStat((enPolicytype)*pType);
        if(stat == pstat_free || stat == pstat_willrun) {
            ///启动清理
            m_policyMgr.update_policyStat((enPolicytype)*pType,pstat_uinit);
            ///直接通知执行清理函数
            sendto_pl4Exec(VCF_CMD_POLICY_EXEC_UINIT,pType,sizeof(int));
        }
        break ;
    }
    }
    return CYApp::msg_proc(cmd,buffer,len,id);
}

int  CVCFApp::getTimerType(int id) {
    for(int i = 0 ; i < en_policytype_count ; i++) {
        if(id == m_policyTimer[i]) {
            return i ;
        }
    }
    return en_policytype_count ;
}

int  CVCFApp::ExitInstances(int extid) {
    if(m_nUploadTimer >= 0) {
        kill_timer(m_nUploadTimer);
        m_nUploadTimer = -1 ;
    }
    if(m_nUpdatePolicyTimer >= 0) {
        kill_timer(m_nUpdatePolicyTimer);
        m_nUpdatePolicyTimer = -1 ;
    }
    if(m_nCheckWatchv >= 0) {
        kill_timer(m_nCheckWatchv);
        m_nCheckWatchv = -1 ;
    }

    for(int i = 0 ; i < en_policytype_count ; i++) {
        stop_pl4(i);
    }
    delSpecRule();
    ///暂时延时200毫秒，作为策略退出的延迟
    usleep(200000);
    stopAllcmdChannel();
    m_NetEngine.close();
    m_localDB.db_Attach();
    m_localDB.db_Close();
    m_localDB.db_Dettch();
    m_imcSrv.close();

    m_runlog.log_close();
    for(int i = enlog_debug ; i < enlog_count ; i++) {
        m_log[i].log_close();
    }

    return CYApp::ExitInstances(extid);
}

///增加服务器允许规则
void  CVCFApp::addSpecRule() {
#ifndef __APPLE__
    log_trace("增加服务器ＩＮＰＵＴ规则");
    m_myIptables.SetSrvIP(m_strSrvIp);
    delSpecRule();

    char  cmd[256] = "";
    sprintf(cmd,"iptables -I  INPUT -s %s -j ACCEPT",m_strSrvIp.c_str());
    system(cmd);

#else //APPLE_HERE

#endif

}

///删除服务器允许规则
void  CVCFApp::delSpecRule() {
#ifndef __APPLE__
    log_trace("删除服务器ＩＮＰＵＴ规则");
    char  cmd[256] = "";
    sprintf(cmd,"iptables -D  INPUT -s %s -j ACCEPT",m_strSrvIp.c_str());
    system(cmd);

#else //APPLE_HERE

#endif

}
///获取服务器类型
void  CVCFApp::get_Srvtype() {
    int sockfd = -1;
    struct sockaddr_in servaddr;
    char url[256] = "";
    sprintf(url,"GET /EDP-WEB/ HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Connection: Close\r\n\r\n",m_strSrvIp.c_str(),g_srvWebPort);
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
        return ;
    }

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(g_srvWebPort);
    if (inet_pton(AF_INET, m_strSrvIp.c_str(), &servaddr.sin_addr) <= 0 ) {
        close(sockfd);
        return ;
    }
    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        close(sockfd);
        return ;
    }

    int ret = write(sockfd,url,strlen(url));
    if (ret < 0) {
        close(sockfd);
        return ;
    }

    char buffer[4096] = "";
    memset(buffer, 0, 4096);
    ret= read(sockfd, buffer, 4095);
    if(ret <= 0) {
        //printf("4.5%s\n",buffer);
        close(sockfd);
        return  ;
    }

    char * p = strstr(buffer,"EDP-WEB");
    if(p) {
        //printf(">>=>>=>>LINUX服务器\n");
        m_bwinSrv = false ;
    }

    close(sockfd);
}

void  CVCFApp::checkSelf() {
    /*自身资源占用*/
    char szlog[1024]="";
    char cmd[256]="";
    std::string  log = "\n";
    sprintf(cmd,"ps -p %d u",getpid());
    FILE * fp = popen(cmd,"r");
    if(fp != NULL) {
        while(fgets(szlog,1024,fp)) {
            log = log + szlog ;
        }
        pclose(fp);
    }
    sprintf(cmd,"pstree %d",getpid());
    fp = popen(cmd,"r");

    if(fp) {
        while(fgets(szlog,1024,fp)){
            log = log + szlog ;
        }
        pclose(fp);
    }
    /**
     * 记录策略
     */
    sprintf(szlog,"策略总数: %d\n",m_policyMgr.get_PolicyCount());
    log = log + szlog ;
    /**
     * 记录断网
     */
    log = log + "策略断网状态\n";
    for(int i =0 ; i < en_policytype_count ; i++) {
        if(m_bCloseNet[i]) {
            log = log + " -是- ";
        } else {
            log = log + " -否- ";
        }
    }

    ///是否服务器关闭网络
    if(m_bCloseNetFromSrv) {
        log = log + "\n服务器断网状态： 是\n";
    } else {
        log = log + "\n服务器断网状态： 否\n";
    }

    if(log.length()) {
        log_notice(log.c_str());
    }
}


bool  CVCFApp::timer_proc(int id) {
    using namespace YCommonTool ;

#ifdef SELF_DEBUG
    if(m_nCheckSelf == id) {
        checkSelf() ;
        return true ;
    }
#endif

    if(m_nCheckWatchv == id) {
        checkWatchV();
        ///向托盘广播消息
        m_imcSrv.pub_msg_4tray(MC_CMD_S2C_HELLO,NULL,0);
        return true ;
    }

    ///日志上传定时器
    if(id == m_nUploadTimer) {
        ///启动日志消息通道上传日志
        sendto_Uplog(VCF_CMD_BATCH_UPLOAD,NULL,0) ;
    } else if(m_nUpdatePolicyTimer == id) {
        ///更新策略服务器
        sendto_Main(VCF_CMD_CALL_POLICYUPDATE,NULL,0);
    } else if (m_nHeartBeatTimer == id){
        sendto_pl4Exec(VCF_CMD_HEART_BEAT,NULL,0);
    } else {
        int type = getTimerType(id);
        if(type < en_policytype_count) {
            ///通知主线程改执行某条策略
            sendto_Main(VCF_CMD_POLICYEXEC_NOW,&type,sizeof(type));
        }
    }
    return CYApp::timer_proc(id) ;
}

void  CVCFApp::showCloseNetTips(){
    ///获取提示
    FILE * fp = fopen(g_closeNetPromptFile.c_str(),"r");
    if(fp==NULL) {
        return ;
    }
    char sz[250] = "";
    fgets(sz,250,fp);
    fclose(fp);
    char buffer[512] = "";
    tag_GuiTips * pTips = (tag_GuiTips *)buffer ;
    pTips->sign = en_TipsGUI_btnOK | en_TipsGUI_timeOut ;
    pTips->defaultret = en_TipsGUI_None ;
    pTips->pfunc = NULL ;
    pTips->param.timeout = 5000 ;
    sprintf(pTips->szTitle,"提示");
    sprintf(pTips->szTips,"%s",sz);
    g_GetSendInterface()->sendto_Imc(VCF_CMD_GUI_TIPS,buffer,sizeof(tag_GuiTips));
}

bool  CVCFApp::get_Localconfig() {
    std::string dbfile = getMoudlepath() + LDB_NAME;
    if(!m_localDB.db_Open(LDB_NAME,dbfile.c_str())) {
        return false ;
    }
    m_localDB.db_Attach();
    ///查询是否注册
    m_bRegister = false ;
    std::vector<T_localcfg> cfgvt ;
    char szQuery[64] = "";
    sprintf(szQuery,"name = '%s'",LDB_REGISTER);
    if(m_localDB.select(tbl_config,&cfgvt,szQuery)) {
        if(strcmp(cfgvt[0].vals,LDB_TRUE_VAL) == 0 ) {
            printf("是否注册 : %s\n",cfgvt[0].vals);
            m_bRegister = true ;
        }
    }
#if 0
#if defined(HW_X86) && defined(OEM_ZB_KYLIN)
    ///加入网络控制内核模块
    if(0 != access("/sys/module/EdoNetko", 0)) {
        char  cmd[32] = "";
        sprintf(cmd,"insmod ./%s",EDP_NETKO);
        system(cmd);
    }
#endif
#endif
    ///已经注册后获取
    if(m_bRegister) {
        ///查询注册IP
        sprintf(szQuery,"name = '%s'",LDB_REGIP);
        if(m_localDB.select(tbl_config,&cfgvt,szQuery)) {
            m_strRegiP = cfgvt[0].vals;
        }
        printf("获取注册IP：%s\n",m_strRegiP.c_str());

        ///查询注册MAC
        sprintf(szQuery,"name = '%s'",LDB_REGMAC);
        if(m_localDB.select(tbl_config,&cfgvt,szQuery)) {
            m_strRegMac = cfgvt[0].vals;
        }
        printf("获取注册MAC：%s\n",m_strRegMac.c_str());

        ///查询服务器地址
        sprintf(szQuery,"name = '%s'",LDB_SRVIP);
        if(m_localDB.select(tbl_config,&cfgvt,szQuery)) {
            m_strSrvIp = cfgvt[0].vals;
        }
        printf("serverip: %s\n",m_strSrvIp.c_str());

        ///查询注册字符串
        sprintf(szQuery,"name = '%s'",LDB_REGGUISTR);
        if(m_localDB.select(tbl_config,&cfgvt,szQuery)) {
            m_strReginfo = cfgvt[0].vals;
        }

        ///获取断网状态
        sprintf(szQuery,"name = '%s'",LDB_OFFL_ALAWAYS);
        if(m_localDB.select(tbl_config,&cfgvt,szQuery)) {
            m_bofflineAlaways = (atoi(cfgvt[0].vals) != 0);
        }

        ///获取注册网卡, 根据MAC找网卡名
        std::list<std::string>  niclst;
        if(get_Nicinfo(niclst)) {
            std::list<std::string>::iterator  iter = niclst.begin();
            while(iter != niclst.end()) {
                if(get_mac(*iter) == m_strRegMac) {
                    m_strRegNic = *iter ;
                    break ;
                }
                iter++ ;
            }
        }

        if(m_strRegNic.length() == 0) {
            sprintf(szQuery,"name = '%s'",LDB_REGNIC);
            if(m_localDB.select(tbl_config,&cfgvt,szQuery)) {
                m_strRegNic = cfgvt[0].vals;
            }
        }

        //获取服务器类型
        sprintf(szQuery,"name = '%s'",LDB_SRVTYPE);
        if(m_localDB.select(tbl_config,&cfgvt,szQuery)) {
            if(atoi(cfgvt[0].vals) == 1) {
                m_bwinSrv = true ;
            } else {
                m_bwinSrv = false ;
            }
        }
        printf("是否windows服务器: %s\n",m_bwinSrv ? "true":"false");

        printf("---regmac is: %s\n", m_strRegMac.c_str());

        char buffer_idp[32]="";
        get_device_indetify(buffer_idp,32,m_strRegMac);
        m_strDevid = buffer_idp ;

        ///添加服务器IP为特殊IP
#if 0
        ctrl_EdpNetKo(netko_addspecIp);
#endif

        /**
         * 从本地数据库中读出以前的策略
         */
        std::vector<T_policy> vt ;
        if(m_localDB.select(tbl_policy,&vt) > 0) {
            std::vector<T_policy>::iterator iter = vt.begin();
            while(iter != vt.end()) {
                CPolicy  * pPolicy = m_policyMgr.importFromXml(iter->pid,iter->type,iter->crc,iter->pContent);
                printf("%u %s\n",iter->crc,iter->pContent);
                if(pPolicy) {
                    pPolicy->set_id(iter->pid);
                    pPolicy->set_crc(iter->crc);
                }
                iter++ ;
            }
        }
    }

    if(m_bofflineAlaways) {
        closeNet();
        m_bcurOffline = true ;
    }
    m_localDB.db_Dettch();
    return true ;
}

bool  CVCFApp::checkandset_Env() {
    ///用户检查
    if(getuid() != 0) {
        return false ;
    }
    ///设置路径
    int ret =  chdir(getMoudlepath().c_str());
    if(ret) {
        return false ;
    }
    return true ;
}

void  CVCFApp::on_Regui(unsigned short cmd,void * pbuffer,int len) {
    switch(cmd) {  ///cmd 在MCInterface.h里面定义
        ///需要 IP/MAC
    case MC_CMD_C2S_NICINFO: {
        using namespace YCommonTool ;
        ///获取网卡信息
        std::list<std::string> niclist ;
        get_Nicinfo(niclist);
        char buffer[4096] = "";
        tag_S2C_Nicinfos * pinfo = (tag_S2C_Nicinfos *)buffer ;
        pinfo->cbcnt = 0 ;
        std::list<std::string>::iterator  iter = niclist.begin();
        std::string  ip , mac ;
        while(iter != niclist.end()) {
            ip =  get_ip(*iter);
            mac = get_mac(*iter);

#if 1
            std::cout << "nic name : " << *iter << " ipaddre: "<< ip << " mac: "<< mac <<std::endl;
#endif
            if(ip.empty() || mac.empty() || iter->empty()) {
                iter++;
                continue;
            }

            tag_S2C_Nicinfo & nic = pinfo->infos[pinfo->cbcnt];
            strcpy(nic.szip,ip.c_str());
            strcpy(nic.szmac,mac.c_str());
            pinfo->cbcnt++ ;
            iter++ ;
        }

        m_imcSrv.sendData(MC_CMD_S2C_NICINFO,buffer,sizeof(tag_S2C_Nicinfos) + pinfo->cbcnt * sizeof(tag_S2C_Nicinfo));
        break;
    }
    case MC_CMD_C2S_REG: {
        char  * pReginfo = (char *)pbuffer;
        printf("**************************\n");
        ///获取选择的IP/MAC
        std::string tmp  =  pReginfo;
        ///获取一些特殊值
        if(!get_SpacialVal(tmp)) {
            log_error("获取注册信息里面的特殊字段失败");
            break ;
        }
        m_log[1].log_log("获取服务器地址： %s %d\n",m_strSrvIp.c_str(),m_strSrvIp.length());
        get_Srvtype();
        std::string reg_info;
        reg_info =reg_info +  "MACAddress0="+m_strRegMac +STRITEM_TAG_END;
        reg_info =reg_info +  "IPAddress0="+m_strRegiP+STRITEM_TAG_END;
        reg_info = reg_info + "MACCount=1" + STRITEM_TAG_END;
        reg_info = reg_info + "IPCount=1"  +STRITEM_TAG_END;

        char buf[256]={0};
        get_device_indetify(buf,256,m_strRegMac);
        reg_info = reg_info + "DeviceIdentify=" + buf + STRITEM_TAG_END;
        reg_info = reg_info + (char*)pReginfo;

        char computer_name[256]="";
        gethostname(computer_name,256);
        reg_info = reg_info + "ComputerName="+computer_name+STRITEM_TAG_END;

        char os[1204]="";
        get_os_type(os,1204,false);
        reg_info = reg_info + "EdpRegVersion=" + CLIENT_VERSION  +STRITEM_TAG_END;
        reg_info = reg_info + "OSVersion=" + os+STRITEM_TAG_END;
        reg_info = reg_info + "OSType=APPLE/OSX"+STRITEM_TAG_END;

        printf("reg = %s\n",reg_info.c_str());
        ///发送注册信息
        char  szRegBuffer[2048] = "";
        strcpy(szRegBuffer,reg_info.c_str());
        if(!m_NetEngine.sendnetmsg(S_CMD_USER_REGISTER,szRegBuffer,reg_info.length())) {
            std::string key = VRVNETPRO_ERROR ;
            std::string error = m_NetEngine.get_Param(key);
            m_imcSrv.sendData(MC_CMD_S2C_REG_NG,error.c_str(),error.length());
        } else {
            ///修改数据库
            char buffer[1024] = "";
            tag_LDBexec *  pdbExec = (tag_LDBexec *)buffer ;
            pdbExec->tbl = tbl_config ;
            pdbExec->cbop  = dbop_modify ;
            pdbExec->cnt = 5;
            T_localcfg * pcfg = (T_localcfg *)pdbExec->data ;
            pcfg->name = LDB_REGISTER ;
            pcfg->vals = LDB_TRUE_VAL ;
            pcfg++ ;
            pcfg->name = LDB_REGIP;
            pcfg->vals = m_strRegiP.c_str();
            pcfg++;
            pcfg->name = LDB_REGMAC ;
            pcfg->vals = m_strRegMac.c_str();
            pcfg++;
            pcfg->name = LDB_REGGUISTR ;
            pcfg->vals = pReginfo;
            pcfg++;
            pcfg->name = LDB_SRVTYPE ;
            if(m_bwinSrv) {
                pcfg->vals = "1";
            } else {
                pcfg->vals = "0";
            }

            m_strReginfo = pReginfo;
            if(m_strSrvIp.length()) {
                pcfg++;
                pcfg->name = LDB_SRVIP ;
                pcfg->vals = m_strSrvIp.c_str();
                pdbExec->cnt++;
            }

            if(sendmsg(m_nlogChannelID,VCF_CMD_LDB_OPERATOR,pdbExec,sizeof(tag_LDBexec) + sizeof(T_localcfg) * pdbExec->cnt)) {
                m_imcSrv.sendData(MC_CMD_S2C_REG_OK,NULL,0);
                std::string regxml="/var/tmp/Regist.xml";
                if(0==access(regxml.c_str(),F_OK))
                {
                    rename(regxml.c_str(),basename((char *)(regxml.c_str())));
                }
            } else {
                const char * pError = "记录注册成功到本地数据库失败";
                log_error(pError);
                m_imcSrv.sendData(MC_CMD_S2C_REG_NG,pError,strlen(pError));
            }
            ///通知主线程启动成功
            sendto_Main(VCF_CMD_REGISTER_SUCC,NULL,0);
            ///由可能其他用户终端也有注册GUI启动
            m_imcSrv.call_Exit(m_nRegGui);
        }

        break;
    }
    }
}

bool  CVCFApp::get_SpacialVal(std::string & reg_info) {
    size_t  npos = reg_info.find("SelectNicInfo=",0);
    if(npos == string::npos) {
        const char * pError = "没有找到\"SelectNicInfo\"字段\n";
        log_error(pError);
        m_imcSrv.sendData(MC_CMD_S2C_REG_NG,pError,strlen(pError));
        return false ;
    } else {
        size_t  npos1 = reg_info.find(STRITEM_TAG_END,npos);
        if(npos1 == string::npos ) {
            const char  * pError  = "SelectNicInfo字段结尾没有找到STRITEM_TAG_END";
            log_error(pError);
            m_imcSrv.sendData(MC_CMD_S2C_REG_NG,pError,strlen(pError));
            return false ;
        }
        size_t selinfo_len = strlen("SelectNicInfo=");
        std::string ipmac_str = reg_info.substr(npos + selinfo_len,npos1-npos);
        npos = ipmac_str.find("/",0);
        if(npos == string::npos) {
            const char  * pError  = "SelectNicInfo字段值格式错误\n";
            log_error(pError);
            m_imcSrv.sendData(MC_CMD_S2C_REG_NG,pError,strlen(pError));
            return false ;
        }
        m_strRegiP  = ipmac_str.substr(0,npos);
        m_strRegMac = ipmac_str.substr(npos+1,ipmac_str.length()-npos-strlen(STRITEM_TAG_END));
        if(m_strRegMac.length() > 12) {
            m_strRegMac.erase(12,m_strRegMac.length()-12);
        }



        /**
         * 获取注册网卡名
         */
        findRegNic();

        char buffer_idp[32]="";
        get_device_indetify(buffer_idp,32,m_strRegMac);
        m_strDevid = buffer_idp ;
    }

    ///查找服务器地址
    npos =	reg_info.find("WebServerIP=",0);
    if(npos != string::npos) {
        npos += strlen("WebServerIP=");
        size_t  npos1 = reg_info.find(STRITEM_TAG_END,npos);
        m_strSrvIp = reg_info.substr(npos,npos1-npos);
    } else {
        const char  * pError = "注册字符串没有找到WebServerIP字段";
        log_error(pError);
        m_imcSrv.sendData(MC_CMD_S2C_REG_NG,pError,strlen(pError));
        return false ;
    }
    return true ;
}


bool  CVCFApp::findRegNic() {
    std::list<std::string>  niclst;
    YCommonTool::get_Nicinfo(niclst) ;
    std::list<std::string>::iterator  iter = niclst.begin();
    while(iter != niclst.end()) {
        if(m_strRegMac.empty() || m_strRegNic.empty()) {
            std::string ip = YCommonTool::get_ip(*iter);
            std::string mac = YCommonTool::get_mac(*iter);
            if(!ip.empty() && !mac.empty()) {
                set_lconfig(lcfg_regnic, *iter);
                set_lconfig(lcfg_regmac, mac);
                set_lconfig(lcfg_regip, ip);
                return true;
            }
        }
        std::cout << " iter in nic: " << iter->c_str() << "our reg nic: "<< m_strRegMac << std::endl;
        if(YCommonTool::get_mac(*iter) == m_strRegMac) {
            m_strRegNic = *iter ;
            return true ;
        }
        iter++ ;
    }
    return false ;
}

void  CVCFApp::Sinkmsg_proc(unsigned short cmd,void * pbuffer,int len,int pid) {
    ///根据不同的客户端ID区分消息号
    printf("收到客户端消息: %d\n",cmd);
    if(cmd == MC_CMD_C2S_UNINSTALl) {
        tag_C2S_uninstall * punInstall = (tag_C2S_uninstall *)pbuffer;
        printf("收到卸载消息 num = %s , pwd= %s: %d\n",punInstall->num,punInstall->pw,cmd);
        char buffer[256]="";
        m_imcSrv.sendData(MC_CMD_S2C_UNKNOWN,NULL,0);
        sprintf(buffer,"./%s %s %s %s %s &",EDP_UNINSTALL, m_strSrvIp.c_str(),
                punInstall->num, punInstall->pw, m_strDevid.c_str());
        system(buffer);
        return ;
    }
    if(m_nRegGui == pid) { ///注册进程发来的消息号.
        return on_Regui(cmd,pbuffer,len);
    } else {
        return on_Tipui(cmd,pbuffer,len);
    }
    m_imcSrv.sendData(MC_CMD_S2C_UNKNOWN,NULL,0);
}

bool  CVCFApp::onLogon(int id,bool btray ,const char * pUser) {
    ///是否托盘
    if(btray) {
        m_bLoginDeskTop++ ;
        std::string user = pUser ;
        printf("桌面用户登录 %s\n",pUser);
        m_eventNotifyer.sendEvent(enNotifyer_deskUser_logon,&user);
        add_desk_user(user);
    }
    return true ;
}

void  CVCFApp::onLogout(int id) {
    if(id == m_nRegGui){
        m_nRegGui= -1;
    } else {
        ///是否托盘
        CIMCSrv::tag_Cli cli ;
        if(m_imcSrv.getCli(id,cli)) {
            if(cli.bTray) {
                printf("桌面用户推出 %s\n",cli.strparams.c_str());
                del_desk_user(cli.strparams);
                m_bLoginDeskTop--;
            }
        }
    }
}

std::string  CVCFApp::get_Param(std::string & key)  {
    if(key == CLI_LISTEN_PORT) {
        return "22105";
    } else if(key == SRV_ADDRESS) {
        return  m_strSrvIp;
    } else if(key == SRV_LISTEN_PORT) {
        return "88";
    }
    return "" ;
}

bool   CVCFApp::recvnetmsg(enNetRmsg msg , void * pData , int len) {
    tag_NetRmsg * pMsg = (tag_NetRmsg *)pData ;

    switch(msg) {
	///服务器推送概况下来
    case R_CMD_DISTRIBUTE_POLICY : {
        printf("服务器推送概况下来。。。。。。。。。。。。。。。。。。。。。。。。。。。。。。。。。。。。。。。。\n");
        char  *  pbuffer = (char *)pMsg->pData ;
        std::string str_General = pbuffer;
        break;
        return on_Update_pGeneral(str_General,str_General);
    }
    }
    return true ;
}

bool   CVCFApp::onConnect(int error) {

    return true ;
}

bool   CVCFApp::onClose(SOCKET skt, bool close_by_remote) {
    return true ;
}

bool   CVCFApp::onAccept(SOCKET skt,struct sockaddr_in * pAddr) {
    ///判断是否服务器IP
    if(pAddr->sin_addr.s_addr != inet_addr(m_strSrvIp.c_str())) {
        return false ;
    }
    printf("服务器%s连接上来\n",m_strSrvIp.c_str());
    return true ;
}

///启动策略执行
bool   CVCFApp::start_pl4(int pType, int interval, bool once) {
    tag_CallPolicyStart start ;
    start.type = pType ;
    start.interval = interval ;
    start.once = once ;
    ///默认为1000毫秒
    if(start.interval == 0) {
        start.interval = 1000 ;
    }
    return  sendto_Main(VCF_CMD_CALL_POLICY_START,&start,sizeof(tag_CallPolicyStart));
}

int       CVCFApp::get_pl4Status(int pType) {
    return  m_policyMgr.get_policyStat((enPolicytype)pType) ;
}

void      CVCFApp::stop_pl4(int pType) {
    sendto_Main(VCF_CMD_CALL_POLICY_STOP,&pType,sizeof(pType));
}

//创建注册的XML
int  buildXml_tip(tag_GuiTips * tip,char * xml) {
    sprintf(xml,"<?xml version=\"1.0\" encoding=\"utf-8\"?>"\
            "<gui><guitype>tips</guitype><param>"\
            "<tipsid>%d</tipsid>"\
            "<title>%s</title>"\
            "<sign>%u</sign>"\
            "<tip>%s</tip>"\
            "<timeout>%d</timeout>"\
            "<defultret>%d</defultret></param></gui>",g_tipsid,tip->szTitle,tip->sign,tip->szTips,tip->param.timeout,tip->defaultret);
    return g_tipsid++ ;
}
//创建提示的XML
void  buildXml_reg(char * xml) {
    sprintf(xml,"<?xml version=\"1.0\" encoding=\"utf-8\"?><gui><guitype>reg</guitype></gui>");
}


#include "vrvprotocol/VRVProtocol.hxx"
/*status 1-- start 2 stop*/
void report_status_to_server(int status) {
    /*TODO:添加探测业务, 暂时屏蔽上报客户端启动停止*/
    return;
    /*
      if(g_GetlcfgInterface()->is_WinSrv()) {
      return;
      }
    */
    extern bool report_policy_log_spec(tag_Policylog * plog);
    char buffer[2048] = {0};
    tag_Policylog *plog = (tag_Policylog *)buffer;
    plog->type = AGENT_STATUS_REPORT;
    std::string report_info;
    char local_time_str[64] = {0};
    YCommonTool::get_local_time(local_time_str);
    report_info.append("time=");
    report_info.append(local_time_str);
    report_info.append("\n");

    std::string ip_addr;
    g_GetlcfgInterface()->get_lconfig(lcfg_regip, ip_addr);
    report_info.append("IPAddress0=");
    report_info.append(ip_addr.c_str());
    report_info.append("\n");

    switch(status) {
    case CLIENT_START: {
        plog->what = CLIENT_START;
        report_info.append("Content=客户端启动");
    }
        break;
    case CLIENT_STOP: {
        plog->what = CLIENT_STOP;
        report_info.append("Content=客户端退出");
    }
        break;
    default:
        return;
    }

    printf("report to server conetnt is %s\n", report_info.c_str());

    strncpy(plog->log, report_info.c_str(), report_info.length());
    report_policy_log_spec(plog);
    return;
}

std::string CVCFApp::get_server_time() {
    /*TODO: cache server_time */
    std::string ret_info;
    m_NetEngine.sendnetmsg(S_CMD_GET_SERVER_TIME, &ret_info, sizeof(&ret_info));
    std::cout << " on_get_server_time ret_info" << ret_info <<std::endl;
    return ret_info;
}
