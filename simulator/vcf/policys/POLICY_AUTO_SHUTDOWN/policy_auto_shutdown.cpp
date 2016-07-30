#include "policy_auto_shutdown.h"
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <fcntl.h>
#include <termios.h>
#include <string>
#include <unistd.h>
#include "../../vrvprotocol/VRVProtocol.hxx"
#include "../../vrvprotocol/VRVProtocolEx.hxx"
#include "../../common/Commonfunc.h"
#include "../../vrcport_tool.h"
#include "../../VCFCmdDefine.h"
#include "../../../include/MCInterface.h"
using namespace std;

extern int code_convert(const char *from_charset,const char *to_charset,char *inbuf,int inlen,char *outbuf,int &outlen);
///0:action;1:no action
static int g_mouse_action;
static int g_hour,g_minutes;
///0:deal,shut down;1:don't deal;
static int deal_halt; 
///0:lock screen;1:don't lock
static int deal_lock; 
static int lock_flag;
///0:boot in not allowed time;1:allowed time
static int deal_boot; 
static int promp_times;
///0:halt in setted time;1:don't ---for shut down,boot in a minutes
static int halt_flag; 
static int diaglog_flag;
static int detect_interval;
static int minu_promp;
static int dialog_flag;
static int times;
static int keep_times;
static int boot_dialog_flag;
static int boot_interval_dialog = 0;
static unsigned int old_crcvalue;
static int dialog_return_rnt_1 =  -1;
static int dialog_return_rnt_2 =  -1;
static int dialog_return_rnt_3 =  -1;


struct timespec  mutex_timeout; // 线程锁超时
pthread_mutex_t mutex1 =  PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t condition1 =  PTHREAD_COND_INITIALIZER;
pthread_mutex_t mutex2 =  PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t condition2 =  PTHREAD_COND_INITIALIZER;
pthread_mutex_t mutex3 =  PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t condition3 =  PTHREAD_COND_INITIALIZER;

#define MOUSE_FILE_PATH "/dev/input/mice"
#define KEYBORT_FILE_PATH "/dev/input/event2"

#define ARR_LENGTH 1024

static const char *en_month[] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
static  volatile  bool  g_exitSign = false ;

//struct  CAutoDownCtrl
//{
//public:
//    CAutoDownCtrl();
//    virtual ~CAutoDownCtrl();
//public:
//pthread_t pid_mainctrl_autodown;
static pthread_t pid_keyboard_event;
static pthread_t pid_mouse_event;    
//};

static CPolicyAutoShutdown *g_pPolicyAutoShutdown = NULL;
//static CAutoDownCtrl* g_pAutoDownCtrl = NULL;

static   volatile    bool   g_adv_enable_autoshutdon = true ;
static   void   advcfg_statchage(void *pParam) 
{
    bool *pbool = ( bool *)pParam;
    g_adv_enable_autoshutdon = *pbool ;
}

//new add
extern ILocalogInterface* g_GetlogInterface(void) ;
static void autoshutdown_log_run_info(const char *log_content)
{
    char log_info[2048] = {0};

    if(NULL == log_content)
    {
        return ;
    }
        
    snprintf(log_info, sizeof(log_info), "autoshutdown:%s\n", log_content);

    g_GetlogInterface()->loglog(log_info);
}
//

vector<string> split_new(const string& src, string delimit, string null_subst)
{
    vector<string> v;

    if( src.empty() || delimit.empty() )
    {
        throw "split:empty string/0";
    }

    typedef basic_string<char>::size_type S_T;
    S_T deli_len = delimit.size();
    unsigned long index = string::npos, last_search_position = 0;

    while( (index=src.find(delimit,last_search_position))!=string::npos )
    {
        if(index==last_search_position)
        {
            v.push_back(null_subst);
        }
        else
        {
            v.push_back( src.substr(last_search_position, index-last_search_position) );
        }
        last_search_position = index + deli_len;
    }
    string last_one = src.substr(last_search_position);
    v.push_back( last_one.empty()? null_subst:last_one );

    return v;
}

struct tm *Get_LocalTime()
{
    time_t   now;
    struct   tm     *timenow;

    time(&now);
    timenow   =   localtime(&now);
    return timenow;
}

static string Change_Month_To_Digit(string str_month)
{
    string str_tmp;
    char ch_tmp[8] = {0};
    for(unsigned int index = 0; index < sizeof(en_month)/sizeof(char *); index++)
    {
        if(str_month == en_month[index])
        {
            sprintf(ch_tmp,"%d",index+1);
            return str_tmp.assign(ch_tmp);
        }
    }
    return str_tmp;
}

void CurRebootTime(string &info)
{
    char timech[ARR_LENGTH];
    FILE *fp = popen("last | grep reboot | awk \'{print $6,$7,$8}\'", "r");
    if(NULL == fp) 
    {
        return;
    }

    fgets(timech, ARR_LENGTH-1, fp);    
    timech[strlen(timech)] = '\0';
    string str_tmp;
    str_tmp.assign(timech);
    vector<string> vec_tmp = split_new(str_tmp, " ", "");
    string str_month = Change_Month_To_Digit(vec_tmp[0]);
    struct tm *ptm;
    char year[8] = {0};
    ptm = Get_LocalTime();
    sprintf(year,"%d",ptm->tm_year + 1900);
    str_tmp.clear();
    str_tmp.assign(year);
    str_tmp += "-" + str_month + "-" + vec_tmp[1]+ " " + vec_tmp[2];
    info = str_tmp.substr(0,str_tmp.length()-1);

    pclose(fp);
}

void autoshutdown_user_choice_1(unsigned int sign)
{
    cout<<"sign: "<<sign<<endl;
    dialog_return_rnt_1 = sign;
    cout<<"dialog_return_rnt_1: "<<dialog_return_rnt_1<<endl;
    pthread_mutex_lock(&mutex1);
    pthread_cond_signal(&condition1);
    pthread_mutex_unlock(&mutex1);
}
void autoshutdown_user_choice_2(unsigned int sign)
{
    dialog_return_rnt_2 = sign;
    pthread_mutex_lock(&mutex2);
    pthread_cond_signal(&condition2);
    pthread_mutex_unlock(&mutex2);
}
void autoshutdown_user_choice_3(unsigned int sign)
{
    dialog_return_rnt_3 = sign;
    pthread_mutex_lock(&mutex3);
    pthread_cond_signal(&condition3);
    pthread_mutex_unlock(&mutex3);
}

void Illegal_Deal(int kind,int deal,string str)
{
    char log_infos[512]={0};
    memset(log_infos,0,sizeof(log_infos));
    sprintf(log_infos,"illgal_deal paras is : kind %d , deal %d , str %s",kind,deal,str.c_str());
    autoshutdown_log_run_info("ok enter illeage_deal");
    autoshutdown_log_run_info(log_infos);
    if("1" == g_pPolicyAutoShutdown->UpRegionService && 0 != kind)
    {
        string SysUserName;

        //YCommonTool::get_ttyloginUser("tty1", SysUserName);
        get_desk_user(SysUserName);
        if("" == SysUserName)
        {
            SysUserName="root";
        }
        char szTime[21]="";
        YCommonTool::get_local_time(szTime);
        string str_kind;
        switch(kind)
        {
        case 1:
            str_kind = g_pPolicyAutoShutdown->MinuteTime + "分钟鼠标键盘无动作，自动关机!!";
            break;
        case 2:
            str_kind = "超出关机设定时间，用户取消关机!!";
            break;
        case 3:
            str_kind = "允许开机时间外开机，系统自动关机!!";
            break;
        case 4:
            str_kind = "关机探测时间之后重新开机!!";
            break;
        case 5:
            str_kind = "超出策略设置持续时间，系统关机!!";
            break;
        case 6:
            str_kind = "开机时间超出指定时间，此次开机时间：" + str;
            break;
        case 7:
            str_kind = g_pPolicyAutoShutdown->LockSreenTime + "分钟鼠标键盘无动作，自动锁屏！";
            break;
        default:
            break;
        }

        char buffer[2048]={0};
        tag_Policylog *plog = (tag_Policylog *)buffer ;
        plog->type = AGENT_RPTAUDITLOG;
        plog->what = AUDITLOG_REQUEST;
        char *pTmp = plog->log ;
        sprintf(pTmp,"Body0=time=%s<>kind=1801<>policyid=%d<>policyname=%s<>KeyUserName=%s<>classaction=%d<>riskrank=%d<>context=%s%s%s%s"
                ,szTime
                ,g_pPolicyAutoShutdown->get_id()
                ,g_pPolicyAutoShutdown->get_name().c_str()
                ,SysUserName.c_str()
                ,Illegal_Behavior
                ,Event_Alarm
                ,str_kind.c_str()
                ,STRITEM_TAG_END
                ,"BodyCount=1"
                ,STRITEM_TAG_END);
        cout<<"ok...............report................."<<pTmp<<endl;
        if(1!=deal)
        {
            report_policy_log(plog);
        }
        else
        {
            report_policy_log(plog,true);
        }
        //cout<<"ok report_policy_log to server 7"<<endl;
    }
    if(1 == deal)
    {
        cout<<"ok...............shutdown ................."<<endl;
        g_GetSendInterface()->sendto_Main(VCF_CMD_CALL_SHUTDOWN,NULL,0);
    }
}

void *Listen_Ms(void *arg)
{
    struct tm *ptm;

    int fd = open(MOUSE_FILE_PATH,O_RDONLY);
    if(0 > fd)
    {
        //pthread_exit(arg);
        pthread_exit(0);
    }
    char buf[256] = {0};
    while(g_exitSign)
    {
        if(!g_adv_enable_autoshutdon) 
        {
            usleep(10000);
            continue ;
        }
        if(0 < read(fd,buf,255))
        {
            //cout<<"mouse set g_mouse_action 0"<<endl;
            g_mouse_action = 0;
            ptm = Get_LocalTime();
            g_hour = ptm->tm_hour;
            g_minutes = ptm->tm_min;
        }
        //else
        //{
        //g_mouse_action=1;
        //ptm=Get_LocalTime();
        //g_hour=ptm->tm_hour;
        //g_minutes=ptm->tm_min;
        //}
        usleep(2000);
    }
    close(fd);
    return NULL;
}
int kbhit(void)
{
    struct termios oldt, newt;
    int ch;
    int oldf;

    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    oldf = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK);
    ch = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    fcntl(STDIN_FILENO, F_SETFL, oldf);
    if(ch != EOF)
    {
        return 1;
    }
    return 0;
}
void *Monitor_Keybord(void *arg)
{    
    while(g_exitSign)
    {
        if(!g_adv_enable_autoshutdon) 
        {
            usleep(10000);
            continue ;
        }
        if(0 != kbhit())
        {
            //cout<<"keybord set g_mouse_action 0"<<endl;
            g_mouse_action = 0;
            struct tm *ptm;
            ptm = Get_LocalTime();
            g_hour = ptm->tm_hour;
            g_minutes = ptm->tm_min;
        }
        //else//add
        //{
        //g_mouse_action=1;
        //struct tm *ptm;
        //ptm=Get_localTime();
        //g_hour=ptm->tm_hour();
        //g_minutes=ptm->tm_min();
        //}
        usleep(2000);
    }
    return NULL;
}

bool  policy_auto_shutdown_init() 
{
    cout<<"enter AutoShutdown_policy_init() "<<endl;
    autoshutdown_log_run_info("enter policy_auto_shutdown_init");

    int prnt1_mouse = 0;
    int prnt2_keyboard = 0;
    int inot_fd = 0;
    g_exitSign = true;
    //if(g_pAutoDownCtrl == NULL)
    //{
    //g_pAutoDownCtrl = new CAutoDownCtrl;
    //}
    ///开始鼠标事件检测
    //prnt1_mouse = pthread_create(&g_pAutoDownCtrl->pid_mouse_event, NULL, Listen_Ms, &inot_fd);
    g_adv_enable_autoshutdon= true;
    g_GetEventNotifyinterface()->registerEvent(enNotifyer_policyAdvcfg_statChange,advcfg_statchage);
    prnt1_mouse = pthread_create(&pid_mouse_event, NULL, Listen_Ms, &inot_fd);
    if(prnt1_mouse) 
    {
        return false;
    }
    ///开始键盘事件检测
    //prnt2_keyboard = pthread_create(&g_pAutoDownCtrl->pid_keyboard_event,NULL,Monitor_Keybord,NULL);
    prnt2_keyboard = pthread_create(&pid_keyboard_event,NULL,Monitor_Keybord,NULL);
    if(prnt2_keyboard)
    {
        return false;
    }

    cout<<"leave AutoShutdown_policy_init() "<<endl;
    autoshutdown_log_run_info("leave policy_auto_shutdown_init");
    return  true ;
}

bool policy_auto_shutdown_worker(CPolicy * pPolicy, void * pParam) 
{
    cout<<"enter  AutoShutdown_policy_worker()"<<endl;
    autoshutdown_log_run_info("enter policy_auto_shutdown_worker");

    ///获取当前策略类型
    if(pPolicy->get_type() != POLICY_AUTO_SHUTDOWN) 
    {
        return false ;
    }

    if(g_pPolicyAutoShutdown == NULL) 
    {
        g_pPolicyAutoShutdown = new CPolicyAutoShutdown ;
        if(g_pPolicyAutoShutdown == NULL)
        {
            return false;
        }
    }

    //pPolicy->copy_to(g_pPolicyAutoShutdown);
    g_pPolicyAutoShutdown = (CPolicyAutoShutdown*)pPolicy;
    if(old_crcvalue != g_pPolicyAutoShutdown->get_crc())
    {
        autoshutdown_log_run_info("reinit all vars......");
        diaglog_flag = 0;
        minu_promp = 0;
        dialog_flag = 0;
        times = 0;
        keep_times = 0;
        boot_dialog_flag = 0;
        lock_flag = 0;
        deal_lock = 1;

        if(atoi(g_pPolicyAutoShutdown->ShutDownKeepTime.c_str()) > atoi(g_pPolicyAutoShutdown->ShutdownDialogShowInterval.c_str()))
        {
            promp_times = atoi(g_pPolicyAutoShutdown->ShutDownKeepTime.c_str())/atoi(g_pPolicyAutoShutdown->ShutdownDialogShowInterval.c_str());
        }
        else
        {
            promp_times = 0;
        }
          
        struct tm *ptm;
        int h_now,n_now,h_cal,n_cal;
        ptm = Get_LocalTime();
        h_now = ptm->tm_hour;
        n_now = ptm->tm_min;
        h_cal = atoi(g_pPolicyAutoShutdown->ShutDownHour.c_str()) + (atoi(g_pPolicyAutoShutdown->ShutDownMinute.c_str()) + atoi(g_pPolicyAutoShutdown->ShutDownKeepTime.c_str()))/60;
        n_cal = (atoi(g_pPolicyAutoShutdown->ShutDownMinute.c_str()) + atoi(g_pPolicyAutoShutdown->ShutDownKeepTime.c_str()))%60;
        halt_flag = 1;
        if(h_now > h_cal)
        {
            halt_flag = 0;
        }
        else if(h_now == h_cal)
        {
            if(h_now > h_cal)
            {
                halt_flag = 0;
            }
        }
        if(0 == halt_flag && "1" == g_pPolicyAutoShutdown->UseSystemTimeTest)
        {
            Illegal_Deal(4,0,"");///关机探测时间之后重新开机
        }

        //static int boot_interval_dialog = 0;
        boot_interval_dialog = 0;
        //deal_halt = 1;
        //deal_boot = 1;

        g_mouse_action = 0;
        ptm = Get_LocalTime();
        g_hour = ptm->tm_hour;
        g_minutes = ptm->tm_min;
        ///save policy crc
        old_crcvalue = g_pPolicyAutoShutdown->get_crc();
    }

    char log_infos[512]={0};
    //
    deal_halt = 1;
    deal_boot = 1;
    struct tm *ptm;
    int h,n;
    ptm = Get_LocalTime();
    h = ptm->tm_hour;
    n = ptm->tm_min;

    cout<<"g_mouse_action:"<<g_mouse_action<<endl;
    cout<<"h: "<<h<<endl;
    cout<<"n: "<<n<<endl;
    if(h < g_hour)
    {
        h=h+24;
        cout<<"2h: "<<h<<endl;
    }

    sprintf(log_infos,"g_mouse_action is %d, h is %d, n is %d",g_mouse_action,h,n);
    autoshutdown_log_run_info(log_infos);
          
    if(1 == g_mouse_action)///鼠标键盘无动作
    {
        if("1" == g_pPolicyAutoShutdown->UseIdleTimeTest)///使用计算机空闲探测关机
        {
            cout<<"use idle time test"<<endl;
            cout<<"g_pPolicyAutoShutdown->MinuteTime:"<<g_pPolicyAutoShutdown->MinuteTime<<endl;
            memset(log_infos,0,sizeof(log_infos));
            sprintf(log_infos,"g_pPolicyAutoShutdown->MinuteTime is %s",g_pPolicyAutoShutdown->MinuteTime.c_str());
            autoshutdown_log_run_info(log_infos);
            cout<<"(n + 60*(h - g_hour) - g_minutes): "<<(n + 60*(h - g_hour) - g_minutes)<<endl;
            memset(log_infos,0,sizeof(log_infos));
            sprintf(log_infos,"(n + 60*(h - g_hour) - g_minutes) is %d",(n + 60*(h - g_hour) - g_minutes));
            autoshutdown_log_run_info(log_infos);
            if(atoi(g_pPolicyAutoShutdown->MinuteTime.c_str()) <= (n + 60*(h - g_hour) - g_minutes))
            {
                autoshutdown_log_run_info("ok handle shutdown");
                cout<<"ok handle"<<endl;
                char buffer[512] = "";
                tag_GuiTips * pTips = (tag_GuiTips *)buffer ;
                pTips->sign = en_TipsGUI_btnYes | en_TipsGUI_btnNo | en_TipsGUI_timeOut;
                pTips->defaultret = en_TipsGUI_btnYes;
                sprintf(pTips->szTitle,"%s","提示");
                char outbuffer[129]="";
                int  out_len = 129 ;
                code_convert("gb2312","utf-8",const_cast<char *>(g_pPolicyAutoShutdown->ShutdownMessage.c_str()),g_pPolicyAutoShutdown->ShutdownMessage.length(),outbuffer,out_len);
                sprintf(pTips->szTips,"%s",outbuffer);
                pTips->pfunc = autoshutdown_user_choice_1;
                pTips->param.timeout = 15000;
                cout<<"call the tips"<<endl;
                autoshutdown_log_run_info("sent to main gui tips");
                g_GetSendInterface()->sendto_Main(VCF_CMD_GUI_TIPS,buffer,sizeof(tag_GuiTips));
                pthread_mutex_lock(&mutex1);
                mutex_timeout.tv_sec = time(NULL) + 16;
                pthread_cond_timedwait(&condition1,&mutex1,&mutex_timeout);
                pthread_mutex_unlock(&mutex1);
                //if(1 == dialog_return_rnt_1)
                memset(log_infos,0,sizeof(log_infos));
                sprintf(log_infos,"return value 1 is %d",dialog_return_rnt_1);
                autoshutdown_log_run_info(log_infos);
                cout<<"@@@@@@dialog_return_rnt_1: "<<dialog_return_rnt_1<<endl;
                if(en_TipsGUI_btnNo != dialog_return_rnt_1)
                {
                    Illegal_Deal(1,1,"");///xxx分钟内鼠标键盘无动作自动关机
                }
            }
        }
        if("1" == g_pPolicyAutoShutdown->TestIdleLockScreen)///使用计算机空闲探测锁屏
        {
            memset(log_infos,0,sizeof(log_infos));
            sprintf(log_infos,"g_pPolicyAutoShutdown->TestIdleLockScreen: %s , g_pPolicyAutoShutdown->LockSreenTime %s , (n + 60*(h - g_hour) - g_minutes) %d", g_pPolicyAutoShutdown->TestIdleLockScreen.c_str(),g_pPolicyAutoShutdown->LockSreenTime.c_str(),(n + 60*(h - g_hour) - g_minutes));
            autoshutdown_log_run_info(log_infos);
            cout<<"test lockscreen."<<endl;
            cout<<"ok g_pPolicyAutoShutdown->TestIdleLockScreen : "<< g_pPolicyAutoShutdown->TestIdleLockScreen<<endl;
            cout<<"left: "<<atoi(g_pPolicyAutoShutdown->LockSreenTime.c_str())<<endl;
            cout<<"right: "<<(n + 60*(h - g_hour) - g_minutes)<<endl;
            if(atoi(g_pPolicyAutoShutdown->LockSreenTime.c_str()) == (n + 60*(h - g_hour) - g_minutes))
            {
                //cout<<"ok lock screen"<<endl;
                deal_lock= 0;
            }
            else
            {
                deal_lock = 1;
            }
            cout<<"deal_lock "<<deal_lock<<endl;
        }
    }
    else
    {
        if(h >= 24)
        {
            g_hour=h-24;
        }
        else
        {
            g_hour = h;
        }
        g_minutes = n;
        deal_lock = 1;
    }
    if(h >= 24)
    {
        h=h-24;
    }
    cout<<"1111111111"<<endl;
    autoshutdown_log_run_info("111111111111");
    ///使用系统时间探测并且未超出探测时间          
    if(("1" == g_pPolicyAutoShutdown->UseSystemTimeTest)  && (1 == halt_flag))
    {
        if(h == atoi(g_pPolicyAutoShutdown->ShutDownHour.c_str()))
        {
            if(n == atoi(g_pPolicyAutoShutdown->ShutDownMinute.c_str()) || n > atoi(g_pPolicyAutoShutdown->ShutDownMinute.c_str()) )
            {
                if(0 != deal_halt)
                {
                    deal_halt = 0;
                }
            }
        }
        else if(h > atoi(g_pPolicyAutoShutdown->ShutDownHour.c_str()))
        {
            deal_halt = 0;
        }
    }
    cout<<"deal_halt: "<<deal_halt<<endl;
    cout<<"222222222"<<endl;
    autoshutdown_log_run_info("222222222222");
    cout<<"deal_lock: "<<deal_lock<<endl;
    ///处理锁屏 
    if(0 == deal_lock )
    {
        cout<<"start deal_lock. "<<endl;
        deal_lock = 1;
        //int ret;
        autoshutdown_log_run_info("send lock screen signal");
        g_GetSendInterface()->sendto_Main(VCF_CMD_LOCK_SCREEN,NULL,0);
        cout<<"finish sendto main msg"<<endl;
        //
        //if(0 == ret)  
        //{
        Illegal_Deal(7, 0,"");///xxx分钟鼠标键盘无动作，自动锁屏
        //}
    }
    cout<<"3333333333"<<endl;
    autoshutdown_log_run_info("333333333333");
    ///允许开始时间
    if("1" == g_pPolicyAutoShutdown->AllowBootSwitch)
    {
        if(h < atoi(g_pPolicyAutoShutdown->AllowBootStartTimeHour.c_str())||h > atoi(g_pPolicyAutoShutdown->AllowBootEndTimeHour.c_str()))
        {
            deal_boot = 0;
        }
        else if(atoi(g_pPolicyAutoShutdown->AllowBootStartTimeHour.c_str()) == h || atoi(g_pPolicyAutoShutdown->AllowBootEndTimeHour.c_str()) == h)
        {
            if(atoi(g_pPolicyAutoShutdown->AllowBootStartTimeMinute.c_str()) > n || atoi(g_pPolicyAutoShutdown->AllowBootEndTimeMinute.c_str()) < n)
            {
                deal_boot = 0;
            }
        }

    }
    cout<<"deal_boot "<<deal_boot<<endl;
    cout<<"4444444444"<<endl;
    autoshutdown_log_run_info("44444444444444");
    ///处理系统探测关机 
    ///这个算法有点麻烦 
    if(0 == deal_halt)
    {
        cout<<"deal_hatl is 0"<<endl;
        autoshutdown_log_run_info("deal_hatl = 0");
        if(keep_times == atoi(g_pPolicyAutoShutdown->ShutDownKeepTime.c_str()) || atoi(g_pPolicyAutoShutdown->ShutDownKeepTime.c_str()) < atoi(g_pPolicyAutoShutdown->ShutdownDialogShowInterval.c_str()))
        {
            autoshutdown_log_run_info("shutdown right now........");
            char buffer[512] = "";
            tag_GuiTips * pTips = (tag_GuiTips *)buffer ;
            pTips->sign = en_TipsGUI_btnOK | en_TipsGUI_timeOut;
            pTips->defaultret = en_TipsGUI_None;
            sprintf(pTips->szTitle,"%s","提示");
            char outbuffer[129]="";
            int  out_len = 129 ;
            code_convert("gb2312","utf-8",const_cast<char *>(g_pPolicyAutoShutdown->ShutdownMessage.c_str()),g_pPolicyAutoShutdown->ShutdownMessage.length(),outbuffer,out_len);                
            sprintf(pTips->szTips,"%s",outbuffer);
            pTips->pfunc = NULL;
            pTips->param.timeout = 5000;
            autoshutdown_log_run_info("sendto main tips right now..........");
            g_GetSendInterface()->sendto_Main(VCF_CMD_GUI_TIPS,buffer,sizeof(tag_GuiTips));
            Illegal_Deal(5,1,"");///超出策略设置持续时间，系统关机
        } 
        else
        {
            if(0 == diaglog_flag)
            {
                autoshutdown_log_run_info("shutdown select 1............dialog_flag is 0");
                char buffer[512] = "";
                tag_GuiTips * pTips = (tag_GuiTips *)buffer ;
                pTips->sign = en_TipsGUI_btnYes | en_TipsGUI_btnNo | en_TipsGUI_timeOut;
                pTips->defaultret = en_TipsGUI_btnNo;
                sprintf(pTips->szTitle,"%s","提示");
                char outbuffer[129]="";
                int  out_len = 129 ;
                code_convert("gb2312","utf-8",const_cast<char *>(g_pPolicyAutoShutdown->ShutdownMessage.c_str()),g_pPolicyAutoShutdown->ShutdownMessage.length(),outbuffer,out_len);
                sprintf(pTips->szTips,"%s",outbuffer);
                pTips->pfunc = autoshutdown_user_choice_2;
                pTips->param.timeout = 5000;
                autoshutdown_log_run_info("shutdown select 1.....................send tips");
                g_GetSendInterface()->sendto_Main(VCF_CMD_GUI_TIPS,buffer,sizeof(tag_GuiTips));
                pthread_mutex_lock(&mutex2);
                mutex_timeout.tv_sec = time(NULL) + 6;
                pthread_cond_timedwait(&condition2,&mutex2,&mutex_timeout);
                pthread_mutex_unlock(&mutex2);
                //detect_interval = dialog_return_rnt_2;
                if(en_TipsGUI_btnYes ==  dialog_return_rnt_2)
                {
                    detect_interval = 1;
                }
                else
                {
                    detect_interval = 0;
                }
                diaglog_flag = 1;
            }
            if(0 == detect_interval)
            {
                cout<<"times: "<<times<<endl;
                cout<<"detect_interval = 0"<<endl;
                autoshutdown_log_run_info("detect_interval is 0");
                if(times != atoi(g_pPolicyAutoShutdown->ShutdownDialogShowInterval.c_str()))
                {
                    cout<<"times: "<<times<<endl;
                    times++;
                    cout<<"times++"<<endl;
                }
                else
                {
                    cout<<"open tips windows"<<endl;
                    char buffer[512] = "";
                    tag_GuiTips * pTips = (tag_GuiTips *)buffer ;
                    pTips->sign = en_TipsGUI_btnYes | en_TipsGUI_btnNo | en_TipsGUI_timeOut;
                    pTips->defaultret = en_TipsGUI_btnNo;
                    sprintf(pTips->szTitle,"%s","提示");
                    char outbuffer[129]="";
                    int  out_len = 129 ;
                    code_convert("gb2312","utf-8",const_cast<char *>(g_pPolicyAutoShutdown->ShutdownMessage.c_str()),g_pPolicyAutoShutdown->ShutdownMessage.length(),outbuffer,out_len);
                    sprintf(pTips->szTips,"%s",outbuffer);
                    pTips->pfunc = autoshutdown_user_choice_3;
                    //pTips->param.timeout = 10;
                    pTips->param.timeout = 5000;
                    autoshutdown_log_run_info("shutdown select 2.....................send tips");
                    cout<<"send tips........."<<endl;
                    g_GetSendInterface()->sendto_Main(VCF_CMD_GUI_TIPS,buffer,sizeof(tag_GuiTips));
                    pthread_mutex_lock(&mutex3);
                    mutex_timeout.tv_sec = time(NULL) + 6;
                    pthread_cond_timedwait(&condition3,&mutex3,&mutex_timeout);
                    pthread_mutex_unlock(&mutex3);
                    //detect_interval = dialog_return_rnt_3;
                    cout<<"dialog_return_rnt_3: "<<dialog_return_rnt_3<<endl;
                    if(en_TipsGUI_btnYes == dialog_return_rnt_3)
                    {
                        detect_interval = 1;
                    }
                    else
                    {
                        detect_interval = 0;
                    }
                    //times=0;
                    times=1;
                }
            }
            if(1 == detect_interval)
            {
                autoshutdown_log_run_info("send 0,1");
                Illegal_Deal(0,1,"");
            }
            else if(0 == detect_interval)
            {
                autoshutdown_log_run_info("send 2,0");
                Illegal_Deal(2, 0,"");///"超出关机设定时间，用户取消关机
            }
        }
        keep_times++;
    }
    cout<<"5555555555"<<endl;
    autoshutdown_log_run_info("55555555555");
    ///处理非允许时间段内开机  
    if(0 == deal_boot)
    {
        autoshutdown_log_run_info("deal_boot is 0");
        switch(atoi(g_pPolicyAutoShutdown->ViolationApproach.c_str()))
        {
        case 0:///不提示
            break;
        case 1:///提示
        {
            cout<<"case 1 "<<endl;
            autoshutdown_log_run_info("open computer case 1");
            if("1" == g_pPolicyAutoShutdown->IntervalPrompt)///是否间隔提示
            {
                if(0 == minu_promp||boot_interval_dialog == atoi(g_pPolicyAutoShutdown->IntervalTimes.c_str()))
                {
                    char buffer[512] = "";
                    tag_GuiTips * pTips = (tag_GuiTips *)buffer ;
                    pTips->sign = en_TipsGUI_btnOK | en_TipsGUI_timeOut;
                    pTips->defaultret = en_TipsGUI_None;
                    sprintf(pTips->szTitle,"%s","提示");
                    char outbuffer[129]="";
                    int  out_len = 129 ;
                    code_convert("gb2312","utf-8",const_cast<char *>(g_pPolicyAutoShutdown->PromptContent.c_str()),g_pPolicyAutoShutdown->PromptContent.length(),outbuffer,out_len);
                    sprintf(pTips->szTips,"%s",outbuffer);
                    pTips->pfunc = NULL;
                    pTips->param.timeout = 5000;
                    autoshutdown_log_run_info("open computer case 1 send tips aaaaaaaaa");
                    g_GetSendInterface()->sendto_Main(VCF_CMD_GUI_TIPS,buffer,sizeof(tag_GuiTips));
                    boot_interval_dialog = 0;
                    minu_promp = 1;
                }
            }
            else if("0" == g_pPolicyAutoShutdown->IntervalPrompt && 0 == dialog_flag)
            {
                char buffer[512] = "";
                tag_GuiTips * pTips = (tag_GuiTips *)buffer ;
                pTips->sign = en_TipsGUI_btnOK | en_TipsGUI_timeOut;
                pTips->defaultret = en_TipsGUI_None;
                sprintf(pTips->szTitle,"%s","提示");
                char outbuffer[129]="";
                int  out_len = 129 ;
                code_convert("gb2312","utf-8",const_cast<char *>(g_pPolicyAutoShutdown->PromptContent.c_str()),g_pPolicyAutoShutdown->PromptContent.length(),outbuffer,out_len);
                sprintf(pTips->szTips,"%s",outbuffer);
                pTips->pfunc = NULL;
                pTips->param.timeout = 5000;
                autoshutdown_log_run_info("open computer case 1 send tips bbbbbbbb");
                g_GetSendInterface()->sendto_Main(VCF_CMD_GUI_TIPS,buffer,sizeof(tag_GuiTips));
                dialog_flag = 1;
            }
            else
            {
                cout<<"other option"<<endl;
            }
                                
            if(0 == boot_dialog_flag)
            {
                string str_start_time;
                CurRebootTime(str_start_time);
                Illegal_Deal(6, 0, str_start_time);///开机时间超出指定时间，此次开机时间：xxx
                boot_dialog_flag = 1;
            }
        }
        break;
        case 2:///关机
            Illegal_Deal(3,1,"");///允许开机时间外开机，系统自动关机
            break;
        default:
            break;
        }
    }
    cout<<"66666666666"<<endl;
    autoshutdown_log_run_info("66666666666666666");
    g_mouse_action = 1;
    ++boot_interval_dialog;

    cout<<"leave  AutoShutdown_policy_worker()"<<endl;
    autoshutdown_log_run_info("leave policy_auto_shutdown_worker");

    return true;
}

void policy_auto_shutdown_uninit() 
{
    cout<<"enter AutoShutdown_policy_Uninit()"<<endl;
    autoshutdown_log_run_info("enter policy_auto_shutdown_uninit");

    int res;
    void *thread_result;

    g_exitSign = false;
    res = pthread_cancel(pid_mouse_event);
    res = pthread_join(pid_mouse_event, &thread_result);
    res = pthread_cancel(pid_keyboard_event);
    res = pthread_join(pid_keyboard_event, &thread_result);

    pthread_mutex_destroy(&mutex1);
    pthread_cond_destroy(&condition1);
    pthread_mutex_destroy(&mutex2);
    pthread_cond_destroy(&condition2);
    pthread_mutex_destroy(&mutex3);
    pthread_cond_destroy(&condition3);
    g_GetEventNotifyinterface()->UnregisterEvent(enNotifyer_policyAdvcfg_statChange,advcfg_statchage);

    //if(g_pAutoDownCtrl != NULL)
    //{
    //delete g_pAutoDownCtrl;
    //g_pAutoDownCtrl = NULL;
    //}
    if(g_pPolicyAutoShutdown != NULL)
    {
        //delete g_pPolicyAutoShutdown;
        g_pPolicyAutoShutdown = NULL;
    }

    cout<<"leave AutoShutdown_policy_Uninit()"<<endl;
    autoshutdown_log_run_info("leave policy_auto_shutdown_uninit");
    return;
}
