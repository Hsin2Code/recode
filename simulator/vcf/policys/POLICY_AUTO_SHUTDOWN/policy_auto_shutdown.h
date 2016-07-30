#ifndef POLICYAUTOSHUTDOWN_H_
#define POLICYAUTOSHUTDOWN_H_
#include "../policysExport.h"

///自动关机函数定义
extern bool  policy_auto_shutdown_init();
extern bool  policy_auto_shutdown_worker(CPolicy *pPolicy, void *pParam);
extern void  policy_auto_shutdown_uninit();


///自动关机策略
class CPolicyAutoShutdown : public CPolicy
{
public:
    CPolicyAutoShutdown()
    {
        enPolicytype type = POLICY_AUTO_SHUTDOWN;
        set_type(type);
    }
    virtual bool import_xml(const char* pxml)
    {
        if(pxml == NULL) 
	{
            return false ;
	}
	CMarkup  xml ;
	if(!xml.SetDoc(pxml)) 
	{
           return false ;
	}
	if(xml.FindElem("vrvscript")) 
	{
            xml.IntoElem();
            while(xml.FindElem("item")) 
	    {
	        UseIdleTimeTest= xml.GetAttrib("UseIdleTimeTest");
            UseSystemTimeTest= xml.GetAttrib("UseSystemTimeTest");
            ShutDownHour= xml.GetAttrib("ShutDownHour");
            ShutDownMinute= xml.GetAttrib("ShutDownMinute");
            ShutDownKeepTime= xml.GetAttrib("ShutDownKeepTime");
            MinuteTime= xml.GetAttrib("MinuteTime");
            TestIdleLockScreen= xml.GetAttrib("TestIdleLockScreen");
            LockSreenTime= xml.GetAttrib("LockSreenTime");
            ShutdownMessage= xml.GetAttrib("ShutdownMessage");
            ShutdownDialogShowInterval= xml.GetAttrib("ShutdownDialogShowInterval");
            UpRegionService= xml.GetAttrib("UpRegionService");
            AllowBootSwitch= xml.GetAttrib("AllowBootSwitch");
            AllowBootStartTimeHour= xml.GetAttrib("AllowBootStartTimeHour");
            AllowBootStartTimeMinute= xml.GetAttrib("AllowBootStartTimeMinute");
	        AllowBootEndTimeHour= xml.GetAttrib("AllowBootEndTimeHour");
            AllowBootEndTimeMinute= xml.GetAttrib("AllowBootEndTimeMinute");
            ViolationApproach= xml.GetAttrib("ViolationApproach");
            PromptContent= xml.GetAttrib("PromptContent");
            IntervalPrompt= xml.GetAttrib("IntervalPrompt");
            IntervalTimes= xml.GetAttrib("IntervalTimes");
        }
            xml.OutOfElem();
    }
		return import_xmlobj(xml);
    }
    virtual void   copy_to(CPolicy *pDest) 
    {
        if(pDest->get_type() != POLICY_AUTO_SHUTDOWN) 
        {
            return;
        }
        CPolicyAutoShutdown *pCtrl = (CPolicyAutoShutdown *)pDest;
        pCtrl->UseIdleTimeTest=UseIdleTimeTest;
        pCtrl->UseSystemTimeTest=UseSystemTimeTest;
        pCtrl->ShutDownHour=ShutDownHour;
        pCtrl->ShutDownMinute=ShutDownMinute;
        pCtrl->ShutDownKeepTime=ShutDownKeepTime;
        pCtrl->MinuteTime=MinuteTime;
        pCtrl->TestIdleLockScreen=TestIdleLockScreen;
        pCtrl->LockSreenTime=LockSreenTime;
        pCtrl->ShutdownMessage=ShutdownMessage;
        pCtrl->ShutdownDialogShowInterval=ShutdownDialogShowInterval;
        pCtrl->UpRegionService=UpRegionService;
        pCtrl->AllowBootSwitch=AllowBootSwitch;
        pCtrl->AllowBootStartTimeHour=AllowBootStartTimeHour;
        pCtrl->AllowBootStartTimeMinute=AllowBootStartTimeMinute;
        pCtrl->AllowBootEndTimeHour=AllowBootEndTimeHour;
        pCtrl->AllowBootEndTimeMinute=AllowBootEndTimeMinute;
        pCtrl->ViolationApproach=ViolationApproach;
        pCtrl->PromptContent=PromptContent; 
        pCtrl->IntervalPrompt=IntervalPrompt; 
        pCtrl->IntervalTimes=IntervalTimes;

        CPolicy::copy_to(pDest);
    }
public:
    std::string UseIdleTimeTest;
    std::string UseSystemTimeTest;
    std::string ShutDownHour;
    std::string ShutDownMinute;
    std::string ShutDownKeepTime;
    std::string MinuteTime;
    std::string TestIdleLockScreen;
    std::string LockSreenTime;
    std::string ShutdownMessage;
    std::string ShutdownDialogShowInterval;
    std::string UpRegionService;
    ///boot
    std::string AllowBootSwitch;
    std::string AllowBootStartTimeHour;
    std::string AllowBootStartTimeMinute;
    std::string AllowBootEndTimeHour;
    std::string AllowBootEndTimeMinute;
    ///deal mode for boot in not allowed time 0:no prompt;1:prompt;2:halt
    std::string ViolationApproach;
    ///boot message
    std::string PromptContent;
    ///boot dialog 1:show dialog in minues;0:no
    std::string IntervalPrompt; 
    std::string IntervalTimes;
};

#endif

