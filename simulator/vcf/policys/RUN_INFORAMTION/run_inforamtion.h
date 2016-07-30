#ifndef POLICYRUNINFORAMTION_H_
#define POLICYRUNINFORAMTION_H_
#include "../policysExport.h"

//
//#include <iostream>
//using namespace std;
//

///运行资源监控函数定义
extern bool run_inforamtion_init();
extern bool run_inforamtion_worker(CPolicy *pPolicy, void *pParam);
extern void run_inforamtion_uninit();

///运行资源监控策略
class CPolicyRunInforamtion : public CPolicy
{
public:
    CPolicyRunInforamtion()
    {
        enPolicytype type = RUN_INFOMATION;
        set_type(type);
    }
    virtual bool import_xml(const char *pxml)
    {
        //cout<<"runinformation import_xml"<<endl;
        if(pxml == NULL) 
        {
            //cout<<"pxml null"<<endl;
            return false ;
        }
        CMarkup  xml ;
	if(!xml.SetDoc(pxml)) 
	{
	     //cout<<"xml setdoc !"<<endl;
        return false ;
	}
	if(xml.FindElem("vrvscript")) 
	{
        xml.IntoElem();
        while(xml.FindElem("item")) 
	    {
            CPUPercent=xml.GetAttrib("CPUPercent");
            CPUTemperature=xml.GetAttrib("CPUTemperature");
	        CPUKeepTime=xml.GetAttrib("CPUKeepTime");
            CPUTempKeepTime=xml.GetAttrib("CPUTempKeepTime");
	        CPUUpInfo=xml.GetAttrib("CPUUpInfo");
	        CPUPrompt=xml.GetAttrib("CPUPrompt");
	        CPUPromptInfo=xml.GetAttrib("CPUPromptInfo");
	        MEMPercent=xml.GetAttrib("MEMPercent"); 
	        MEMKeepTime=xml.GetAttrib("MEMKeepTime");
	        MEMUpInfo=xml.GetAttrib("MEMUpInfo");
	        MEMPrompt=xml.GetAttrib("MEMPrompt");
	        MEMPromptInfo=xml.GetAttrib("MEMPromptInfo");
	        DiskTemperature=xml.GetAttrib("DiskTemperature");
	        DiskTemperatureKeepTime=xml.GetAttrib("DiskTemperatureKeepTime");	
	        MinSystemDiskSpace=xml.GetAttrib("MinSystemDiskSpace");
	        CheckOtherDisk=xml.GetAttrib("CheckOtherDisk");
	        DISKUpInfo=xml.GetAttrib("DISKUpInfo");
	        DISKPrompt=xml.GetAttrib("DISKPrompt");
	        DISKPromptInfo=xml.GetAttrib("DISKPromptInfo");
            IOOutSpeed = xml.GetAttrib("IOOutSpeed");
            IOOutSpeedKeepTime=xml.GetAttrib("IOOutSpeedKeepTime");
            IOInSpeed=xml.GetAttrib("IOInSpeed");
            IOInSpeedKeepTime=xml.GetAttrib("IOInSpeedKeepTime");
            IOReport=xml.GetAttrib("IOReport");
            IOClientPrompt=xml.GetAttrib("IOClientPrompt");
            IOClientPromtInfo=xml.GetAttrib("IOClientPromtInfo");
	        ProcessCPUPercent=xml.GetAttrib("ProcessCPUPercent");
	        ProcessCPUKeepTime=xml.GetAttrib("ProcessCPUKeepTime");
	        ProcessMemoryPercent=xml.GetAttrib("ProcessMemoryPercent");
	        ProcessMemoryKeepTime=xml.GetAttrib("ProcessMemoryKeepTime");
	        //ProcessPrompt=xml.GetAttrib("ProcessPrompt");//diff
	        ProcessPrompt=xml.GetAttrib("ProcessIOReport");
	        //ProcessInfo=xml.GetAttrib("ProcessInfo");//diff
	        ProcessInfo=xml.GetAttrib("ProcessIOClientPrompt");
	        //ProcessPromptInfo=xml.GetAttrib("ProcessPromptInfo");//diff
	        ProcessPromptInfo=xml.GetAttrib("ProcessIOClientPromtInfo");
	    }
          xml.OutOfElem();
	}
	return import_xmlobj(xml);
    }
    virtual void   copy_to(CPolicy *pDest) 
    {
        if(pDest->get_type() != RUN_INFOMATION) 
        {
            return;
        }
        CPolicyRunInforamtion *pCtrl = (CPolicyRunInforamtion *)pDest;
        pCtrl->CPUPercent=CPUPercent;
        pCtrl->CPUTemperature=CPUTemperature;
        pCtrl->CPUKeepTime=CPUKeepTime;
        pCtrl->CPUTempKeepTime=CPUTempKeepTime;
        pCtrl->CPUUpInfo=CPUUpInfo;
        pCtrl->CPUPrompt=CPUPrompt;
        pCtrl->CPUPromptInfo=CPUPromptInfo;
        pCtrl->MEMPercent=MEMPercent;
        pCtrl->MEMKeepTime=MEMKeepTime;
        pCtrl->MEMUpInfo=MEMUpInfo;
        pCtrl->MEMPrompt=MEMPrompt;
        pCtrl->MEMPromptInfo=MEMPromptInfo;
        pCtrl->DiskTemperature=DiskTemperature;
        pCtrl->DiskTemperatureKeepTime=DiskTemperatureKeepTime;
        pCtrl->MinSystemDiskSpace=MinSystemDiskSpace;
        pCtrl->CheckOtherDisk=CheckOtherDisk; 
        pCtrl->DISKUpInfo=DISKUpInfo;
        pCtrl->DISKPrompt=DISKPrompt; 
        pCtrl->DISKPromptInfo=DISKPromptInfo;
        pCtrl->IOOutSpeed=IOOutSpeed;
        pCtrl->IOOutSpeedKeepTime=IOOutSpeedKeepTime;
        pCtrl->IOInSpeed=IOInSpeed;
        pCtrl->IOInSpeedKeepTime=IOInSpeedKeepTime;
        pCtrl->IOReport=IOReport;
        pCtrl->IOClientPrompt=IOClientPrompt;
        pCtrl->IOClientPromtInfo=IOClientPromtInfo;
        pCtrl->ProcessCPUPercent=ProcessCPUPercent;
        pCtrl->ProcessCPUKeepTime=ProcessCPUKeepTime;
        pCtrl->ProcessMemoryPercent=ProcessMemoryPercent;
        pCtrl->ProcessMemoryKeepTime=ProcessMemoryKeepTime;
        pCtrl->ProcessPrompt=ProcessPrompt;//diff
        pCtrl->ProcessInfo=ProcessInfo;//diff
        pCtrl->ProcessPromptInfo=ProcessPromptInfo;//diff
        CPolicy::copy_to(pDest);
	}
public:
    std::string CPUPercent;
    std::string CPUTemperature;
    std::string CPUKeepTime;
    std::string CPUTempKeepTime;
    std::string CPUUpInfo;
    std::string CPUPrompt;
    std::string CPUPromptInfo;
    std::string MEMPercent; 
    std::string MEMKeepTime;
    std::string MEMUpInfo;
    std::string MEMPrompt;
    std::string MEMPromptInfo;
    std::string DiskTemperature;
    std::string DiskTemperatureKeepTime;
    std::string MinSystemDiskSpace;
    std::string CheckOtherDisk;
    std::string DISKUpInfo;
    std::string DISKPrompt;
    std::string DISKPromptInfo;
    std::string IOOutSpeed;
    std::string IOOutSpeedKeepTime;
    std::string IOInSpeed;
    std::string IOInSpeedKeepTime;
    std::string IOReport;
    std::string IOClientPrompt;
    std::string IOClientPromtInfo;
    std::string ProcessCPUPercent;
    std::string ProcessCPUKeepTime;
    std::string ProcessMemoryPercent;
    std::string ProcessMemoryKeepTime;
    std::string ProcessPrompt;//ProcessIOReport
    std::string ProcessInfo;//ProcessIOClientPrompt
    std::string ProcessPromptInfo;//ProcessIOClientPromtInfo
};

#endif

