#ifndef POLICYHEALTHCHECK_H_
#define POLICYHEALTHCHECK_H_
#include "../policysExport.h"

extern bool policy_healthcheck_init();
extern bool policy_healthcheck_worker(CPolicy *pPolicy, void *pParam);
extern void policy_healthcheck_uninit();

class CPolicyHealthcheck : public CPolicy
{
public:
    CPolicyHealthcheck()
    {
        enPolicytype type = POLICY_HEALTHCHECK;
        set_type(type);
    }
    virtual bool import_xml(const char *pxml)
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
                SITStart=xml.GetAttrib("SITStart");
                SITFile=xml.GetAttrib("SITFile");
                SITRDesk=xml.GetAttrib("SITRDesk");
                SITShare=xml.GetAttrib("SITShare");
                SITHidFile=xml.GetAttrib("SITHidFile");
                SITUser=xml.GetAttrib("SITUser");
                SITGpInfo=xml.GetAttrib("SITGpInfo");
                SITURL=xml.GetAttrib("SITURL"); 
                SITHosts=xml.GetAttrib("SITHosts");
                SITVirus=xml.GetAttrib("SITVirus");
                SITProc=xml.GetAttrib("SITProc");
                SITSrv=xml.GetAttrib("SITSrv");
                SITSysFlaw=xml.GetAttrib("SITSysFlaw");
                SITPass=xml.GetAttrib("SITPass");	
                SITIEProx=xml.GetAttrib("SITIEProx");
	      }
            xml.OutOfElem();
        }
        return import_xmlobj(xml);
    }
    virtual void   copy_to(CPolicy *pDest) 
    {
        if(pDest->get_type() != POLICY_HEALTHCHECK) 
        {
            return;
        }
        CPolicyHealthcheck *pCtrl = (CPolicyHealthcheck *)pDest;
        pCtrl->SITStart=SITStart;
        pCtrl->SITFile=SITFile;
        pCtrl->SITRDesk=SITRDesk;
        pCtrl->SITShare=SITShare;
        pCtrl->SITHidFile=SITHidFile;
        pCtrl->SITUser=SITUser;
        pCtrl->SITGpInfo=SITGpInfo;
        pCtrl->SITURL=SITURL;
        pCtrl->SITHosts=SITHosts;
        pCtrl->SITVirus=SITVirus;
        pCtrl->SITProc=SITProc;
        pCtrl->SITSrv=SITSrv;
        pCtrl->SITSysFlaw=SITSysFlaw;
        pCtrl->SITPass=SITPass;
        pCtrl->SITIEProx=SITIEProx;
        CPolicy::copy_to(pDest);
	}
public:
    std::string SITStart;
    std::string SITFile;
    std::string SITRDesk;
    std::string SITShare;
    std::string SITHidFile;
    std::string SITUser;
    std::string SITGpInfo;
    std::string SITURL; 
    std::string SITHosts;
    std::string SITVirus;
    std::string SITProc;
    std::string SITSrv;
    std::string SITSysFlaw;
    std::string SITPass;
    std::string SITIEProx;
};

#endif