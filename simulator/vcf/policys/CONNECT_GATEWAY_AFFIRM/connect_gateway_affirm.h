#ifndef POLICYCONNECTGATEWAYAFFIRM_H_
#define POLICYCONNECTGATEWAYAFFIRM_H_
#include "../policysExport.h"

extern bool connect_gateway_affirm_init();
extern bool connect_gateway_affirm_worker(CPolicy *pPolicy, void *pParam);
extern void connect_gateway_affirm_uninit();

class CConnectGatewayAffirm : public CPolicy
{
public:
    CConnectGatewayAffirm()
    {
        enPolicytype type = CONNECT_GATEWAY_AFFIRM;
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
                IntervalTime=xml.GetAttrib("IntervalTime");
                GatewayIP=xml.GetAttrib("GatewayIP");
                IdentifyMode=xml.GetAttrib("IdentifyMode");
                UseDefaultUserLogin=xml.GetAttrib("UseDefaultUserLogin");
                DefaultUser1Name=xml.GetAttrib("DefaultUser1Name");
                DefaultUser1Pass=xml.GetAttrib("DefaultUser1Pass");
                ShowTrayIcon=xml.GetAttrib("ShowTrayIcon");
            }
            xml.OutOfElem();
        }
        return import_xmlobj(xml);
    }
    virtual void   copy_to(CPolicy *pDest) 
    {
        if(pDest->get_type() != CONNECT_GATEWAY_AFFIRM) 
        {
            return;
        }
        CConnectGatewayAffirm *pCtrl = (CConnectGatewayAffirm *)pDest;
        pCtrl->IntervalTime=IntervalTime;
        pCtrl->GatewayIP=GatewayIP;
        pCtrl->IdentifyMode=IdentifyMode;
        pCtrl->UseDefaultUserLogin=UseDefaultUserLogin;
        pCtrl->DefaultUser1Name=DefaultUser1Name;
        pCtrl->DefaultUser1Pass=DefaultUser1Pass;
        pCtrl->ShowTrayIcon=ShowTrayIcon;
        CPolicy::copy_to(pDest);
	}
public:
    std::string IntervalTime;
    std::string GatewayIP;
    std::string IdentifyMode;
    std::string UseDefaultUserLogin;
    std::string DefaultUser1Name;
    std::string DefaultUser1Pass;
    std::string ShowTrayIcon;
};

#endif