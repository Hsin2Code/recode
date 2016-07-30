#ifndef POLICYDEVINSTALLCTRL_H_
#define POLICYDEVINSTALLCTRL_H_
#include "../policysExport.h"

struct usb_dev
{
    std::string major;
    std::string minor;
    std::string dev;
};

typedef struct structForbidden
{
    char srcFileName[256];
    char newFileName[256];
}FORBIDDEN,*PFORBIDDEN;

///硬件资源控制函数定义
extern bool dev_install_ctrl_init();
extern bool dev_install_ctrl_worker(CPolicy* pPolicy, void* pParam);
extern void dev_install_ctrl_uninit();

///硬件资源控制策略
class CDevInstallCtrl : public CPolicy
{
public:
    CDevInstallCtrl()
    {
        enPolicytype type = DEV_INSTALL_CTRL;
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
                //SpecialDeviceGuid=xml.GetAttrib("SpecialDeviceGuid");
                //OtherDeviceExcept=xml.GetAttrib("OtherDeviceExcept");
                //OtherDevice=xml.GetAttrib("OtherDevice");
                OtherUnknownDevice=xml.GetAttrib("OtherUnknownDevice");
                CDROM=xml.GetAttrib("CDROM");
                CDROMExcept=xml.GetAttrib("CDROMExcept");
                FLOPPY=xml.GetAttrib("FLOPPY");
                UDISK=xml.GetAttrib("UDISK");
                //USBSTORAGEExcept=xml.GetAttrib("USBSTORAGEExcept");
                USBINTERFACE=xml.GetAttrib("USBINTERFACE");
                USBMouseKeyboard=xml.GetAttrib("USBMouseKeyboard");
                PRINTER=xml.GetAttrib("PRINTER");
                //PRINTERService=xml.GetAttrib("PRINTERService");	        
                MODEL=xml.GetAttrib("MODEL");
                Dev1394=xml.GetAttrib("Dev1394");
                INFRARED=xml.GetAttrib("INFRARED");	
                BlueTooth=xml.GetAttrib("BlueTooth");
                LPTPORT=xml.GetAttrib("LPTPORT");
                PcmciaCard=xml.GetAttrib("PcmciaCard");
                OtherIDE=xml.GetAttrib("OtherIDE");
                TypeDriver=xml.GetAttrib("TypeDriver");
                SCSI=xml.GetAttrib("SCSI");
                SCSIExcept=xml.GetAttrib("SCSIExcept");
                PORT=xml.GetAttrib("PORT");
                AllNetWork=xml.GetAttrib("AllNetWork");
                NetWorkExcept=xml.GetAttrib("NetWorkExcept");
                //PPPOE=xml.GetAttrib("PPPOE");
                NotNeedHelpControl=xml.GetAttrib("NotNeedHelpControl");
                MutiPolicyMode=xml.GetAttrib("MutiPolicyMode");
                NetWork=xml.GetAttrib("NetWork");
                UpRegionService=xml.GetAttrib("UpRegionService");
                WriteLocalFile=xml.GetAttrib("WriteLocalFile");
                USBINTERFACEExcept=xml.GetAttrib("USBINTERFACEExcept");
            }
            xml.OutOfElem();
        }
        return import_xmlobj(xml);
    }
    virtual void copy_to(CPolicy * pDest) 
    {
        if(pDest->get_type() != DEV_INSTALL_CTRL) 
        {
            return;
        }
        CDevInstallCtrl *pCtrl = (CDevInstallCtrl *)pDest;
        //pCtrl->SpecialDeviceGuid=SpecialDeviceGuid;
        //pCtrl->OtherDeviceExcept=OtherDeviceExcept;
        //pCtrl->OtherDevice=OtherDevice;
        pCtrl->OtherUnknownDevice=OtherUnknownDevice;
        pCtrl->CDROM=CDROM;
        pCtrl->CDROMExcept=CDROMExcept;
        pCtrl->FLOPPY=FLOPPY;
        pCtrl->UDISK=UDISK;
        //pCtrl->USBSTORAGEExcept=USBSTORAGEExcept;
        pCtrl->USBINTERFACE=USBINTERFACE;
        pCtrl->USBMouseKeyboard=USBMouseKeyboard;
        pCtrl->PRINTER=PRINTER;
        //pCtrl->PRINTERService=PRINTERService;
        pCtrl->MODEL=MODEL;
        pCtrl->Dev1394=Dev1394;
        pCtrl->INFRARED=INFRARED;
        pCtrl->BlueTooth=BlueTooth;
        pCtrl->LPTPORT=LPTPORT;
        pCtrl->PcmciaCard=PcmciaCard; 
        pCtrl->OtherIDE=OtherIDE;
        pCtrl->TypeDriver=TypeDriver; 
        pCtrl->SCSI=SCSI;
        pCtrl->SCSIExcept=SCSIExcept;
        pCtrl->PORT=PORT;
        pCtrl->AllNetWork=AllNetWork;
        pCtrl->NetWorkExcept=NetWorkExcept;
        //pCtrl->PPPOE=PPPOE;
        pCtrl->NotNeedHelpControl=NotNeedHelpControl;
        pCtrl->MutiPolicyMode=MutiPolicyMode;
        pCtrl->NetWork=NetWork;
        pCtrl->UpRegionService=UpRegionService;
        pCtrl->WriteLocalFile=WriteLocalFile;
        pCtrl->USBINTERFACEExcept=USBINTERFACEExcept;
        CPolicy::copy_to(pDest);
    }
public:
    //std::string SpecialDeviceGuid;
    //std::string OtherDeviceExcept;
    //std::string OtherDevice;
    std::string OtherUnknownDevice;
    std::string CDROM;
    std::string CDROMExcept;
    std::string FLOPPY;
    std::string UDISK;
    //std::string USBSTORAGEExcept;
    std::string USBINTERFACE; 
    std::string USBMouseKeyboard;
    std::string PRINTER;
    //std::string PRINTERService;
    std::string MODEL;
    std::string Dev1394;
    std::string INFRARED;
    std::string BlueTooth;
    std::string LPTPORT;
    std::string PcmciaCard;
    std::string OtherIDE;
    std::string TypeDriver;
    std::string SCSI;
    std::string SCSIExcept;
    std::string PORT;
    std::string AllNetWork;
    std::string NetWorkExcept;
    //std::string PPPOE;
    std::string NotNeedHelpControl;
    std::string MutiPolicyMode;
    std::string NetWork;
    std::string UpRegionService;
    std::string WriteLocalFile;
    std::string USBINTERFACEExcept;
};

#endif

