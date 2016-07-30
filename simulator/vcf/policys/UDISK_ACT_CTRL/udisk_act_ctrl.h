#ifndef POLICYUDISKACTCTRL_H_
#define POLICYUDISKACTCTRL_H_
#include "../policysExport.h"

// usb分区下监控目录
struct wd_element {
    int wd;
    char name[256];
};

// usb设备分区节点
struct wd_name {
    std::vector<wd_element> wdelem;
    std::string inotify_usb_partion;
    std::string mountdir;
};

// 告警存储结构
struct alert_node {
    unsigned int mask;
    int  kind;
    char path_set[1024];
    char monitor_name[1024];
    bool is_dir;
};

typedef struct label_auth_info{
    std::string name;
    std::string right;
} label_auth_info_t;


///移动存储审计函数定义
extern bool udisk_act_ctrl_init();
extern bool udisk_act_ctrl_worker(CPolicy* pPolicy, void* pParam);
extern void udisk_act_ctrl_uninit();

///移动存储审计策略
class CUdiskActCtrl : public CPolicy
{
    public:
        CUdiskActCtrl() {
            enPolicytype type = UDISK_ACT_CTRL;
            set_type(type);
        }
        virtual ~CUdiskActCtrl(){}
        virtual bool import_xml(const char* pxml) {
            if(pxml == NULL) {
                return false ;
            }

#if 1
	    std::string code_convert_content = "";
	    if(g_GetlcfgInterface()->is_WinSrv()) {
		    int dst_buf_len = strlen(pxml) * 2 + 1;
		    int org_buf_len = dst_buf_len;
		    char *dst_buf = (char *)malloc(dst_buf_len);
		    memset(dst_buf, 0, dst_buf_len);
		    /*utf-8 3 byte can encode need more space than gb2312*/
		    extern int code_convert(const char *from_charset, 
				    const char *to_charset,char *inbuf,int inlen,char *outbuf,int & outlen);
		    (void)code_convert("gb2312","utf-8//IGNORE", 
				    (char *)pxml,strlen(pxml),
				    dst_buf, dst_buf_len);
		    if((org_buf_len - dst_buf_len) >= strlen(pxml)) {
			    code_convert_content.append(dst_buf);
		    }
		   if(dst_buf){
			free(dst_buf);
			dst_buf = NULL;
                    }
	    }
#endif
            CMarkup  xml ;
            if(!xml.SetDoc(code_convert_content.empty() ? pxml : code_convert_content.c_str())) {
            //if(!xml.SetDoc(pxml)) {
                return false ;
            }
            if(xml.FindElem("vrvscript")) {
                xml.IntoElem();
                while(xml.FindElem("item")) {
                    /*0 禁止 1 只读 2 读写*/
                    CanUseUSB=xml.GetAttrib("CanUseUSB");
                    //DisableUdiskRunApp=xml.GetAttrib("DisableUdiskRunApp");
                    //MovableHardDisk=xml.GetAttrib("MovableHardDisk");
                    //CanUseSafeUSB=xml.GetAttrib("CanUseSafeUSB");
                    /*标签U盘大标签*/
                    IdentityStringLevel1=xml.GetAttrib("IdentityStringLevel1");
                    /*可以使用标签U盘*/
                    IdentityFlagLevel2=xml.GetAttrib("IdentityFlagLevel2");
                    /*标签U盘小标签*/
                    IdentityStringLevel2=xml.GetAttrib("IdentityStringLevel2");
                    //LockScreenPromtString=xml.GetAttrib("LockScreenPromtString");
                    /*本单位认证失败提示否*/
                    InsideNoWarning=xml.GetAttrib("InsideNoWarning");
                    /*本单位提示信息*/
                    PromptInfo=xml.GetAttrib("PromptInfo");
                    /*本单位认证失败动作*/
                    FailedForReadOnly=xml.GetAttrib("FailedForReadOnly");
                    /*外单位认证失败提示否*/
                    OutSideNoWarning=xml.GetAttrib("OutSideNoWarning");
                    /*外单位认证失败提示信息*/
                    PromptOnOtherDeptmentInfo=xml.GetAttrib("PromptOnOtherDeptmentInfo");
                    /*外单位认证失败动作*/
                    FailedOnOtherDeptmentForReadOnly=xml.GetAttrib("FailedOnOtherDeptmentForReadOnly");
                    //CanUseFloppy=xml.GetAttrib("CanUseFloppy");
                    //CanUseCDROM=xml.GetAttrib("CanUseCDROM");
                    //EnableUSBCdRom=xml.GetAttrib("EnableUSBCdRom");
                    //ExceptionCDList=xml.GetAttrib("ExceptionCDList");
                    //OnUnSafeDiskArrivalLockScreen=xml.GetAttrib("OnUnSafeDiskArrivalLockScreen");
                    //OnLockScreenResetMode=xml.GetAttrib("OnLockScreenResetMode");
                    //VRVSecUSBNoCheck=xml.GetAttrib("VRVSecUSBNoCheck");
                    //UseSerialIdentity=xml.GetAttrib("UseSerialIdentity");
                    //UDiskSerial=xml.GetAttrib("UDiskSerial");
                    //DisableUsbLoss=xml.GetAttrib("DisableUsbLoss");
                    //SecUsbUpdateInfo=xml.GetAttrib("SecUsbUpdateInfo");
                    //ExceptionUDiskList=xml.GetAttrib("ExceptionUDiskList");
                    //UseSafeUDiskSet=xml.GetAttrib("UseSafeUDiskSet");
                    //JiaMiAreaUseMode=xml.GetAttrib("JiaMiAreaUseMode");
                    //PuTongAreaUseMode=xml.GetAttrib("PuTongAreaUseMode");
                    //AuditMode=xml.GetAttrib("AuditMode");
                    //JiaMiAreaFormatMode=xml.GetAttrib("JiaMiAreaFormatMode");
                    //PuTongAreaFormatMode=xml.GetAttrib("PuTongAreaFormatMode");
                    UpRegionService=xml.GetAttrib("UpRegionService");
                    WriteLocalFile=xml.GetAttrib("WriteLocalFile");
                    AuditCopyIn=xml.GetAttrib("AuditCopyIn");
                    InFileExtName=xml.GetAttrib("InFileExtName");
                    AuditCopyOut=xml.GetAttrib("AuditCopyOut");
                    UDiskAction=xml.GetAttrib("UDiskAction");
                    ReportDrawRemoveDisk=xml.GetAttrib("ReportDrawRemoveDisk");
                    OutFileExtName=xml.GetAttrib("OutFileExtName");
                    //IsMiddleComputer=xml.GetAttrib("IsMiddleComputer");
                    //BackupCopyOrCutFileToUDisk=xml.GetAttrib("BackupCopyOrCutFileToUDisk");
                    //KillVirusOnInsertDisk=xml.GetAttrib("KillVirusOnInsertDisk");
                    FilterWarnOnFilesExist=xml.GetAttrib("FilterWarnOnFilesExist");
                    MaxFileNum=xml.GetAttrib("MaxFileNum");
                    //NeiWangDedicated=xml.GetAttrib("NeiWangDedicated");
                    //WayInto=xml.GetAttrib("WayInto");
                    //Exchange=xml.GetAttrib("Exchange");
                    //checkSecUsbUpdate=xml.GetAttrib("checkSecUsbUpdate");	    
                }
                xml.OutOfElem();
            }
            get_label_auth_info();
            return import_xmlobj(xml);
        }
        virtual void   copy_to(CPolicy * pDest) 
        {
            if(pDest->get_type() != UDISK_ACT_CTRL) 
            {
                return;
            }
            CUdiskActCtrl * pCtrl = (CUdiskActCtrl *)pDest;

            pCtrl->CanUseUSB=CanUseUSB;
            //pCtrl->DisableUdiskRunApp=DisableUdiskRunApp;
            //pCtrl->MovableHardDisk=MovableHardDisk;
            //pCtrl->CanUseSafeUSB=CanUseSafeUSB;
            pCtrl->IdentityStringLevel1=IdentityStringLevel1;
            pCtrl->IdentityFlagLevel2=IdentityFlagLevel2;
            pCtrl->IdentityStringLevel2=IdentityStringLevel2;
            //pCtrl->LockScreenPromtString=LockScreenPromtString;
            pCtrl->InsideNoWarning=InsideNoWarning;
            pCtrl->PromptInfo=PromptInfo;
            pCtrl->FailedForReadOnly=FailedForReadOnly;
            pCtrl->OutSideNoWarning=OutSideNoWarning;
            pCtrl->PromptOnOtherDeptmentInfo=PromptOnOtherDeptmentInfo;
            pCtrl->FailedOnOtherDeptmentForReadOnly=FailedOnOtherDeptmentForReadOnly;
            //pCtrl->CanUseFloppy=CanUseFloppy;
            //pCtrl->CanUseCDROM=CanUseCDROM;
            //pCtrl->EnableUSBCdRom=EnableUSBCdRom;
            //pCtrl->ExceptionCDList=ExceptionCDList;
            //pCtrl->OnUnSafeDiskArrivalLockScreen=OnUnSafeDiskArrivalLockScreen;
            //pCtrl->OnLockScreenResetMode=OnLockScreenResetMode;
            //pCtrl->VRVSecUSBNoCheck=VRVSecUSBNoCheck;
            //pCtrl->UseSerialIdentity=UseSerialIdentity;
            //pCtrl->UDiskSerial=UDiskSerial;
            //pCtrl->DisableUsbLoss=DisableUsbLoss;
            //pCtrl->SecUsbUpdateInfo=SecUsbUpdateInfo;
            //pCtrl->ExceptionUDiskList=ExceptionUDiskList;
            //pCtrl->UseSafeUDiskSet=UseSafeUDiskSet;
            //pCtrl->JiaMiAreaUseMode=JiaMiAreaUseMode;
            //pCtrl->PuTongAreaUseMode=PuTongAreaUseMode;
            //pCtrl->AuditMode=AuditMode;
            //pCtrl->JiaMiAreaFormatMode=JiaMiAreaFormatMode;
            //pCtrl->PuTongAreaFormatMode=PuTongAreaFormatMode;
            pCtrl->UpRegionService=UpRegionService;
            pCtrl->WriteLocalFile=WriteLocalFile;
            pCtrl->AuditCopyIn=AuditCopyIn;
            pCtrl->InFileExtName=InFileExtName;
            pCtrl->AuditCopyOut=AuditCopyOut;
            pCtrl->UDiskAction=UDiskAction;
            pCtrl->ReportDrawRemoveDisk=ReportDrawRemoveDisk;
            pCtrl->OutFileExtName=OutFileExtName;
            //pCtrl->IsMiddleComputer=IsMiddleComputer;
            //pCtrl->BackupCopyOrCutFileToUDisk=BackupCopyOrCutFileToUDisk;
            //pCtrl->KillVirusOnInsertDisk=KillVirusOnInsertDisk;
            pCtrl->FilterWarnOnFilesExist=FilterWarnOnFilesExist;
            pCtrl->MaxFileNum=MaxFileNum;
            //pCtrl->NeiWangDedicated=NeiWangDedicated;
            //pCtrl->WayInto=WayInto;
            //pCtrl->Exchange=Exchange;
            //pCtrl->checkSecUsbUpdate=checkSecUsbUpdate;	
            pCtrl->m_label_auth = m_label_auth;
            CPolicy::copy_to(pDest);
        }
    public:
        std::string CanUseUSB;
        //std::string DisableUdiskRunApp;
        //std::string MovableHardDisk;
        //std::string CanUseSafeUSB;
        std::string IdentityStringLevel1;
        std::string IdentityFlagLevel2;
        std::string IdentityStringLevel2;
        //std::string LockScreenPromtString;
        std::string InsideNoWarning;
        std::string PromptInfo;
        std::string FailedForReadOnly;
        std::string OutSideNoWarning;
        std::string PromptOnOtherDeptmentInfo;
        std::string FailedOnOtherDeptmentForReadOnly;
        //std::string CanUseFloppy;
        //std::string CanUseCDROM;
        //std::string EnableUSBCdRom;
        //std::string ExceptionCDList;
        //std::string OnUnSafeDiskArrivalLockScreen;
        //std::string OnLockScreenResetMode;
        //std::string VRVSecUSBNoCheck;
        //std::string UseSerialIdentity;
        //std::string UDiskSerial;
        //std::string DisableUsbLoss;
        //std::string SecUsbUpdateInfo;
        //std::string ExceptionUDiskList;
        //std::string UseSafeUDiskSet;
        //std::string JiaMiAreaUseMode;
        //std::string PuTongAreaUseMode;
        //std::string AuditMode;
        //std::string JiaMiAreaFormatMode;
        //std::string PuTongAreaFormatMode;
        std::string UpRegionService;
        std::string WriteLocalFile;
        std::string AuditCopyIn;
        std::string InFileExtName;
        std::string AuditCopyOut;
        std::string UDiskAction;
        std::string ReportDrawRemoveDisk;
        std::string OutFileExtName;
        //std::string IsMiddleComputer;
        //std::string BackupCopyOrCutFileToUDisk;
        //std::string KillVirusOnInsertDisk;
        std::string FilterWarnOnFilesExist;
        std::string MaxFileNum;
        //std::string NeiWangDedicated;
        //std::string WayInto;
        //std::string Exchange;
        //std::string checkSecUsbUpdate;
        //error_test???
    private:
        void get_label_auth_info() {
            /*clear status*/
            m_label_auth.clear();
            if(IdentityStringLevel2.empty()) {
                return;
            }
            std::vector<std::string> label_auth_v;
            YCommonTool::split_new(IdentityStringLevel2, label_auth_v, ";");
            for(size_t i = 0; i < label_auth_v.size(); i++) {
                std::vector<std::string> extract_auth_v; 
                YCommonTool::split_new(label_auth_v.at(i), extract_auth_v, "|");
                /*fix to 2 name | right*/
                if(extract_auth_v.size() != 2) {
                    continue;
                }
                label_auth_info_t auth_info;
                auth_info.name = extract_auth_v.at(0);
                auth_info.right = extract_auth_v.at(1);
                m_label_auth.push_back(auth_info);
            }
        }
    private:
        property_def(label_auth, std::vector<label_auth_info_t>);
};

#endif
