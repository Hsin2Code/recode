#ifndef POLICYFILECHECKSUMEDIT_H_
#define POLICYFILECHECKSUMEDIT_H_
#include "../policysExport.h"

///文件校验策略函数定义
extern bool file_checksum_edit_init();
extern bool file_checksum_edit_worker(CPolicy* pPolicy, void* pParam);
extern void file_checksum_edit_uninit();

class IllegalRecord
{
public:
	std::string filename;
	std::string context;
	int report_flag;
};

///文件校验策略
class CFileChecksumEdit : public CPolicy
{
public:
    CFileChecksumEdit()
    {
        enPolicytype type = FILE_CHECKSUM_EDIT;
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
                FilePatchList=xml.GetAttrib("FilePatchList");
                PromptInfo=xml.GetAttrib("PromptInfo");
                DealMode=xml.GetAttrib("DealMode");
                CheckCrcByServer=xml.GetAttrib("CheckCrcByServer");    
             }
             xml.OutOfElem();
        }
        return import_xmlobj(xml);
    }
    virtual void   copy_to(CPolicy * pDest) 
    {
        if(pDest->get_type() != FILE_CHECKSUM_EDIT) 
        {
            return;
        }
        CFileChecksumEdit* pCtrl = (CFileChecksumEdit*)pDest;

        pCtrl->FilePatchList=FilePatchList;
        pCtrl->PromptInfo=PromptInfo;
        pCtrl->DealMode=DealMode;
        pCtrl->CheckCrcByServer=CheckCrcByServer;
        CPolicy::copy_to(pDest);
	}
public:
    std::string FilePatchList;
    std::string PromptInfo;
    std::string DealMode;
    std::string CheckCrcByServer;
};

#endif

