#include "file_checksum_edit.h"
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <fcntl.h>
#include <sstream>
#include <algorithm>
#include <unistd.h>
#include "../../vrvprotocol/VRVProtocol.hxx"
#include "../../vrvprotocol/VRVProtocolEx.hxx"
#include "../../common/Commonfunc.h"
#include "../../common/MdyCfgFile.h"
#include "../../common/TIniFile.h"
#include "../../vrcport_tool.h"
#include "../../VCFCmdDefine.h"
#include "../../../include/MCInterface.h"
using namespace std;

extern int code_convert(const char *from_charset,const char *to_charset,char *inbuf,int inlen,char *outbuf,int & outlen);

static unsigned int old_crcvalue;
static vector<string> vec_file_path;
static vector<string> vec_report_path;
static vector<string> vec_report_path_del;
static map<string,string> map_record_ckm;
static map<string,string> map_report_info;	
static vector<IllegalRecord> vec_record;
static vector<string> vec_path;
static set<string> set_file_for_new;
static set<string> set_change_dir;
static CFileChecksumEdit* g_pFileChecksumEdit = NULL;

static vector<string> vec_path_extend;
static vector<string> vec_file_path_extend;
#define CHK_SUM_FILE_PATH_EXTEND "/var/log/file_chk_sum_extend.txt"
#define MONITOR_FILES_LIMITATION 25
 
void collect_all_path_and_files(string files_path)
{
    Files file;
    vector<string> vec_tmp_file;
    vector<string> vec_tmp_dir;

    if(vec_file_path_extend.size() >= MONITOR_FILES_LIMITATION)
    {
	  return;
    }
    else
    {
    }
    if(file.Is_Files(files_path))
    {
        cout<<"files_path: "<<files_path<<"is a file."<<endl;
        return;
    }
    if(file.Is_Folder(files_path))
    {
        if('/' != files_path[files_path.length() - 1])
        {
            files_path += "/";
        }
        vector<string>::iterator res_path = find(vec_path_extend.begin(),vec_path_extend.end(),files_path);
        if(res_path == vec_path_extend.end())
        {
            vector<string> vec_tmp_file2;
            vec_tmp_file2 = file.Get_Files(files_path);
            if(vec_file_path_extend.size() + vec_tmp_file2.size() >= MONITOR_FILES_LIMITATION+5)
            {
	          return;
            }
            else
            {
            }
            vec_path_extend.push_back(files_path);
        }
        else
        {
            return;
        }
        vec_tmp_file = file.Get_Files(files_path);
        for(vector<int>::size_type index1 = 0; index1 < vec_tmp_file.size(); index1++)
        {
            vector<string>::iterator result = find(vec_file_path_extend.begin(), vec_file_path_extend.end(),files_path+vec_tmp_file[index1]);
            if(result == vec_file_path_extend.end())
            {
                vec_file_path_extend.push_back(files_path+vec_tmp_file[index1]);
            }
            else
            {
            }
        }
        if(vec_file_path_extend.size() >= MONITOR_FILES_LIMITATION)
        {
            return;
        }
        else
        {
        }
        vec_tmp_dir = file.Get_Folders(files_path);
        for(vector<int>::size_type index2 = 0; index2< vec_tmp_dir.size(); index2++)
        {
            collect_all_path_and_files(files_path+vec_tmp_dir[index2]);
        }
    }
}

void Write_Chksum_file_extend()
{
    IniFile inifile(CHK_SUM_FILE_PATH_EXTEND);
    string str;

    str = inifile.ReadString("CHKSUM","CRC");
    if("" == str)
    {
        stringstream strcrctmp;
        strcrctmp<<g_pFileChecksumEdit->get_crc();
        inifile.WriteString("CHKSUM","CRC",strcrctmp.str().c_str());
    }
    for(vector<int>::size_type ix = 0; ix < vec_file_path_extend.size(); ix++)
    {
        while(1)
        {
            string::size_type pos(0);
            if((pos = vec_file_path_extend[ix].find("\\")) != string::npos)
            {
                vec_file_path_extend[ix].replace(pos,1,"/");
            }
            else
            {
                break;
            }
        }
        if(-1 != access(vec_file_path_extend[ix].c_str(),F_OK))
        {
            string str_cmd;
            str_cmd = "md5sum " + vec_file_path_extend[ix];
            FILE *fp = popen(str_cmd.c_str() ,"r");
            if(NULL != fp)
            {
                char resault[128] = {0};
                char md5[64] = {0};
                fgets(resault,127,fp);
                sscanf(resault,"%s ",md5);
                string str_md5;
                str_md5.assign(md5);
                inifile.WriteString("CHKSUM", vec_file_path_extend[ix].c_str(), str_md5.c_str());
            }
            pclose(fp);
        }
    }
    inifile.Update();
    ifstream file;
    file.open(CHK_SUM_FILE_PATH_EXTEND);
    file.seekg(0,std::ios::end);
    int length = file.tellg();
    char *buf_in = NULL;
    buf_in = new char[length];
    if(buf_in == NULL)
    {
        return;
    }
    memset(buf_in,0,sizeof(buf_in));
    file.seekg(0,std::ios::beg);
    file.read(buf_in,length);
    string file_content;
    file_content = buf_in;
    delete []buf_in;
    stringstream strStr;
    strStr.str(file_content);
}

void Creat_Chksum_File_Extend()
{
    FILE *fp = NULL;
    creat(CHK_SUM_FILE_PATH_EXTEND,O_RDWR);
    const char *ch_tmp = "[CHKSUM]";
    if(NULL == (fp = fopen(CHK_SUM_FILE_PATH_EXTEND,"w")))
    {
        cout<<"CHK_SUM_FILE_PATH open fail!!"<<endl;
    }
    fputs(ch_tmp,fp);
    fclose(fp);
}

vector<string> split_new_filechecksum(const string& src, string delimit, string null_subst)
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

void dialog_edp_filechecksum(string content)
{
    char buffer[512] = "";

    tag_GuiTips *pTips = (tag_GuiTips *)buffer ;
    pTips->sign = en_TipsGUI_btnOK | en_TipsGUI_timeOut ;
    pTips->defaultret = en_TipsGUI_None;
    sprintf(pTips->szTitle,"%s","提示");
    sprintf(pTips->szTips,"%s",content.c_str());
    pTips->pfunc = NULL;
    pTips->param.timeout = 5000;
    g_GetSendInterface()->sendto_Main(VCF_CMD_GUI_TIPS,buffer,sizeof(tag_GuiTips));
}

void Report_Audit_Info_Filechecksum(string context,string filename)
{
    string SysUserName;
     cout<<"ok shangbao"<<endl;
    //YCommonTool::get_ttyloginUser("tty1", SysUserName);
    get_desk_user(SysUserName);
    if("" == SysUserName)
    {
        SysUserName="root";
    }
    char szTime[21]="";
    YCommonTool::get_local_time(szTime);

    char buffer[2048]={0};
    tag_Policylog *plog = (tag_Policylog *)buffer ;
    plog->type = AGENT_RPTAUDITLOG;
    plog->what = AUDITLOG_REQUEST;
    char *pTmp = plog->log ;
    sprintf(pTmp,"Body0=time=%s<>kind=2401<>policyid=%d<>policyname=%s<>filename=%s<>KeyUserName=%s<>classaction=%d<>riskrank=%d<>context=%s%s%s%s"
    ,szTime
    ,g_pFileChecksumEdit->get_id()
    ,g_pFileChecksumEdit->get_name().c_str()
    ,filename.c_str()
    ,SysUserName.c_str()
    ,Abnormal_Behavior
    ,Event_Error
    ,context.c_str()
    ,STRITEM_TAG_END
    ,"BodyCount=1"
    ,STRITEM_TAG_END);
    cout<<"pTmp: "<<pTmp<<endl;
    report_policy_log(plog);
}

//void Illegal_Deal(string file_path)
void Illegal_Deal()
{
    char outbuffer[129]="";
    string stroutbuffer;
    int  out_len = 129 ;

    switch(atoi(g_pFileChecksumEdit->DealMode.c_str()))
    {
        case 0: ///don't deal
            break;
        case 1: ///dialog
        case 3:
            code_convert("gb2312","utf-8",const_cast<char *>(g_pFileChecksumEdit->PromptInfo.c_str()),g_pFileChecksumEdit->PromptInfo.length(),outbuffer,out_len);
            stroutbuffer = outbuffer;
            //dialog_edp_filechecksum(file_path+stroutbuffer);
            dialog_edp_filechecksum(stroutbuffer);
            break;
        default:
            break;
    }
}

string Get_File_Name(string file_path)
{
	string str1;

	for(string::size_type i = file_path.length(); i > 0; i--)
	{
		if('/' == file_path[i])
		{
			str1.assign(file_path,i+1,file_path.length());
			break;
		}
	}

	return str1;
}

string Get_Dir_Path(string file_path)
{
    string str1;

    for(string::size_type i = file_path.length(); i > 0; i--)
    {
        if('/' == file_path[i])
        {
            str1.assign(file_path,0,i);
            break;
        }
    }

    return str1;
}

string File_Ckm_Check(string filename, string ckm)
{
    map <string,string>::iterator it;

    for(it = map_record_ckm.begin(); it !=map_record_ckm.end(); it++)
    {
        if(ckm == it->second)
        {
            return it->first; //rename
        }
        else
        {
            continue;
        }
    }

    return ""; //delete file
}

void Clear_Illegal_File_Record(string filename)
{
    for(vector<IllegalRecord>::iterator it = vec_record.begin(); it != vec_record.end(); it++)
    {
        if(it->filename == filename)
        {
            vec_record.erase(it);
            break;
        }
    }
}

void Record_Illegal_File_And_Context(string file, string context)
{
    unsigned int index;

    for(index = 0; index < vec_record.size(); index++)
    {
        if(file == vec_record[index].filename && (context == vec_record[index].context))
        {
            return;
        }
        else
        {
            continue;
        }
    }
    IllegalRecord record;
    record.filename = file;
    record.context = context;
    record.report_flag = 0; ///not report
    vec_record.push_back(record);
}

string Calculate_Chksum(string file_path)
{
    string str_cmd;

    str_cmd = "md5sum " + file_path;
    FILE *fp = popen(str_cmd.c_str() ,"r");
    if(NULL != fp)
    {
        char resault[128] = {0};
        char md5[64] = {0};
        fgets(resault,127,fp);
        sscanf(resault,"%s ",md5);
        string str_md5;
        str_md5.assign(md5);
        pclose(fp);
        return str_md5;
    }
    else
    {
        return "";
    }
}

void Get_Filepath_Ckm()
{
    ifstream file;
    file.open(CHK_SUM_FILE_PATH_EXTEND);
    file.seekg(0,std::ios::end);
    int length = file.tellg();
    char *buf_in = NULL;
    buf_in = new char[length];
    if(buf_in == NULL)
    {
        return;
    }
    memset(buf_in,0,sizeof(buf_in));
    file.seekg(0,std::ios::beg);
    file.read(buf_in,length);
    string file_content;
    file_content = buf_in;
    delete []buf_in;
    stringstream strStr;
    strStr.str(file_content);
    string line;

    while(getline(strStr,line))
    {
        line = line.substr(0,line.size());
        if(0 == line.compare(0,8,"[CHKSUM]")||0 == line.compare(0,3,"CRC"))
        {
            continue;
        }
        else if(line.find("/") != string::npos)
        {
            vector<string> vec_tmp = split_new_filechecksum(line, "=", "");
            //cout<<vec_tmp[0]<<"=== "<<vec_tmp[1]<<endl;
            map_record_ckm[vec_tmp[0]] = vec_tmp[1];
            vec_tmp.clear();
        }
    }
}

bool file_checksum_edit_init() 
{
    cout<<"enter file_checksum_edit_init() "<<endl;
    cout<<"leave file_checksum_edit_init() "<<endl;
    return  true ;
}

bool file_checksum_edit_worker(CPolicy * pPolicy, void * pParam) 
{
    cout<<"enter  file_checksum_edit_worker()"<<endl;
    ///获取当前策略类型
    if(pPolicy->get_type() != FILE_CHECKSUM_EDIT) 
    {
        cout<<"type error."<<endl;
        return false ;
    }

    g_pFileChecksumEdit= (CFileChecksumEdit*)pPolicy;
    cout<<"old_crc is: "<<old_crcvalue<<endl;
    cout<<"policy crc is: "<<g_pFileChecksumEdit->get_crc()<<endl;
    if(old_crcvalue != g_pFileChecksumEdit->get_crc())
    {
        cout<<"init all vars..."<<endl;
        vec_file_path.clear();
        vec_report_path.clear();
        vec_report_path_del.clear();
        map_record_ckm.clear();
        map_report_info.clear();	
        vec_record.clear();
        vec_path.clear();
        set_file_for_new.clear();
        set_change_dir.clear();
        vec_path_extend.clear();
        vec_file_path_extend.clear();
        Files file;
        vector<string> vec_tmp;
        string str_tmp("#####");

        cout<<"g_pFileChecksumEdit->FilePatchList: "<<g_pFileChecksumEdit->FilePatchList<<endl;

        if(g_pFileChecksumEdit->FilePatchList == "")
        {
            vec_path.push_back("");
        }
        else
        {
            vec_path= split_new_filechecksum(g_pFileChecksumEdit->FilePatchList,str_tmp,"");
        }

//
        vector<string> vec_path_tranlate;
        vec_path_tranlate.clear();

        char outbuffer[129]="";
        string stroutbuffer;
        int  out_len = 129 ;

        for(vector<int>::size_type tran_it = 0; tran_it < vec_path.size(); tran_it++)
        {
            code_convert("gb2312","utf-8",const_cast<char *>(vec_path[tran_it].c_str()),vec_path[tran_it].length(),outbuffer,out_len);
            stroutbuffer = outbuffer;
            cout<<"stroutbuffer: "<<stroutbuffer<<endl;
            vec_path_tranlate.push_back(stroutbuffer);
        }
        vec_path.clear();
        vec_path = vec_path_tranlate;
//

        for(vector<int>::size_type ix = 0; ix < vec_path.size(); ix++)
        {
            cout<<"vec_path: "<<vec_path[ix]<<endl;//more
            if(vec_path[ix] == "")
            {
                continue;
            }
            int pos=-1;
            if((pos=vec_path[ix].find(":")) == 1)
            {
                vec_path[ix]=vec_path[ix].substr(2,vec_path[ix].length()-1);
            }
            while(1)
            {
                string::size_type pos(0);
                if((pos = vec_path[ix].find("\\")) != string::npos)
                {
                    vec_path[ix].replace(pos,1,"/");
                }
                else
                    break;
            }
            if(0 == access(vec_path[ix].c_str(),F_OK))
            {
                if(file.Is_Folder(vec_path[ix]))
                {
                    collect_all_path_and_files(vec_path[ix]);
                }
            }
            if(!file.Is_Folder(vec_path[ix]))
           {
               size_t last_gap_2=vec_path[ix].find_last_of("/");
               string file_path_2=vec_path[ix].substr(0,last_gap_2+1);
               if(-1 != access(file_path_2.c_str(),F_OK))
               {
                   vector<string>::iterator result = find(vec_file_path_extend.begin(), vec_file_path_extend.end(),vec_path[ix]);
                   if(result == vec_file_path_extend.end())
                   {
                       vec_path_extend.push_back(vec_path[ix]);
                       vec_file_path_extend.push_back(vec_path[ix]);                
                   }
               }
           }
        }

        if(-1 == access(CHK_SUM_FILE_PATH_EXTEND,F_OK))
        {
            Creat_Chksum_File_Extend();
            Write_Chksum_file_extend();
        }
        else
        {
            IniFile inifile(CHK_SUM_FILE_PATH_EXTEND);
            string str_crc = inifile.ReadString("CHKSUM","CRC");
            inifile.Update();
            stringstream strctrtmp;
            strctrtmp<<g_pFileChecksumEdit->get_crc();
            if(strctrtmp.str() != str_crc)
            {
                unlink(CHK_SUM_FILE_PATH_EXTEND);
                Creat_Chksum_File_Extend();
                Write_Chksum_file_extend();
             }
        }
        Get_Filepath_Ckm();

        ///save policy crc
        old_crcvalue = g_pFileChecksumEdit->get_crc();
    }

    Files file;
    vec_path.clear();
    vec_path=vec_path_extend;

    for(vector<int>::size_type ix = 0; ix < vec_path.size(); ix++)
    {
        if(vec_path[ix] == "")
        {
            continue;
        }
        size_t last_gap_4=vec_path[ix].find_last_of("/");
        string file_path_4=vec_path[ix].substr(0,last_gap_4+1);

        if(-1 == access(file_path_4.c_str(),F_OK))
        {
            map <string,string>::iterator it;
            string map_path;
            string context;
            for(it = map_record_ckm.begin(); it !=map_record_ckm.end(); it++)
            {
                size_t last_gap_5 = it->first.find_last_of("/");
                string file_path_5 = it->first.substr(0,last_gap_5+1);
                if(file_path_4 == file_path_5)
                {
                    context = it->first + "删除";
                    cout<<"context: "<<context<<endl;
                    set_change_dir.insert(it->first);
                    Record_Illegal_File_And_Context(it->first,context);
                }
                else
                {
                    continue;
                }
            }
        }
        else
        {
            set<string>::iterator iterx = set_change_dir.begin();
            while(iterx != set_change_dir.end())
            {
                string change_dir = *iterx;
                cout<<"change_dir: "<<change_dir<<endl;
                if(0== access(change_dir.c_str(),F_OK))
                {
                    set_change_dir.erase(change_dir);
                    Clear_Illegal_File_Record(change_dir);
                }
                iterx++;
            }
            if(file.Is_Folder(vec_path[ix].c_str()))
            {
                vector<string> vec_file = file.Get_Files(vec_path[ix]);
                map <string,string>::iterator index;
                set<string> used_only_once;
                used_only_once.clear();
                for(index = map_record_ckm.begin(); index != map_record_ckm.end(); index++)
                {
                    string map_file_full_path = index->first;
                    size_t last_gap=map_file_full_path.find_last_of("/");
                    string map_file_path=map_file_full_path.substr(0,last_gap+1);
                    if(vec_path[ix] != map_file_path)
                    {
                        continue;
                    }
                    int statusflag = 0;
                    if(vec_file.size() == 0)
                    {
                        statusflag=2;
                    }
                    for(vector<int>::size_type index1 = 0; index1 < vec_file.size(); index1++)
                    {
                        string fullpath = vec_path[ix] + vec_file[index1];
                        string str_ckm_tmp = Calculate_Chksum(fullpath);
                        //if(index->first == fullpath || index->second == str_ckm_tmp)//or
                        map<string,string>::iterator exist_iter = map_record_ckm.find(fullpath);
                        if((exist_iter==map_record_ckm.end()) &&  (index->second == str_ckm_tmp) && (-1 == access(index->first.c_str(),F_OK)))
                        {
                            set<string>::iterator iter_for_used = used_only_once.find(fullpath);
                            if(iter_for_used == used_only_once.end())
                            {
                                used_only_once.insert(fullpath);
                                statusflag = 1;///exist
                                break;
                            }
                            else
                            {
                                statusflag=2;
                            }
                        }
                        else if(index->first == fullpath)
                        {
                            statusflag = 1; ///exist
                            break;
                        }
                        else
                        {
                            statusflag = 2; ///delete
                        }
                    }
                    if(2 == statusflag)
                    {
                        cout<<index->first<<" deleted affirmative. "<<endl;
                        string content = index->first + "文件被删除!!";
                        Record_Illegal_File_And_Context(index->first, content);
                    }
                    else
                    {
                        cout<<index->first<<" exist affirmative. "<<endl;
                    }
                }
                set<string> used_only_once_2;
                used_only_once_2.clear();
                for(vector<int>::size_type ix1 = 0; ix1 < vec_file.size(); ix1++) ///change check
                {
                    string context = "";
                    map <string,string>::iterator it;
                    string fullpath_2 = vec_path[ix] + vec_file[ix1];
                    string reportname;
                    for(it = map_record_ckm.begin(); it != map_record_ckm.end(); it++)
                    {
                        string map_file_full_path_2 = it->first;
                        size_t last_gap_2=map_file_full_path_2.find_last_of("/");
                        string map_file_path_2=map_file_full_path_2.substr(0,last_gap_2+1);
                        if(vec_path[ix] != map_file_path_2)
                        {
                             continue;
                        }
                        map<string,string>::iterator exist_iter = map_record_ckm.find(fullpath_2);
                        set<string>::iterator find_used_3 = used_only_once_2.find(it->first);
                        string str_ckm = Calculate_Chksum(fullpath_2);
                        reportname = it->first;
                        if(it->first == fullpath_2)
                        {
                            if(str_ckm != it->second)
                            {
                                context = vec_path[ix] + vec_file[ix1] + "被修改!!"; ///file modified
                                cout<<it->first<<" modified affirmative. "<<endl;
                                break;
                            }
                            else
                            {
                                context = "";
				       cout<<it->first<<" not change affirmative. "<<endl;
                                break;
                            }
                        }
                        else if(it->second == str_ckm && (-1==access(it->first.c_str(),F_OK)) && (exist_iter==map_record_ckm.end()) && (find_used_3 == used_only_once_2.end()))
                        {
                            if(it->first != fullpath_2) ///rename
                            {
                                context = it->first + "重命名" + vec_path[ix] + vec_file[ix1];
                                used_only_once_2.insert(it->first);
                                cout<<it->first<<" rename affirmative. "<<endl;
                                set<string>::iterator iter_rm = set_file_for_new.find(fullpath_2);
                                if(iter_rm != set_file_for_new.end())
                                {
                                    set_file_for_new.erase(iter_rm);
                                    Clear_Illegal_File_Record(fullpath_2);
                                }
                                break;
                            }
                            else
                            {
                                context = "";
                                cout<<"context: "<<context<<endl;
                                break;
                            }
                        }
                        //else if(it->first != fullpath_2&&it->second != str_ckm) ///new
                        else
                        {
                            context = fullpath_2 + "新建!!";
                            reportname = fullpath_2;
                            vector<string>::iterator iter_path = find(vec_file_path_extend.begin(),vec_file_path_extend.end(),fullpath_2);
                            if(iter_path == vec_file_path_extend.end())
                            {
                                set_file_for_new.insert(fullpath_2);
                            }
                        }
                    }
                    if("" != context)
                    {
                        Record_Illegal_File_And_Context(reportname,context);
                    }
                    else
                    {
                        Clear_Illegal_File_Record(reportname);
                    } 	
                }
            }
            else
            {
                string context;

                if(0 == access(vec_path[ix].c_str(),F_OK))
                {
                    string str_ckm = Calculate_Chksum(vec_path[ix]);
                    IniFile ckmfile(CHK_SUM_FILE_PATH_EXTEND);
                    string str_txt_ckm = ckmfile.ReadString("CHKSUM", vec_path[ix].c_str());
                    if(str_ckm != str_txt_ckm)
                    {
                        context = vec_path[ix] + "文件被修改!";///modify
                        cout<<"context: "<<context<<endl;
                        Record_Illegal_File_And_Context(vec_path[ix], context);
			ckmfile.WriteString("CHKSUM", vec_path[ix].c_str(), str_ckm.c_str());
			ckmfile.Update();
                    }
                    else
                    {
                        Clear_Illegal_File_Record(vec_path[ix]);
                        continue;
                    }
                }
                else ///policy set file isn't exist
                {
                    string md5_noexist;
                    for(map <string,string>::iterator itermap = map_record_ckm.begin(); itermap != map_record_ckm.end(); itermap++)
                    {
                        if(itermap->first == vec_path[ix])
                        {
                            md5_noexist = itermap->second;
                            break;
                        }
                    }
                    bool noexistfound = false;
                    string dir_path = Get_Dir_Path(vec_path[ix]);
                    vector<string> vec_file = file.Get_Files(dir_path);
                    for(vector<int>::size_type ix1 = 0; ix1 < vec_file.size(); ix1++)
                    {
                        string file_path = dir_path + "/" + vec_file[ix1];
                        string str_ckm = Calculate_Chksum(file_path);
                        if(md5_noexist == str_ckm)
                        {
                            noexistfound = true;
                            context = vec_path[ix] + "重命名" + vec_file[ix1];
                            cout<<"context: "<<context<<endl;
                            break; 
                        }
                    }
                    if(noexistfound == false)
                    {
                        context = vec_path[ix] + "删除";
                        cout<<"context: "<<context<<endl;		   
                    }
                    Record_Illegal_File_And_Context(vec_path[ix], context);
                }
            }
    	  }
    }
    set<string>::iterator iterxx = set_file_for_new.begin();
    while(iterxx != set_file_for_new.end())
    {
        string path_for_new=*iterxx;
        if(-1== access(path_for_new.c_str(),F_OK))
        {
            set_file_for_new.erase(iterxx++);
            Clear_Illegal_File_Record(path_for_new);
        }
        else
        {
            iterxx++;
        }
    }
    if(vec_record.size() != 0)
    {
        if(("2" == g_pFileChecksumEdit->DealMode||"3" == g_pFileChecksumEdit->DealMode))
        {
            unsigned int index;       
            for(index = 0; index <vec_record.size(); index++)
            {
                if(0 == vec_record[index].report_flag)
                {
                    Report_Audit_Info_Filechecksum(vec_record[index].context, vec_record[index].filename);
                    vec_record[index].report_flag =1;
                }
                //Illegal_Deal(vec_record[index].filename);
            }
	     Illegal_Deal();
        }
    }

    cout<<"leave  file_checkum_edit_worker()"<<endl;

    return true;
}

void file_checksum_edit_uninit() 
{
    cout<<"enter file_checksum_edit_uninit()"<<endl;

    vec_file_path.clear();
    vec_report_path_del.clear();
    vec_report_path.clear();
    map_record_ckm.clear();
    vec_record.clear();
    vec_path_extend.clear();
    vec_file_path_extend.clear();
    set_file_for_new.clear();
    set_change_dir.clear();

    cout<<"leave file_checksum_edit_uninit()"<<endl;
    return;
}

