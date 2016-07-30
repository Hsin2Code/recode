#ifndef _MdyCfgFile_H
#define _MdyCfgFile_H

#include <vector>
#include <map>
#include <algorithm>
#include <string>
#include <fstream>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <sys/stat.h>
#define MAX_DUR 5*60
#define MAX_FILEPATH    255
#define DefaltValue ""
using namespace std;

typedef map<string, string, less<string> > strMap_ifcfg;
typedef strMap_ifcfg::iterator strMap_ifcfgIt;


struct IfconfigAnalyze
{
    strMap_ifcfg *pMap;
    IfconfigAnalyze(strMap_ifcfg & strMap_ifcfg):pMap(&strMap_ifcfg) {};
    //卸懈写懈()
    void operator()(const string &sIni)
    {

        size_t first = 0;
        size_t last = 0;
        if((first = sIni.find('=')) == string::npos)
        {
            return ;
        }


        string strtmp1 = sIni.substr(0, first);
        string strtmp2 = sIni.substr(first + 1, string::npos);
        first= strtmp1.find_first_not_of(" \t");
        last = strtmp1.find_last_not_of(" \t");

        if(first == string::npos || last == string::npos)
        {
            return ;
        }

        string strkey = strtmp1.substr(first, last - first + 1);
        first = strtmp2.find_first_not_of(" \t");

        if(((last = strtmp2.find("\t#", first)) != string::npos) ||
                ((last = strtmp2.find(" #", first)) != string::npos) ||
                ((last = strtmp2.find("\t;",first)) != string::npos) ||
                ((last = strtmp2.find(" ;", first)) != string::npos) ||
                ((last = strtmp2.find("\t//", first)) != string::npos)||
                ((last = strtmp2.find(" //",  first)) != string::npos))
        {
            strtmp2 = strtmp2.substr(0, last - first);
        }

        last = strtmp2.find_last_not_of(" \t");

        if(first == string::npos || last == string::npos)
        {
            return ;
        }

        string value = strtmp2.substr(first, last - first + 1);

        string mapkey = strkey;
        (*pMap)[mapkey] = value;
    }
};

class IfconfigFile
{
public:
    IfconfigFile(const char* pIniFile)  //pIniFile:file name
    {
        memset(szIniFile, 0, MAX_FILEPATH);
        int iLen = (strlen(pIniFile) > MAX_FILEPATH)? MAX_FILEPATH: strlen(pIniFile);
        memcpy(szIniFile, pIniFile, iLen);
        OpenIni(szIniFile);
    };

    ~IfconfigFile()
    {
    };

    void Update()
    {
        WriteIni(szIniFile);
    }

    char* ReadString(const char* pKey)
    {
        strMap_ifcfgIt it = iniMap.find(pKey);
        if(it == iniMap.end())
        {
            return (char *)DefaltValue;
        }
        char *retstr = (char *)it->second.c_str();
        return retstr;
    };
    void WriteString(const char* pKey, const char* pValue)
    {


        strMap_ifcfgIt it = iniMap.find(pKey);
        if(it != iniMap.end())
        {
            it->second = pValue;
            return ;
        }

        iniMap[pKey] = pValue;
    };

    void AddKVPair(const char *key, const char *value) {
        iniMap[key] = value;
    };

private:

    char szIniFile[MAX_FILEPATH];
    strMap_ifcfg iniMap;

    bool OpenIni(const char* pIniFile) //pIniFile:file name
    {
        ifstream fin(pIniFile);
        if(!fin.is_open())
        {
            return false;
        }

        vector<string> strVect;

        string strLine;
        while(!fin.eof())
        {
            getline(fin, strLine, '\n');
            const char *p = strLine.c_str();
            char first_char = *p;        //get first char,injudge it is a note or not
            if('#' != first_char)
            {
                strVect.push_back(strLine);
            }

        }
        fin.close();

        if(strVect.empty())
        {
            return false;
        }

        for_each(strVect.begin(), strVect.end(), IfconfigAnalyze(iniMap));

        return !iniMap.empty();
    }

    bool WriteIni(const char* pIniFile)
    {
        if (iniMap.empty())
        {
            return false;
        }

        ofstream clear;
        clear.open(pIniFile, std::ofstream::out|std::ofstream::trunc);
        clear.close();

        ofstream fout(pIniFile);
        if (!fout.is_open())
        {
            return false;
        }

        strMap_ifcfgIt it;
        string sSessSave = "", sSess, sKey, strSect;
        size_t uPos = 0;
        for (it = iniMap.begin(); it != iniMap.end(); ++it)
        {
            strSect = it->first;
            sKey = strSect.substr(uPos , strlen(strSect.c_str()));
            fout << sKey << "=" << it->second << "" << endl;
        }

        fout.close();

        return true;
    }
};

/**********************************************************
Describe:opreat file
Creater:yxl
Date:2012.12.29
**********************************************************/
class Files
{
public:
	bool Is_Prepared(const string &path)
    {
        struct stat st;
        stat(path.c_str(), &st);
        return time(0)-st.st_ctime >= MAX_DUR;
    }
    bool Is_Folder(const string &path)
    {
        struct stat st;
        int ret = stat(path.c_str(), &st);
        return ret>=0 && S_ISDIR(st.st_mode);
    }
    bool Is_Files(const string &path)
    {
        struct stat st;
        int ret = stat(path.c_str(), &st);
        return ret>=0 && S_ISREG(st.st_mode);
    }
    vector<string> Get_Folders(const string &path)
    {
        vector<string> folders;
        struct dirent* ent = NULL;
        DIR* pDir;
        pDir = opendir(path.c_str());
        while(NULL != (ent = readdir(pDir)))
        {
            string fullpath = path + "/" + ent->d_name;

            if(Is_Folder(fullpath))
            {
                if(strcmp(ent->d_name, ".")!=0 && strcmp(ent->d_name, "..")!=0)
                {
                    folders.push_back(ent->d_name);
                }
            }
        }

        closedir(pDir);
        return folders;
    }

    vector<string> Get_Files(const string &path,const string &postfix="")
    {
        vector<string> files;
        struct dirent* ent = NULL;
        DIR* pDir;
        pDir = opendir(path.c_str());
        while(NULL != (ent = readdir(pDir)))
        {
            string fullpath = path + "/" + ent->d_name;

            if(Is_Files(fullpath))
            {
                if(postfix == "" || strstr(ent->d_name, postfix.c_str())!=NULL)
                {
                    files.push_back(ent->d_name);
                }
            }
        }
        closedir(pDir);
        return files;
    }

};
#endif
