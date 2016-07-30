//---------------------------------------------------------------------------
#ifndef _TIniFile_H
#define _TIniFile_H

#include <vector>
#include <map>
#include <algorithm>
#include <string>
#include <fstream>

#include <string.h>

#define MAX_FILEPATH    255

using namespace std;

typedef map<string, string, less<string> > strMap;  //map ��������
typedef strMap::iterator strMapIt; //iterator

const char* const MIDDLESTRING = "____****____";  
//const char* DefaultValue1 = "";

struct IniAnalyze
{
    string strSect;
    strMap *pMap;
    IniAnalyze(strMap & strMap):pMap(&strMap){};

    //����()
    void operator()(const string &sIni)
    {
        string::size_type first = sIni.find('[');
        string::size_type last = sIni.rfind(']');
        if (first != string::npos && last != string::npos && first != last + 1)
        {
            strSect = sIni.substr(first + 1, last - first - 1);
            return ;
        }

        if(strSect.empty())
        {
            return ;
        }

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
        string mapkey = strSect + MIDDLESTRING + strkey;
        (*pMap)[mapkey] = value;
    }
};

class IniFile
{
public:
    IniFile(const char* pIniFile)  //pIniFile:file name
    {
        memset(szIniFile, 0, MAX_FILEPATH);
        int iLen = (strlen(pIniFile) > MAX_FILEPATH)? MAX_FILEPATH: strlen(pIniFile);
        memcpy(szIniFile, pIniFile, iLen);
        OpenIni(szIniFile);
    };

    ~IniFile()
    {
    };

    void Update()
    {
        WriteIni(szIniFile);
    }

    char* ReadString(const char* pSect, const char* pKey)
    {
        string mapkey = pSect;
        mapkey += MIDDLESTRING;
        mapkey += pKey;
        const char* DefaultValue = "";
        strMapIt it = iniMap.find(mapkey);
        if(it == iniMap.end())
        {
            return (char *)DefaultValue;
        }
        string briage;
        briage = it->second;

        string::size_type iIndex = briage.find('\r');

        if (iIndex != string::npos)
        {
            briage[iIndex] = '\0';
            WriteString(pSect, pKey, briage.c_str());
            it = iniMap.find(mapkey);
        }

	char *retstr= (char *)it->second.c_str();

		return retstr;
    };

    void WriteString(const char* pSect, const char* pKey, const char* pValue)
    {
        string mapkey = pSect;
        mapkey += MIDDLESTRING;
        mapkey += pKey;

        strMapIt it = iniMap.find(mapkey);
        if(it != iniMap.end())
        {
            it->second = pValue;
            return ;
        }

        iniMap[mapkey] = pValue;
    };

    int ReadInteger(const char* pSect, const char* pKey, int iValue = 0)
    {
        char *pValue = ReadString(pSect, pKey);
        if (NULL == pValue)
        {
            return iValue;
        }
        return atoi(pValue);
    }

    void WriteInteger(const char* pSect, const char* pKey, int iValue)
    {
        char szValue[25] = {0};
		sprintf(szValue, "%d", iValue);
        WriteString(pSect, pKey, szValue);
    }

    double ReadDouble(const char* pSect, const char* pKey, double dValue = 0)
    {
        char *pValue = ReadString(pSect, pKey);
        if (NULL == pValue)
        {
            return dValue;
        }
        return atof(pValue);
    }

    void WriteDouble(const char* pSect, const char* pKey, double dValue)
    {
        char szValue[25] = {0};
        sprintf(szValue, "%f", dValue);
        WriteString(pSect, pKey, szValue);
    }

    bool ReadBool(const char* pSect, const char* pKey, bool bValue = false)
    {
        char *pValue = ReadString(pSect, pKey);
        if (NULL == pValue)
        {
            return bValue;
        }
        return strcmp(pValue, "1") == 0? true : false;
    }

    void WriteBool(const char* pSect, const char* pKey, bool bValue)
    {
        char szValue[2] = {0};
        szValue[0] = '0';
        if (bValue) szValue[0] = '1';
        WriteString(pSect, pKey, szValue);
    }

    void DeleteKey(const char* pSect, const char* pKey)
    {
        string mapkey = pSect;
        mapkey += MIDDLESTRING;
        mapkey += pKey;

        strMapIt it = iniMap.find(mapkey);
        if(it != iniMap.end())
        {
            iniMap.erase(it);
        }
    }

    void DeleteSession(const char* pSect)
    {
        strMapIt it;
        string sSess, strSect;
        string::size_type uPos = 0;
        for (it = iniMap.begin(); it != iniMap.end(); ++it)
        {
            strSect = it->first;
            uPos = strSect.find(MIDDLESTRING);
            sSess = strSect.substr(0, uPos);
            if (sSess == pSect)
            {
                iniMap.erase(it);
            }
        }
    }

private:
	
    char szIniFile[MAX_FILEPATH];
    bool bChanged;
    strMap iniMap;

    bool OpenIni(const char* pIniFile)
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
            strVect.push_back(strLine);
        }
        fin.close();

        if(strVect.empty())
        {
            return false;
        }

        for_each(strVect.begin(), strVect.end(), IniAnalyze(iniMap));

        return !iniMap.empty();
    }

    bool WriteIni(const char* pIniFile)
    {
        if (iniMap.empty())
        {
            return false;
        }

        ofstream fout(pIniFile);
        if (!fout.is_open())
        {
            return false;
        }

        strMapIt it;
        int iMID_LEN = strlen(MIDDLESTRING);
        string sSessSave = "", sSess, sKey, strSect;
        string::size_type uPos = 0;
        for (it = iniMap.begin(); it != iniMap.end(); ++it)
        {
            strSect = it->first;
            uPos = strSect.find(MIDDLESTRING);
            sSess = strSect.substr(0, uPos);
            if (sSessSave != sSess)
            {
                sSessSave = sSess;
                fout << "[" << sSess << "]" << endl;
            }

            sKey = strSect.substr(uPos + iMID_LEN, strlen(strSect.c_str()) - uPos - iMID_LEN);
            fout << sKey << "=" << it->second << "" << endl;
        }

        fout.close();

        return true;
    }
};
//---------------------------------------------------------------------------

#endif
