/**
 * CDeviceinfoHelper.h
 *
 *  Created on: 2015-1-28
 *      Author: sharp
 *
 *  硬件信息获取类
 */

#ifndef CDEVICEINFOHELPER_H_
#define CDEVICEINFOHELPER_H_
#include <map>
#include <string>

typedef std::map<int , std::string>  CDeviceInfoMap ;

class CDeviceinfoHelper {
public:
	CDeviceinfoHelper();
	virtual ~CDeviceinfoHelper();

public:
	///初始化
	bool    init();
	///对比缓存和最新的信息
	void    check(CDeviceInfoMap & oldmap,
			CDeviceInfoMap & addmap ,
			CDeviceInfoMap & delmap ,
			CDeviceInfoMap & modifymap) ;
	///获取前缀字符串
	std::string    &    getfront() {
		return  m_strFront  ;
	}

	CDeviceInfoMap &    getMap() {
		return  m_devmap  ;
	}
private:
	bool    getfrot();
	std::string & getAssetVal(int type);
private:
	CDeviceInfoMap  m_devmap ;
	std::string     m_strFront ;
};

#endif /* CDEVICEINFOHELPER_H_ */
