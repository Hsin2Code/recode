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

///硬件资产类型
typedef enum {
	asset_hd , ///硬盘
	asset_cd , ///光驱
	asset_cpu, ///处理器
	asset_mbd, ///主板
	asset_mem, ///内存
	asset_vc , ///显卡
	asset_kb,  ///键盘
	asset_svctl , ///声音，视频和游戏控制器
	asset_mouse, ///鼠标和其他指针设备
	asset_nic,  ///网卡
	asset_fd,   ///软盘驱动器
	asset_slot,  ///系统插槽
	asset_usb, ///USB接口类型
	asset_nic_speed, ///网卡速率
	asset_mem_used , ///内存使用情况
	asset_hd_used,   ///硬盘使用情况
	asset_count,
} en_assetType;

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
