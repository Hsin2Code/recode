#ifndef EDP_USB_TAGE_H
#define EDP_USB_TAGE_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _WINNT_
#define MAX_PATH 256
#define DWORD	unsigned long
#define BYTE	unsigned char
#define WORD	unsigned short int
#define LPVOID  BYTE *
#endif

typedef struct EDP_GET_TAGE_PARAM
{
	char		szFileName[MAX_PATH];
	char		szGloableFlag[MAX_PATH];
	char		szUSBUniqueID[MAX_PATH];
	DWORD		dwSectoreSize;
}EDP_TAGE_PARAM;

#define EDP_TAGE_PARAM_LEN sizeof(EDP_TAGE_PARAM)

typedef struct EDP_Tage_Info
{
	char		szTageGlobleFlage[MAX_PATH];
	char		szTageSmallTage[MAX_PATH];
	char		szDepartment[MAX_PATH];
	char		szOfficeName[MAX_PATH];
	char		szUserName[MAX_PATH];
	char		szUSBOrderID[MAX_PATH];
	char		szRemark[MAX_PATH];
	int			iencrypt;
	DWORD		dwUsbOnlyID;
	char		szReserve[MAX_PATH];
	char		szReserve1[MAX_PATH];
	char		szReserve2[MAX_PATH];
}EDP_TAGE_INFO, *PEDP_TAGE_INFO;

#define EDP_TAGE_INFO_LEN sizeof(EDP_TAGE_INFO)

#define MAX_SECTOR_SIZE 0x1000

#define EDP_PARAM_ERROR -1	//参数错误
#define EDP_FILE_DEVICE_OPEN_ERROR -2	//打开文件失败
#define EDP_PARTITION_ERROR -3		//磁盘分区错误

int EDPReadTage(EDP_TAGE_PARAM EdpUsbDisk, PEDP_TAGE_INFO lpTageInfo);
void InitCRC();

#ifdef __cplusplus
} 

#endif


#endif //EDP_USB_TAGE_H
