#ifndef USB_DESCRAMBLE_XXX
#define USB_DESCRAMBLE_XXX

#include <sys/types.h>
#include <sys/stat.h>

enum err_code {
	UD_SUCCESS = 0,
	UD_PARAM_ERR,
	UD_CREATE_DIR_ERR,
	UD_OPEN_FILE_ERR,
};


enum USB_TYPE{
    INVALID_USB,
    NORMAL_USB,
    NORMAL_LABEL_USB,
    SAFE1_USB,
    SAFEX_USB
};

#if 0
enum udisk_type {
	UD_NORMAL = 0,
	UD_SAFE1,
	UD_UNKNOW_TYPE,
};
#endif

enum udisk_status {
	UD_SCRAMBLE = 0,
	UD_DESCRAMBLE,
	UD_UNKNOW_STAT,
};

typedef struct __udisk_stat_info {
	char udisk_path[PATH_MAX];
	char node_path[PATH_MAX];
	int type;
	int stat;
    __udisk_stat_info() {
        memset(udisk_path, 0, sizeof(udisk_path));
        memset(node_path, 0, sizeof(node_path));
        type = INVALID_USB;
        stat = UD_UNKNOW_STAT;
    }
}udisk_stat_info;


//int udisk_get_safe1_stat(udisk_stat_info* pudisk_info);

int udisk_get_stat(udisk_stat_info* pudisk_info);

int udisk_descramble(udisk_stat_info* pudisk_info, char mnt_mode);

#endif
