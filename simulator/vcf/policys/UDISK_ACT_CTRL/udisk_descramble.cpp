#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h> 
#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <linux/usbdevice_fs.h>
#include "udisk_descramble.h"

#define OFFSET (446)
#define DATA_SIZE (64)
#define UDISK_CMD_LEN (128)

static unsigned char UsbForjiarao[DATA_SIZE] = {
	0x00, 0x04, 0x04, 0x00, 0x08, 0xFE, 0x3F, 0x82, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x02, 0x02, 0x00, 0x08, 0xFE, 0x3F, 0x82, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x03, 0x03, 0x00, 0x08, 0xFE, 0x3F, 0x82, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x01, 0x01, 0x00, 0x04, 0xFE, 0x3F, 0x82, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
};


static int udisk_get_safe1_stat(udisk_stat_info* pudisk_info)
{
	int fd = 0;
	int ret = 0;
	char sector0[DATA_SIZE] = {0};
	char sector2[DATA_SIZE] = {0};
	int sector_size = 0;

	fd = open(pudisk_info->udisk_path, O_RDONLY);
	if (fd == -1) {
		printf("open the udisk error!\n");
		return UD_OPEN_FILE_ERR;
	}   

	ioctl(fd, BLKSSZGET, &sector_size);    
	if (sector_size <= 0) {
		sector_size = 512;
	}   

	lseek(fd, (0*sector_size+OFFSET), SEEK_SET);
	read(fd, sector0, DATA_SIZE);

	lseek(fd, (2*sector_size+OFFSET), SEEK_SET);
	read(fd, sector2, DATA_SIZE);

	ret = memcmp(sector0, sector2, DATA_SIZE);
	if (!ret) {
		pudisk_info->stat = UD_DESCRAMBLE;
	} else {
		pudisk_info->stat = UD_SCRAMBLE;
	}

	close(fd);
	return UD_SUCCESS;
}

int udisk_get_stat(udisk_stat_info* pudisk_info)
{

	int type = pudisk_info->type;
	int ret = UD_SUCCESS;	

	if (!pudisk_info || !pudisk_info->udisk_path || !pudisk_info->udisk_path[0]) {   
		printf("param error!\n");
		return UD_PARAM_ERR;
	}

	switch (type) {
		case SAFE1_USB:
			ret = udisk_get_safe1_stat(pudisk_info);	
			break;
		default:
			printf("unknow udisk type\n");
			pudisk_info->type = INVALID_USB;
			break;
	}

	return ret;
}

int udisk_descramble(udisk_stat_info* pudisk_info, char mnt_mode)
{

	int fd = 0;
	char usbForjierao[DATA_SIZE] = {0};
	char cmd[UDISK_CMD_LEN] = {0}; 
	int sector_size = 0;
	char node_name[PATH_MAX] = "/media/vrvXXXXXX";
	char mode_str[UDISK_CMD_LEN] = "-o rw";
	mode_t mode = S_IRWXU | S_IRWXG | S_IRWXO;

	if (!pudisk_info || !pudisk_info->udisk_path || !pudisk_info->udisk_path[0])
	{
		printf("param error!\n");
		return UD_PARAM_ERR;
	}

	if (mnt_mode == 'R') {
		strcpy(mode_str, "-o ro");
	} else if (mnt_mode == 'W') {
		strcpy(mode_str, "-o rw");
	} else {
		printf("param error\n");
		return UD_PARAM_ERR;
	}

	fd = open(pudisk_info->udisk_path, O_RDWR);
	if (fd == -1) {
		printf("open the udisk error!\n");
		return UD_OPEN_FILE_ERR;
	}

	ioctl(fd, BLKSSZGET, &sector_size);	
	if (sector_size <= 0) {
		sector_size = 512;
	}
	printf("sector size: %d\n", sector_size);

	lseek(fd, (2*sector_size+OFFSET), SEEK_SET);
	read(fd, usbForjierao, DATA_SIZE);

	lseek(fd, (0*sector_size+OFFSET), SEEK_SET);
	write(fd, usbForjierao, DATA_SIZE);
	close(fd);

	if(mkdtemp(node_name) == NULL) {
		return UD_CREATE_DIR_ERR;
	}

	snprintf(cmd, UDISK_CMD_LEN, "partprobe %s; mount %s %s%d %s",  pudisk_info->udisk_path, 
			mode_str, pudisk_info->udisk_path, 1, node_name);
	printf("CMD: %s\n", cmd);
	system(cmd);

	fd = open(pudisk_info->udisk_path, O_RDWR);
	if (fd == -1) {
		printf("open the udisk error!\n");
		return -1;
	}

	lseek(fd, (0*sector_size+OFFSET), SEEK_SET);
	write(fd, UsbForjiarao, DATA_SIZE);

	sync();
	close(fd);	
	strncpy(pudisk_info->node_path, node_name, strlen(node_name));
	return UD_SUCCESS;
}
