#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "protocol.h"
#include "encrypt.h"
#include "journal.h"
/* 发送数据包 扩展 */
uint32_t
send_pkt_ex(int sock, struct pkt_head_t * head, WORD head_len,
            BYTE *data, WORD data_len, WORD encrypt)
{
    ULONG crc = 0;
    /*if(NULL != data)
      {crc = CRC32(crc, data, datalen);}*/
    /*added by yxl 2014.4.2 end*/
    //填充数据
    head->flag = VRV_FLAG;
    head->data_crc = crc;
    head->tag = VRV_TAG;
    head->head_len = PKTHEADEX_SIZE;
    if(data != NULL && data_len>0) {
        head->pkt_len += data_len;
    }

    //发送包头
    ssize_t nbytes;
    nbytes = send(sock, head, head_len, MSG_WAITALL);
    if (nbytes != head_len) {
        LOG_ERR("send VRVPacketEx Header failed.\n");
        return FALSE;
    }
    //发送数据
    if(data != NULL && data_len > 0) {
        //加密数据
        if(encrypt && head->key != 0) {
            encrypt_v1(head->key, (LPVOID)data, (LPVOID)data, data_len, 0);
        }
        uint64_t send_len = 0 ;

        while(send_len < data_len) {
            nbytes = send(sock, data + send_len, data_len - send_len, MSG_WAITALL);
            if(nbytes < 0) {
                LOG_ERR("socket send pkt failed !\n" );
                return FALSE;
            }
            send_len += nbytes ;
        }

        if (send_len != data_len) {
            LOG_ERR("socket send pkt obliterated data !\n");
            return FALSE;
        }
    }
    return TRUE;
}
/* 接收数据包 扩展 */
uint32_t
recv_pkt_ex(int sock, DWORD key, struct pkt_head_t *head, BYTE *data)
{

    DWORD head_len = sizeof(struct pkt_head_t);

    LOG_ERR("start recive packet ex\n");
    //接收包头
    ssize_t nbytes;
    nbytes = recv(sock, &head, head_len, MSG_WAITALL);
    if (nbytes != head_len) {
        LOG_ERR("socket recive error !\n");
        return FALSE;
    }
    //计算长度和申请空间
    DWORD data_len = head->pkt_len - head_len;
    LOG_MSG("recive packet data len: %u", data_len);

    if(data_len > 0) {
        data = (BYTE *)malloc(data_len * sizeof(BYTE));

        //接收数据
        nbytes = recv(sock, data, data_len, MSG_WAITALL);
        if(nbytes != data_len) {
            LOG_ERR("socket recive error\n");
            free(data);
        }

        //解密数据
        if(key != 0) {
            decrypt_v1(key,(LPVOID)data, (LPVOID)data, data_len, 0);
        }
#if 0
        ULONG crc = 0;
        crc = CRC32(crc, data, datalen);
        if(crc != head.PktCrc) {
            free(data);
            return 0;
        }
#endif
    }
    LOG_MSG("recive data success\n");
    return TRUE;
}
