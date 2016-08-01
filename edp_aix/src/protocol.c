#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "protocol.h"
#include "encrypt.h"
#include "journal.h"
#include "type.h"
/* 发送数据包 基准 */
uint32_t
send_pkt(const int sock, struct packet_t *pkt)
{
    ULONG crc = 0;
    /*if(NULL != data)
      {crc = CRC32(crc, data, datalen);}*/
    pkt->head.flag = ENDIANL(VRV_FLAG);
    pkt->head.data_crc = ENDIANL(crc);
    WORD head_len = sizeof(struct head_t);
    DWORD data_len = ENDIANL(pkt->head.pkt_len) - head_len;
    //发送包头
    ssize_t nbytes;
    LOG_MSG("Send packet head len %u \n", head_len);
    nbytes = send(sock, &(pkt->head), head_len, MSG_WAITALL);
    if (nbytes != head_len) {
        LOG_ERR("send VRVPacket Header failed.\n");
        return FAIL;
    }
    //发送数据
    if(data_len > 0) {
        //加密数据
        if(ENDIANL(pkt->head.key)) {
            LOG_MSG("Send base 加密数据\n");
            encrypt_v1(ENDIANL(pkt->head.key), (LPVOID)pkt->data, (LPVOID)pkt->data, data_len, 0);
        }
        ssize_t send_len = 0 ;
        while(send_len < data_len) {
            nbytes = send(sock, pkt->data + send_len, data_len - send_len, MSG_WAITALL);
            LOG_MSG("发送数据...%zu bytes\n", nbytes);
            if(nbytes < 0) {
                LOG_ERR("socket send pkt failed !\n" );
                return FAIL;
            }
            send_len += nbytes ;
        }

        if(send_len != data_len) {
            LOG_ERR("socket send pkt obliterated data !\n");
            return FAIL;
        }
    }
    LOG_MSG("Send packet data len %u \n", data_len);
    return OK;
}
/* 接收数据包 基准 */
int recv_pkt(const int sock, struct packet_t ** pkt)
{
    struct head_t head;
    DWORD head_len = sizeof(head);
    LOG_MSG("start recive packet.\n");
    //接收包头
    ssize_t nbytes;
    nbytes = recv(sock, &head, head_len, MSG_WAITALL);
    if (nbytes != head_len) {
        LOG_ERR("Recv pkt head failed!\n");
        return FAIL;
    }
    LOG_MSG("Recv pkt head success!\n");
    //计算长度和申请空间
    DWORD pkt_len = ENDIANL(head.pkt_len);
    struct packet_t *p_pkt = (struct packet_t *)malloc(pkt_len);
    if(p_pkt == NULL) {
        LOG_ERR("malloc failed!\n");
        return FAIL;
    }
    memset(p_pkt, 0, pkt_len);
    memcpy(p_pkt, &head, head_len);
    DWORD data_len = pkt_len - head_len;

    LOG_MSG("recive packet data len: %u\n", data_len);
    if(data_len > 0) {
        //接收数据
        nbytes = recv(sock, p_pkt->data, data_len, MSG_WAITALL);
        if(nbytes != data_len) {
            LOG_ERR("socket recive error\n");
        }
        //解密数据
        if(ENDIANL(p_pkt->head.key)) {
            LOG_MSG("Recv base 解密数据\n");
            decrypt_v1(ENDIANL(p_pkt->head.key), (LPVOID)p_pkt->data, (LPVOID)p_pkt->data, data_len, 0);
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
    *pkt = p_pkt;
    LOG_MSG("recive data success\n");
    return OK;
}

/* 发送数据包 扩展 */
uint32_t
send_pkt_ex(int sock, struct packet_ex_t* pkt)
{
    ULONG crc = 0;
    /*if(NULL != data)
      {crc = CRC32(crc, data, datalen);}*/
    /*added by yxl 2014.4.2 end*/
    //填充数据
    pkt->head.flag = ENDIANL(VRV_FLAG);
    pkt->head.data_crc = ENDIANL(crc);
    pkt->head.tag = ENDIANS(VRV_TAG);
    pkt->head.head_len = ENDIANS(PKTHEADEX_SIZE);
    DWORD data_len = ENDIANL(pkt->head.pkt_len) - ENDIANS(pkt->head.head_len);
    //发送包头
    ssize_t nbytes;
    LOG_MSG("send packet head len %u \n", ENDIANS(pkt->head.head_len));
    nbytes = send(sock, &(pkt->head), ENDIANS(pkt->head.head_len), MSG_WAITALL);
    if (nbytes != ENDIANS(pkt->head.head_len)) {
        LOG_ERR("send VRVPacketEx Header failed.\n");
        return FAIL;
    }
    //发送数据
    if(data_len > 0) {
        //加密数据
        if(pkt->head.key) {
            encrypt_v1(pkt->head.key, (LPVOID)pkt->data, (LPVOID)pkt->data, data_len, 0);
        }
        ssize_t send_len = 0 ;

        while(send_len < data_len) {
            nbytes = send(sock, pkt->data + send_len, data_len - send_len, MSG_WAITALL);
            LOG_MSG("发送数据...%zu bytes\n", nbytes);
            if(nbytes < 0) {
                LOG_ERR("socket send pkt failed !\n" );
                return FAIL;
            }
            send_len += nbytes ;
        }

        if (send_len != data_len) {
            LOG_ERR("socket send pkt obliterated data !\n");
            return FAIL;
        }
    }
    LOG_MSG("Send packet data len %u \n", data_len);
    return OK;
}
/* 接收数据包 扩展 */
uint32_t
recv_pkt_ex(int sock, struct packet_ex_t **pkt)
{
    struct head_ex_t head;
    DWORD head_len = sizeof(head);
    LOG_MSG("start recive packet ex\n");
    //接收包头
    ssize_t nbytes;
    nbytes = recv(sock, &head, head_len, MSG_WAITALL);
    if (nbytes != head_len) {
        LOG_ERR("socket recive error !\n");
        return FAIL;
    }
    LOG_MSG("Recv pkt head success!\n");
    //计算长度和申请空间
    DWORD pkt_len = ENDIANL(head.pkt_len);
    struct packet_ex_t *p_pkt = (struct packet_ex_t *)malloc(pkt_len);
    if(p_pkt == NULL) {
        LOG_ERR("malloc failed!\n");
        return FAIL;
    }
    memset(p_pkt, 0, pkt_len);
    memcpy(p_pkt, &head, head_len);
    DWORD data_len = pkt_len - head_len;

    LOG_MSG("recive packet data len: %u\n", data_len);
    if(data_len > 0) {
        //接收数据
        nbytes = recv(sock, p_pkt->data, data_len, MSG_WAITALL);
        if(nbytes != data_len) {
            LOG_ERR("socket recive error\n");
        }
        //解密数据
        if(ENDIANL(p_pkt->head.key)) {
            decrypt_v1(ENDIANL(p_pkt->head.key), (LPVOID)p_pkt->data, (LPVOID)p_pkt->data, data_len, 0);
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
    *pkt = p_pkt;
    LOG_MSG("recive data success\n");
    return OK;
}
/* 获取通讯加密密钥 */
uint32_t
get_encrypt_key(int sock, uint32_t *key)
{
    LOG_MSG("Start getting the Communication key...\n");
    char buf[BUFF_SIZE] = {0};
    sprintf(buf, "%s", "GET_PWD_SEND");
    struct packet_ex_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.head.type = ENDIANS(DETECT_ENCRYPT);
    pkt.head.what = ENDIANS(0);
    pkt.head.key = ENDIANL(0x56000001);
    pkt.head.data_crc = ENDIANL(0);
    pkt.head.address = ENDIANL(0);
    pkt.head.pkt_len = ENDIANL(sizeof(pkt));
    int ret = 0;
    ret = send_pkt_ex(sock, &pkt);
    if(ret) {
        return ret;
    }
    struct packet_ex_t *p_pkt = NULL;
    LOG_MSG("recv pkt\n");
    ret = recv_pkt_ex(sock, &p_pkt);
    if(ret) {
        return ret;
    }
    if(ENDIANL(p_pkt->head.flag) == VRV_FLAG && ENDIANS(p_pkt->head.type) == EX_OK ) {
        LOG_MSG("Get Communication key success!\n");
        *key = ENDIANL(p_pkt->head.key);
        return OK;
    } else {
        return FAIL;
    }
}
