/*libnetfilter_queue.c: generic library for access to nf_queue
  *
  * (C) 2005 by Harald Welte <laforge@gnumonks.org>
  * (C) 2005, 2008-2010 by Pablo Neira Ayuso <pablo@netfilter.org>
  *
  *  This program is free software; you can redistribute it and/or modify
  *  it under the terms of the GNU General Public License version 2 
  *  as published by the Free Software Foundation (or any later at your option)
  *
  *  This program is distributed in the hope that it will be useful,
  *  but WITHOUT ANY WARRANTY; without even the implied warranty of
  *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  *  GNU General Public License for more details.
  *
  *  You should have received a copy of the GNU General Public License
  *  along with this program; if not, write to the Free Software
  *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
  *
  *  2006-01-23 Andreas Florath <andreas@florath.net>
  *      Fix __set_verdict() that it can now handle payload.
  */
 
 #include <stdio.h>
 #include <stdlib.h>
 #include <unistd.h>
 #include <string.h>
 #include <ctype.h>
 #include <time.h>
 #include <errno.h>
 #include <netinet/in.h>
 #include <sys/socket.h>
 
 #include "linux_nfnetlink_compat.h"
 #include "linux_nfnetlink.h"
 #include "libnfnetlink.h"
 #include "libnetfilter_queue.h"
 #include "nfnetlink_queue.h"

 
 struct nfq_handle
 {
         struct nfnl_handle *nfnlh;
         struct nfnl_subsys_handle *nfnlssh;
         struct nfq_q_handle *qh_list;
 };
 
 struct nfq_q_handle
 {
         struct nfq_q_handle *next;
         struct nfq_handle *h;
         u_int16_t id;
 
         nfq_callback *cb;
         void *data;
 };
 
 struct nfq_data {
         struct nfattr **data;
 };
 
 int nfq_errno;
 
 /***********************************************************************
  * low level stuff 
  ***********************************************************************/
 
 static void del_qh(struct nfq_q_handle *qh)
 {
         struct nfq_q_handle *cur_qh, *prev_qh = NULL;
 
         for (cur_qh = qh->h->qh_list; cur_qh; cur_qh = cur_qh->next) {
                 if (cur_qh == qh) {
                         if (prev_qh)
                                 prev_qh->next = qh->next;
                         else
                                 qh->h->qh_list = qh->next;
                         return;
                 }
                 prev_qh = cur_qh;
         }
 }
 
 static void add_qh(struct nfq_q_handle *qh)
 {
         qh->next = qh->h->qh_list;
         qh->h->qh_list = qh;
 }
 
 static struct nfq_q_handle *find_qh(struct nfq_handle *h, u_int16_t id)
 {
         struct nfq_q_handle *qh;
 
         for (qh = h->qh_list; qh; qh = qh->next) {
                 if (qh->id == id)
                         return qh;
         }
         return NULL;
 }
 
 /* build a NFQNL_MSG_CONFIG message */
         static int
 __build_send_cfg_msg(struct nfq_handle *h, u_int8_t command,
                 u_int16_t queuenum, u_int16_t pf)
 {
         union {
                 char buf[NFNL_HEADER_LEN
                         +NFA_LENGTH(sizeof(struct nfqnl_msg_config_cmd))];
                 struct nlmsghdr nmh;
         } u;
         struct nfqnl_msg_config_cmd cmd;
 
         nfnl_fill_hdr(h->nfnlssh, &u.nmh, 0, AF_UNSPEC, queuenum,
                         NFQNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);
 
         cmd.command = command;
         cmd.pf = htons(pf);
         nfnl_addattr_l(&u.nmh, sizeof(u), NFQA_CFG_CMD, &cmd, sizeof(cmd));
 
         return nfnl_query(h->nfnlh, &u.nmh);
 }
 
 static int __nfq_rcv_pkt(struct nlmsghdr *nlh, struct nfattr *nfa[],
                 void *data)
 {
         struct nfgenmsg *nfmsg = NLMSG_DATA(nlh);
         struct nfq_handle *h = data;
         u_int16_t queue_num = ntohs(nfmsg->res_id);
         struct nfq_q_handle *qh = find_qh(h, queue_num);
         struct nfq_data nfqa;
 
         if (!qh)
                 return -ENODEV;
 
         if (!qh->cb)
                 return -ENODEV;
 
         nfqa.data = nfa;
 
         return qh->cb(qh, nfmsg, &nfqa, qh->data);
 }
 
 static struct nfnl_callback pkt_cb = {
         .call           = &__nfq_rcv_pkt,
         .attr_count     = NFQA_MAX,
 };
 
 /* public interface */
 
 struct nfnl_handle *nfq_nfnlh(struct nfq_handle *h)
 {
         return h->nfnlh;
 }
 
 int nfq_fd(struct nfq_handle *h)
 {
         return nfnl_fd(nfq_nfnlh(h));
 }
 
 struct nfq_handle *nfq_open(void)
 {
         struct nfnl_handle *nfnlh = nfnl_open();
         struct nfq_handle *qh;
 
         if (!nfnlh)
                 return NULL;
 
         /* unset netlink sequence tracking by default */
         nfnl_unset_sequence_tracking(nfnlh);
 
         qh = nfq_open_nfnl(nfnlh);
         if (!qh)
                 nfnl_close(nfnlh);
 
         return qh;
 }
 
 struct nfq_handle *nfq_open_nfnl(struct nfnl_handle *nfnlh)
 {
         struct nfq_handle *h;
         int err;
 
         h = malloc(sizeof(*h));
         if (!h)
                 return NULL;
 
         memset(h, 0, sizeof(*h));
         h->nfnlh = nfnlh;
 
         h->nfnlssh = nfnl_subsys_open(h->nfnlh, NFNL_SUBSYS_QUEUE, 
                                       NFQNL_MSG_MAX, 0);
         if (!h->nfnlssh) {
                 /* FIXME: nfq_errno */
                 goto out_free;
         }
 
         pkt_cb.data = h;
         err = nfnl_callback_register(h->nfnlssh, NFQNL_MSG_PACKET, &pkt_cb);
         if (err < 0) {
                 nfq_errno = err;
                 goto out_close;
         }
 
         return h;
 out_close:
         nfnl_subsys_close(h->nfnlssh);
 out_free:
         free(h);
         return NULL;
 }
 
 int nfq_close(struct nfq_handle *h)
 {
         int ret;
         
         ret = nfnl_close(h->nfnlh);
         if (ret == 0)
                 free(h);
         return ret;
 }
 
 int nfq_bind_pf(struct nfq_handle *h, u_int16_t pf)
 {
         return __build_send_cfg_msg(h, NFQNL_CFG_CMD_PF_BIND, 0, pf);
 }
 
 int nfq_unbind_pf(struct nfq_handle *h, u_int16_t pf)
 {
         return __build_send_cfg_msg(h, NFQNL_CFG_CMD_PF_UNBIND, 0, pf);
 }
 
 
 
 struct nfq_q_handle *nfq_create_queue(struct nfq_handle *h, 
                 u_int16_t num,
                 nfq_callback *cb,
                 void *data)
 {
         int ret;
         struct nfq_q_handle *qh;
 
         if (find_qh(h, num))
                 return NULL;
 
         qh = malloc(sizeof(*qh));
 
         memset(qh, 0, sizeof(*qh));
         qh->h = h;
         qh->id = num;
         qh->cb = cb;
         qh->data = data;
 
         ret = __build_send_cfg_msg(h, NFQNL_CFG_CMD_BIND, num, 0);
         if (ret < 0) {
                 nfq_errno = ret;
                 free(qh);
                 return NULL;
         }
 
         add_qh(qh);
         return qh;
 }
 
 int nfq_destroy_queue(struct nfq_q_handle *qh)
 {
         int ret = __build_send_cfg_msg(qh->h, NFQNL_CFG_CMD_UNBIND, qh->id, 0);
         if (ret == 0) {
                 del_qh(qh);
                 free(qh);
         }
 
         return ret;
 }
 
 int nfq_handle_packet(struct nfq_handle *h, char *buf, int len)
 {
         return nfnl_handle_packet(h->nfnlh, buf, len);
 }
 
 int nfq_set_mode(struct nfq_q_handle *qh,
                 u_int8_t mode, u_int32_t range)
 {
         union {
                 char buf[NFNL_HEADER_LEN
                         +NFA_LENGTH(sizeof(struct nfqnl_msg_config_params))];
                 struct nlmsghdr nmh;
         } u;
         struct nfqnl_msg_config_params params;
 
         nfnl_fill_hdr(qh->h->nfnlssh, &u.nmh, 0, AF_UNSPEC, qh->id,
                         NFQNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);
 
         params.copy_range = htonl(range);
         params.copy_mode = mode;
         nfnl_addattr_l(&u.nmh, sizeof(u), NFQA_CFG_PARAMS, &params,
                         sizeof(params));
 
         return nfnl_query(qh->h->nfnlh, &u.nmh);
 }
 
 int nfq_set_queue_maxlen(struct nfq_q_handle *qh,
                                 u_int32_t queuelen)
 {
         union {
                 char buf[NFNL_HEADER_LEN
                         +NFA_LENGTH(sizeof(struct nfqnl_msg_config_params))];
                 struct nlmsghdr nmh;
         } u;
         u_int32_t queue_maxlen = htonl(queuelen);
 
         nfnl_fill_hdr(qh->h->nfnlssh, &u.nmh, 0, AF_UNSPEC, qh->id,
                         NFQNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);
 
         nfnl_addattr_l(&u.nmh, sizeof(u), NFQA_CFG_QUEUE_MAXLEN, &queue_maxlen,
                         sizeof(queue_maxlen));
 
         return nfnl_query(qh->h->nfnlh, &u.nmh);
 }
 
 static int __set_verdict(struct nfq_q_handle *qh, u_int32_t id,
                 u_int32_t verdict, u_int32_t mark, int set_mark,
                 u_int32_t data_len, const unsigned char *data)
 {
         struct nfqnl_msg_verdict_hdr vh;
         union {
                 char buf[NFNL_HEADER_LEN
                         +NFA_LENGTH(sizeof(mark))
                         +NFA_LENGTH(sizeof(vh))];
                 struct nlmsghdr nmh;
         } u;
 
         struct iovec iov[3];
         int nvecs;
 
         /* This must be declared here (and not inside the data
          * handling block) because the iovec points to this. */
         struct nfattr data_attr;
 
         memset(iov, 0, sizeof(iov));
 
         vh.verdict = htonl(verdict);
         vh.id = htonl(id);
 
         nfnl_fill_hdr(qh->h->nfnlssh, &u.nmh, 0, AF_UNSPEC, qh->id,
                         NFQNL_MSG_VERDICT, NLM_F_REQUEST);
 
         /* add verdict header */
         nfnl_addattr_l(&u.nmh, sizeof(u), NFQA_VERDICT_HDR, &vh, sizeof(vh));
 
         if (set_mark)
                 nfnl_addattr32(&u.nmh, sizeof(u), NFQA_MARK, mark);
 
         iov[0].iov_base = &u.nmh;
         iov[0].iov_len = NLMSG_TAIL(&u.nmh) - (void *)&u.nmh;
         nvecs = 1;
 
         if (data_len) {
                 /* The typecast here is to cast away data's const-ness: */
                 nfnl_build_nfa_iovec(&iov[1], &data_attr, NFQA_PAYLOAD,
                                 data_len, (unsigned char *) data);
                 nvecs += 2;
                 /* Add the length of the appended data to the message
                  * header.  The size of the attribute is given in the
                  * nfa_len field and is set in the nfnl_build_nfa_iovec()
                  * function. */
                 u.nmh.nlmsg_len += data_attr.nfa_len;
         }
 
         return nfnl_sendiov(qh->h->nfnlh, iov, nvecs, 0);
 }
 
 int nfq_set_verdict(struct nfq_q_handle *qh, u_int32_t id,
                 u_int32_t verdict, u_int32_t data_len, 
                 const unsigned char *buf)
 {
         return __set_verdict(qh, id, verdict, 0, 0, data_len, buf);
 }       
 
 int nfq_set_verdict2(struct nfq_q_handle *qh, u_int32_t id,
                      u_int32_t verdict, u_int32_t mark,
                      u_int32_t data_len, const unsigned char *buf)
 {
         return __set_verdict(qh, id, verdict, htonl(mark), 1, data_len, buf);
 }
 
 int nfq_set_verdict_mark(struct nfq_q_handle *qh, u_int32_t id,
                 u_int32_t verdict, u_int32_t mark,
                 u_int32_t data_len, const unsigned char *buf)
 {
         return __set_verdict(qh, id, verdict, mark, 1, data_len, buf);
 }
 
 /*************************************************************
  * Message parsing functions 
  *************************************************************/
 
 struct nfqnl_msg_packet_hdr *nfq_get_msg_packet_hdr(struct nfq_data *nfad)
 {
         return nfnl_get_pointer_to_data(nfad->data, NFQA_PACKET_HDR,
                                         struct nfqnl_msg_packet_hdr);
 }
 
 uint32_t nfq_get_nfmark(struct nfq_data *nfad)
 {
         return ntohl(nfnl_get_data(nfad->data, NFQA_MARK, u_int32_t));
 }
 
 int nfq_get_timestamp(struct nfq_data *nfad, struct timeval *tv)
 {
         struct nfqnl_msg_packet_timestamp *qpt;
         qpt = nfnl_get_pointer_to_data(nfad->data, NFQA_TIMESTAMP,
                                         struct nfqnl_msg_packet_timestamp);
         if (!qpt)
                 return -1;
 
         tv->tv_sec = __be64_to_cpu(qpt->sec);
         tv->tv_usec = __be64_to_cpu(qpt->usec);
 
         return 0;
 }
 
 u_int32_t nfq_get_indev(struct nfq_data *nfad)
 {
         return ntohl(nfnl_get_data(nfad->data, NFQA_IFINDEX_INDEV, u_int32_t));
 }
 
 u_int32_t nfq_get_physindev(struct nfq_data *nfad)
 {
         return ntohl(nfnl_get_data(nfad->data, NFQA_IFINDEX_PHYSINDEV, u_int32_t));
 }
 
 u_int32_t nfq_get_outdev(struct nfq_data *nfad)
 {
         return ntohl(nfnl_get_data(nfad->data, NFQA_IFINDEX_OUTDEV, u_int32_t));
 }
 
 u_int32_t nfq_get_physoutdev(struct nfq_data *nfad)
 {
         return ntohl(nfnl_get_data(nfad->data, NFQA_IFINDEX_PHYSOUTDEV, u_int32_t));
 }
 
 int nfq_get_indev_name(struct nlif_handle *nlif_handle,
                         struct nfq_data *nfad, char *name)
 {
         u_int32_t ifindex = nfq_get_indev(nfad);
         return nlif_index2name(nlif_handle, ifindex, name);
 }
 
 int nfq_get_physindev_name(struct nlif_handle *nlif_handle,
                            struct nfq_data *nfad, char *name)
 {
         u_int32_t ifindex = nfq_get_physindev(nfad);
         return nlif_index2name(nlif_handle, ifindex, name);
 }
 
 int nfq_get_outdev_name(struct nlif_handle *nlif_handle,
                         struct nfq_data *nfad, char *name)
 {
         u_int32_t ifindex = nfq_get_outdev(nfad);
         return nlif_index2name(nlif_handle, ifindex, name);
 }
 
 int nfq_get_physoutdev_name(struct nlif_handle *nlif_handle,
                             struct nfq_data *nfad, char *name)
 {
         u_int32_t ifindex = nfq_get_physoutdev(nfad);
         return nlif_index2name(nlif_handle, ifindex, name);
 }
 
 struct nfqnl_msg_packet_hw *nfq_get_packet_hw(struct nfq_data *nfad)
 {
         return nfnl_get_pointer_to_data(nfad->data, NFQA_HWADDR,
                                         struct nfqnl_msg_packet_hw);
 }
 
 int nfq_get_payload(struct nfq_data *nfad, unsigned char **data)
 {
         *data = (unsigned char*)nfnl_get_pointer_to_data(nfad->data, NFQA_PAYLOAD, char);
         if (*data)
                 return NFA_PAYLOAD(nfad->data[NFQA_PAYLOAD-1]);
 
         return -1;
 }
 
 #define SNPRINTF_FAILURE(ret, rem, offset, len)                 \
 do {                                                            \
         if (ret < 0)                                            \
                 return ret;                                     \
         len += ret;                                             \
         if (ret > rem)                                          \
                 ret = rem;                                      \
         offset += ret;                                          \
         rem -= ret;                                             \
 } while (0)
 
 int nfq_snprintf_xml(char *buf, size_t rem, struct nfq_data *tb, int flags)
 {
         struct nfqnl_msg_packet_hdr *ph;
         struct nfqnl_msg_packet_hw *hwph;
         u_int32_t mark, ifi;
         int size, offset = 0, len = 0, ret;
         unsigned char *data;
 
         size = snprintf(buf + offset, rem, "<pkt>");
         SNPRINTF_FAILURE(size, rem, offset, len);
 
         if (flags & NFQ_XML_TIME) {
                 time_t t;
                 struct tm tm;
 
                 t = time(NULL);
                 if (localtime_r(&t, &tm) == NULL)
                         return -1;
 
                 size = snprintf(buf + offset, rem, "<when>");
                 SNPRINTF_FAILURE(size, rem, offset, len);
 
                 size = snprintf(buf + offset, rem,
                                 "<hour>%d</hour>", tm.tm_hour);
                 SNPRINTF_FAILURE(size, rem, offset, len);
 
                 size = snprintf(buf + offset,
                                 rem, "<min>%02d</min>", tm.tm_min);
                 SNPRINTF_FAILURE(size, rem, offset, len);
 
                 size = snprintf(buf + offset,
                                 rem, "<sec>%02d</sec>", tm.tm_sec);
                 SNPRINTF_FAILURE(size, rem, offset, len);
 
                 size = snprintf(buf + offset, rem, "<wday>%d</wday>",
                                 tm.tm_wday + 1);
                 SNPRINTF_FAILURE(size, rem, offset, len);
 
                 size = snprintf(buf + offset, rem, "<day>%d</day>", tm.tm_mday);
                 SNPRINTF_FAILURE(size, rem, offset, len);
 
                 size = snprintf(buf + offset, rem, "<month>%d</month>",
                                 tm.tm_mon + 1);
                 SNPRINTF_FAILURE(size, rem, offset, len);
 
                 size = snprintf(buf + offset, rem, "<year>%d</year>",
                                 1900 + tm.tm_year);
                 SNPRINTF_FAILURE(size, rem, offset, len);
 
                 size = snprintf(buf + offset, rem, "</when>");
                 SNPRINTF_FAILURE(size, rem, offset, len);
         }
 
         ph = nfq_get_msg_packet_hdr(tb);
         if (ph) {
                 size = snprintf(buf + offset, rem,
                                 "<hook>%u</hook><id>%u</id>",
                                 ph->hook, ntohl(ph->packet_id));
                 SNPRINTF_FAILURE(size, rem, offset, len);
 
                 hwph = nfq_get_packet_hw(tb);
                 if (hwph && (flags & NFQ_XML_HW)) {
                         int i, hlen = ntohs(hwph->hw_addrlen);
 
                         size = snprintf(buf + offset, rem, "<hw><proto>%04x"
                                                            "</proto>",
                                         ntohs(ph->hw_protocol));
                         SNPRINTF_FAILURE(size, rem, offset, len);
 
                         size = snprintf(buf + offset, rem, "<src>");
                         SNPRINTF_FAILURE(size, rem, offset, len);
 
                         for (i=0; i<hlen; i++) {
                                 size = snprintf(buf + offset, rem, "%02x",
                                                 hwph->hw_addr[i]);
                                 SNPRINTF_FAILURE(size, rem, offset, len);
                         }
 
                         size = snprintf(buf + offset, rem, "</src></hw>");
                         SNPRINTF_FAILURE(size, rem, offset, len);
                 } else if (flags & NFQ_XML_HW) {
                         size = snprintf(buf + offset, rem, "<hw><proto>%04x"
                                                     "</proto></hw>",
                                  ntohs(ph->hw_protocol));
                         SNPRINTF_FAILURE(size, rem, offset, len);
                 }
         }
 
         mark = nfq_get_nfmark(tb);
         if (mark && (flags & NFQ_XML_MARK)) {
                 size = snprintf(buf + offset, rem, "<mark>%u</mark>", mark);
                 SNPRINTF_FAILURE(size, rem, offset, len);
         }
 
         ifi = nfq_get_indev(tb);
         if (ifi && (flags & NFQ_XML_DEV)) {
                 size = snprintf(buf + offset, rem, "<indev>%u</indev>", ifi);
                 SNPRINTF_FAILURE(size, rem, offset, len);
         }
 
         ifi = nfq_get_outdev(tb);
         if (ifi && (flags & NFQ_XML_DEV)) {
                 size = snprintf(buf + offset, rem, "<outdev>%u</outdev>", ifi);
                 SNPRINTF_FAILURE(size, rem, offset, len);
         }
 
         ifi = nfq_get_physindev(tb);
         if (ifi && (flags & NFQ_XML_PHYSDEV)) {
                 size = snprintf(buf + offset, rem,
                                 "<physindev>%u</physindev>", ifi);
                 SNPRINTF_FAILURE(size, rem, offset, len);
         }
 
         ifi = nfq_get_physoutdev(tb);
         if (ifi && (flags & NFQ_XML_PHYSDEV)) {
                 size = snprintf(buf + offset, rem,
                                 "<physoutdev>%u</physoutdev>", ifi);
                 SNPRINTF_FAILURE(size, rem, offset, len);
         }
 
         ret = nfq_get_payload(tb, &data);
         if (ret >= 0 && (flags & NFQ_XML_PAYLOAD)) {
                 int i;
 
                 size = snprintf(buf + offset, rem, "<payload>");
                 SNPRINTF_FAILURE(size, rem, offset, len);
 
                 for (i=0; i<ret; i++) {
                         size = snprintf(buf + offset, rem, "%02x",
                                         data[i] & 0xff);
                         SNPRINTF_FAILURE(size, rem, offset, len);
                 }
 
                 size = snprintf(buf + offset, rem, "</payload>");
                 SNPRINTF_FAILURE(size, rem, offset, len);
         }
 
         size = snprintf(buf + offset, rem, "</pkt>");
         SNPRINTF_FAILURE(size, rem, offset, len);
 
         return len;
 }
 
