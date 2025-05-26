#include "icmp.h"

#include "ip.h"
#include "net.h"

map_t map_ping_req;
map_t map_ping;

/**
 * @brief ����icmp��Ӧ
 *
 * @param req_buf �յ���icmp�����
 * @param src_ip Դip��ַ
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip) {
    // TO-DO
    buf_init(&txbuf,req_buf->len);
    memcpy(txbuf.data,req_buf->data,req_buf->len);
    icmp_hdr_t* icmp_head = (icmp_hdr_t*)txbuf.data;
    icmp_head->type = ICMP_TYPE_ECHO_REPLY;
    icmp_head->checksum16 = 0;
    icmp_head->checksum16 = checksum16((uint16_t*)icmp_head,txbuf.len);
    ip_out(&txbuf,src_ip,NET_PROTOCOL_ICMP); 
}

/**
 * @brief ����һ���յ������ݰ�
 *
 * @param buf Ҫ��������ݰ�
 * @param src_ip Դip��ַ
 */
void icmp_in(buf_t *buf, uint8_t *src_ip) {
    // TO-DO
    if(buf->len < sizeof(icmp_hdr_t)){
        return;
    }
    icmp_hdr_t* icmp_head = (icmp_hdr_t*)buf->data;
    if(icmp_head->type == ICMP_TYPE_ECHO_REQUEST){
        icmp_resp(buf,src_ip);
    }
    else if(icmp_head->type == ICMP_TYPE_ECHO_REPLY){
        icmp_hdr_t* icmp_hdr = (icmp_hdr_t*) buf->data;
        int id = swap16(icmp_hdr->seq16);
        ping_req_t* ping_receive = (ping_req_t*)map_get(&map_ping_req,&id);
        mingw_gettimeofday(&ping_receive->receive_time, NULL);
        ping_receive->length = buf->len - sizeof(icmp_hdr_t);
    }
}

/**
 * @brief ����icmp���ɴ�
 *
 * @param recv_buf �յ���ip���ݰ�
 * @param src_ip Դip��ַ
 * @param code icmp code��Э�鲻�ɴ��˿ڲ��ɴ�
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
    // TO-DO
    int include_ip_bytes = 8 + sizeof(ip_hdr_t);
    buf_init(&txbuf,include_ip_bytes);
    memcpy(txbuf.data,recv_buf->data,include_ip_bytes);
    buf_add_header(&txbuf,sizeof(icmp_hdr_t));
    icmp_hdr_t* icmp_head = (icmp_hdr_t*) txbuf.data;
    icmp_head->type = ICMP_TYPE_UNREACH;
    icmp_head->code = code;
    icmp_head->id16 = 0;
    icmp_head->seq16 = 0;
    icmp_head->checksum16 = 0;
    icmp_head->checksum16 = checksum16((uint16_t*)txbuf.data,txbuf.len);
    ip_out(&txbuf,src_ip,NET_PROTOCOL_ICMP);
}

/**
 * @brief ��ʼ��icmpЭ��
 *
 */
void icmp_init() {
    map_init(&map_ping_req,sizeof(uint16_t),sizeof(ping_req_t),0,0,NULL,NULL);
    map_init(&map_ping,NET_IP_LEN,sizeof(ping_t),0,0,NULL,NULL);
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}

/**
 * @brief ����һ��ping_req
 * 
 * @param dst_ip Ŀ��ip
 * @param id icmp�����ID
 */
void icmp_req_out(uint8_t* dst_ip,uint16_t id){
    // ������ݲ���Ϊ32�ֽڵ�0 
    buf_t* send_ping_req = &txbuf;
    buf_init(send_ping_req,PING_DATA_SIZE);
    memset(send_ping_req->data,0,PING_DATA_SIZE);

    // ��дicmp����ͷ���������кźͱ�ʶ������Ϊid
    buf_add_header(send_ping_req,sizeof(icmp_hdr_t));
    icmp_hdr_t* hdr = (icmp_hdr_t*) send_ping_req->data;
    hdr->type = ICMP_TYPE_ECHO_REQUEST;
    hdr->code = 0;
    hdr->id16 = swap16(id);
    hdr->seq16 = swap16(id);
    hdr->checksum16 = 0;
    hdr->checksum16 = checksum16((uint16_t*)send_ping_req->data,send_ping_req->len);

    // ��¼ping_req�ķ���ʱ�䲢����ping_req��map��
    ping_req_t ping_req;
    memcpy(ping_req.dst_ip,dst_ip,NET_IP_LEN);
    mingw_gettimeofday(&ping_req.send_time, NULL);
    memset(&ping_req.receive_time,0,sizeof(dtime_t));
    map_set(&map_ping_req,&id,&ping_req);

    ip_out(send_ping_req,dst_ip,NET_PROTOCOL_ICMP);
}

/**
 * @brief ping����
 * 
 * @param dst_ip ping��ip��ַ
 * @return int �Ƿ������ping����
 */
int ping_req(uint8_t* dst_ip){
    ping_t* ping = (ping_t*)map_get(&map_ping,dst_ip);
    // ��ʼ��һ��ping
    if(!ping){
        ping_t new_ping;
        new_ping.is_finished = 0;
        new_ping.last_send = time(NULL);
        new_ping.ping_time = 0;
        new_ping.shortest_time = 1000;
        new_ping.longest_time = 0;
        new_ping.success_time = 0;
        new_ping.sum_time = 0;
        map_set(&map_ping,dst_ip,&new_ping);
        ping = &new_ping;
        printf("ping %s\n\n",ip_to_string(dst_ip));
        printf("���� Ping %s ���� %d �ֽڵ�����:\n",ip_to_string(dst_ip),PING_DATA_SIZE);
    }

    if(ping->is_finished){
        return 1;
    }

    time_t now = time(NULL);
    int finish = 0;
    // �����һ�ε�ping_req,������ping_req
    if(now - ping->last_send >= 1){
        if(ping->ping_time >= 1){
            ping_req_check(ping);
        }
        if(ping->ping_time == PING_TEST_TIME){
            finish = 1;
        }
        else{
            ping->ping_time++;
            icmp_req_out(dst_ip,ping->ping_time);
            ping->last_send = now;
        }
    }

    if(finish){
        ping->is_finished = 1;
        printf("\n%s �� Ping ͳ����Ϣ:\n",ip_to_string(dst_ip));
        printf("    ���ݰ�: �ѷ��� = %d���ѽ��� = %d����ʧ = %d (%d%% ��ʧ)\n",PING_TEST_TIME,ping->success_time,PING_TEST_TIME- ping->success_time,100 - (100 * ping->success_time / PING_TEST_TIME));
        if(ping->success_time){
            printf("�����г̵Ĺ���ʱ��(�Ժ���Ϊ��λ):\n");
            printf("    ��� = %dms��� = %dms��ƽ�� = %dms\n",ping->shortest_time,ping->longest_time,ping->sum_time / ping->success_time);
        }
    }

    return 0;
}

/**
 * @brief ���ping_req�Ƿ���Ч
 * 
 * @param ping
 */
void ping_req_check(ping_t* ping){
    ping_req_t* ping_req_entry = (ping_req_t*)map_get(&map_ping_req,&ping->ping_time);
    if(ping_req_entry->receive_time.tv_sec == 0 && ping_req_entry->receive_time.tv_usec == 0){
        printf("����ʱ��\n");
    }
    else{
        int time_interval = (ping_req_entry->receive_time.tv_sec - ping_req_entry->send_time.tv_sec) * 1000 + (ping_req_entry->receive_time.tv_usec - ping_req_entry->send_time.tv_usec) / 1000;
        if(time_interval < ping->shortest_time){
            ping->shortest_time = time_interval;
        }
        if(time_interval > ping->longest_time){
            ping->longest_time = time_interval;
        } 
        ping->sum_time += time_interval;
        ping->success_time++;
        printf("���� %s �Ļظ�: �ֽ�=%d ʱ��=%dms TTL=%d\n",ip_to_string(ping_req_entry->dst_ip),ping_req_entry->length,time_interval,ping_req_entry->TTL);
    }
}

/**
 * @brief ��ipת��Ϊ�ַ���
 * 
 * @param ip
 * @return char* �ַ���
 */
char* ip_to_string(uint8_t *ip) {
    static char result[32];
    if (ip == 0) {
        return "(null)";
    } else {
        sprintf(result, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
        return result;
    }
}

/**
 * @brief ����ping_req��TTL����ip����ô˺���
 * 
 * @param TTL
 * @param buf ������ȡid
 */
void set_ping_req_TTL(uint8_t TTL,buf_t* buf){
    icmp_hdr_t* icmp_hdr = (icmp_hdr_t*) buf->data;
    if(icmp_hdr->type != ICMP_TYPE_ECHO_REPLY){
        return;
    }
    int id = swap16(icmp_hdr->seq16);
    ping_req_t* ping_receive = (ping_req_t*)map_get(&map_ping_req,&id);
    ping_receive->TTL = TTL;
}