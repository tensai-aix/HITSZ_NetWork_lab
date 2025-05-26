#include "icmp.h"

#include "ip.h"
#include "net.h"

map_t map_ping_req;
map_t map_ping;

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
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
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
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
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
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
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    map_init(&map_ping_req,sizeof(uint16_t),sizeof(ping_req_t),0,0,NULL,NULL);
    map_init(&map_ping,NET_IP_LEN,sizeof(ping_t),0,0,NULL,NULL);
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}

/**
 * @brief 发送一次ping_req
 * 
 * @param dst_ip 目的ip
 * @param id icmp请求的ID
 */
void icmp_req_out(uint8_t* dst_ip,uint16_t id){
    // 填充数据部分为32字节的0 
    buf_t* send_ping_req = &txbuf;
    buf_init(send_ping_req,PING_DATA_SIZE);
    memset(send_ping_req->data,0,PING_DATA_SIZE);

    // 填写icmp请求报头，其中序列号和标识符都设为id
    buf_add_header(send_ping_req,sizeof(icmp_hdr_t));
    icmp_hdr_t* hdr = (icmp_hdr_t*) send_ping_req->data;
    hdr->type = ICMP_TYPE_ECHO_REQUEST;
    hdr->code = 0;
    hdr->id16 = swap16(id);
    hdr->seq16 = swap16(id);
    hdr->checksum16 = 0;
    hdr->checksum16 = checksum16((uint16_t*)send_ping_req->data,send_ping_req->len);

    // 记录ping_req的发送时间并存入ping_req的map中
    ping_req_t ping_req;
    memcpy(ping_req.dst_ip,dst_ip,NET_IP_LEN);
    mingw_gettimeofday(&ping_req.send_time, NULL);
    memset(&ping_req.receive_time,0,sizeof(dtime_t));
    map_set(&map_ping_req,&id,&ping_req);

    ip_out(send_ping_req,dst_ip,NET_PROTOCOL_ICMP);
}

/**
 * @brief ping请求
 * 
 * @param dst_ip ping的ip地址
 * @return int 是否完成了ping请求
 */
int ping_req(uint8_t* dst_ip){
    ping_t* ping = (ping_t*)map_get(&map_ping,dst_ip);
    // 初始化一个ping
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
        printf("正在 Ping %s 具有 %d 字节的数据:\n",ip_to_string(dst_ip),PING_DATA_SIZE);
    }

    if(ping->is_finished){
        return 1;
    }

    time_t now = time(NULL);
    int finish = 0;
    // 检查上一次的ping_req,并发送ping_req
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
        printf("\n%s 的 Ping 统计信息:\n",ip_to_string(dst_ip));
        printf("    数据包: 已发送 = %d，已接收 = %d，丢失 = %d (%d%% 丢失)\n",PING_TEST_TIME,ping->success_time,PING_TEST_TIME- ping->success_time,100 - (100 * ping->success_time / PING_TEST_TIME));
        if(ping->success_time){
            printf("往返行程的估计时间(以毫秒为单位):\n");
            printf("    最短 = %dms，最长 = %dms，平均 = %dms\n",ping->shortest_time,ping->longest_time,ping->sum_time / ping->success_time);
        }
    }

    return 0;
}

/**
 * @brief 检查ping_req是否有效
 * 
 * @param ping
 */
void ping_req_check(ping_t* ping){
    ping_req_t* ping_req_entry = (ping_req_t*)map_get(&map_ping_req,&ping->ping_time);
    if(ping_req_entry->receive_time.tv_sec == 0 && ping_req_entry->receive_time.tv_usec == 0){
        printf("请求超时。\n");
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
        printf("来自 %s 的回复: 字节=%d 时间=%dms TTL=%d\n",ip_to_string(ping_req_entry->dst_ip),ping_req_entry->length,time_interval,ping_req_entry->TTL);
    }
}

/**
 * @brief 将ip转化为字符串
 * 
 * @param ip
 * @return char* 字符串
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
 * @brief 设置ping_req的TTL，由ip层调用此函数
 * 
 * @param TTL
 * @param buf 用于提取id
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