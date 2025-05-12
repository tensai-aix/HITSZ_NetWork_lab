#include "icmp.h"

#include "ip.h"
#include "net.h"

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
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}