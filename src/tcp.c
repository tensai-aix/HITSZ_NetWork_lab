#include "tcp.h"

#include "icmp.h"
#include "ip.h"

#include <assert.h>
#include <stdbool.h>

/**
 * @brief TCP 处理程序表
 *
 */
map_t tcp_handler_table;  // dst-port -> handler
/**
 * @brief TCP 连接表
 *
 */
static map_t tcp_conn_table;  // [src_ip, src_port, dst_port] -> tcp_conn

/* =============================== TOOLS =============================== */

/**
 * @brief 根据负载大小和报文段标志位计算序列空间长度
 *
 * @param len       数据包长度
 * @param flags     TCP 报文段的标志位
 * @return size_t   序列空间长度
 */
size_t bytes_in_flight(size_t len, uint8_t flags) {
    size_t res = len;
    if (TCP_FLG_ISSET(flags, TCP_FLG_SYN))
        res += 1;
    if (TCP_FLG_ISSET(flags, TCP_FLG_FIN))
        res += 1;
    return res;
}

/**
 * @brief 生成 TCP 连接的初始随机序列号（ISN）
 *
 */
static inline uint32_t tcp_generate_initial_seq() {
    return rand() % UINT32_MAX;
}

/**
 * @brief 重置 TCP 连接
 */
void tcp_rst(tcp_conn_t *tcp_conn) {
    memset(tcp_conn, 0, sizeof(tcp_conn_t));
    tcp_conn->state = TCP_STATE_LISTEN;
}

/**
 * @brief 生成标识一个 TCP 连接的三元组键
 *
 * @param ip        源 IP 地址
 * @param src_port  源端口号
 * @param dst_port  目标端口号
 * @return tcp_key_t
 */
static inline tcp_key_t generate_tcp_key(uint8_t remote_ip[NET_IP_LEN], uint16_t remote_port, uint16_t host_port) {
    tcp_key_t key;
    memcpy(key.remote_ip, remote_ip, NET_IP_LEN);
    key.remote_port = remote_port;
    key.host_port = host_port;
    return key;
}

/**
 * @brief 根据指定的 IP 和端口信息查找或创建 TCP 连接
 *
 * @param remote_ip
 * @param remote_port
 * @param host_port
 * @param create_if_missing 若为 1，则在未找到连接时创建新的 TCP 连接；若为 0，则仅查找
 *
 * @return tcp_conn_t* 指向已存在或新创建的 TCP 连接的指针；若未找到且无需创建，则返回 NULL
 */
static inline tcp_conn_t *tcp_get_connection(uint8_t remote_ip[NET_IP_LEN], uint16_t remote_port, uint16_t host_port, uint8_t create_if_missing) {
    tcp_key_t key = generate_tcp_key(remote_ip, remote_port, host_port);
    tcp_conn_t *tcp_conn = map_get(&tcp_conn_table, &key);
    if (!tcp_conn && create_if_missing) {
        tcp_conn_t new_conn;
        tcp_rst(&new_conn);
        map_set(&tcp_conn_table, &key, &new_conn);
        tcp_conn = map_get(&tcp_conn_table, &key);
    }
    return tcp_conn;
}

/**
 * @brief 关闭一个 TCP 连接
 *
 * @param remote_ip
 * @param remote_port
 * @param host_port
 */
static inline void tcp_close_connection(uint8_t remote_ip[NET_IP_LEN], uint16_t remote_port, uint16_t host_port) {
    tcp_key_t key = generate_tcp_key(remote_ip, remote_port, host_port);
    map_delete(&tcp_conn_table, &key);
}

/* =============================== TOOLS =============================== */

/* =============================== COMMON API =============================== */

/**
 * @brief 填写 TCP 报文头并发送
 *
 * @param tcp_conn  指向当前 TCP 连接的指针，用于获取和更新序列号、确认号、窗口大小等状态信息
 * @param buf       数据缓冲区，payload 为要发送的数据
 * @param src_port  源端口号
 * @param dst_ip    目标IP地址
 * @param dst_port  目标端口号
 * @param flags     TCP 标志位
 */
void tcp_out(tcp_conn_t *tcp_conn, buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port, uint8_t flags) {
    /* =============================== TODO 1 BEGIN =============================== */
    buf_add_header(buf,sizeof(tcp_hdr_t));
    tcp_hdr_t* tcp_head = (tcp_hdr_t*) buf->data;
    tcp_head->src_port16 = swap16(src_port);
    tcp_head->dst_port16 = swap16(dst_port);
    tcp_head->seq = swap32(tcp_conn->seq);
    tcp_head->ack = swap32(tcp_conn->ack);
    tcp_head->doff = TCP_HEADER_LEN << 2;
    tcp_head->flags = flags;
    tcp_head->win = swap16(TCP_MAX_WINDOW_SIZE);
    tcp_head->uptr = 0;
    tcp_head->checksum16 = 0;
    tcp_head->checksum16 = transport_checksum(NET_PROTOCOL_TCP, buf, net_if_ip, dst_ip);
    ip_out(buf,dst_ip,NET_PROTOCOL_TCP);

    /* =============================== TODO 1 END =============================== */
}

/**
 * @brief 处理一个收到的 TCP 数据包
 *
 * @param buf       要处理的包
 * @param src_ip    源 IP 地址
 */
void tcp_in(buf_t *buf, uint8_t *src_ip) {
    // 包检查：判断接收到的数据包长度是否小于 TCP 头部的长度
    // 如果小于，则说明数据包不完整，直接返回，不进行后续处理
    if (buf->len < sizeof(tcp_hdr_t))
        return;

    tcp_hdr_t *hdr = (tcp_hdr_t *)buf->data;

    // 校验checksum
    uint16_t checksum = hdr->checksum16;
    hdr->checksum16 = 0;
    if (transport_checksum(NET_PROTOCOL_TCP, buf, src_ip, net_if_ip) != checksum)
        return;

    uint8_t *remote_ip = src_ip;
    uint16_t remote_port = swap16(hdr->src_port16);
    uint16_t host_port = swap16(hdr->dst_port16);
    tcp_conn_t *tcp_conn = tcp_get_connection(remote_ip, remote_port, host_port, true);

    uint8_t recv_flags = hdr->flags;
    // 收到RST，关闭 TCP 连接
    if (TCP_FLG_ISSET(recv_flags, TCP_FLG_RST)) {
        tcp_close_connection(remote_ip, remote_port, host_port);
        return;
    }

    uint32_t remote_seq = swap32(hdr->seq);
    uint32_t tcp_hdr_sz = (hdr->doff >> 4) * 4;   // tcp头部的大小
    int data_len = buf->len - tcp_hdr_sz;

    /* =============================== TODO 2 BEGIN =============================== */
    /* Step1 ：根据接收包数据更新当前TCP连接内部状态，并填写回复报文的标志部分。 */

    uint8_t send_flags = 0;  // 回复报文的标志位字段

     // 根据当前 TCP 连接的状态进行不同的处理    
    switch (tcp_conn->state) {
        case TCP_STATE_LISTEN:
            // TODO: 仅在收到连接报文时（SYN报文）才做出处理，否则直接返回
            if(recv_flags != TCP_FLG_SYN){
                return;
            }
            // TODO: 初始化 TCP 连接上下文（tcp_conn结构体）的seq字段
            tcp_conn->seq = 0;
            // TODO: 填写 TCP 连接上下文（tcp_conn结构体）的ack字段
            tcp_conn->ack = remote_seq + 1;
            // TODO: 填写回复标志 send_flags
            send_flags = TCP_FLG_SYN | TCP_FLG_ACK;
            // TODO: 进行状态转移
            tcp_conn->state = TCP_STATE_SYN_RECEIVED;
            break;

        case TCP_STATE_SYN_RECEIVED:
            // TODO: 仅在收到确认报文时（ACK报文）才做出处理，否则直接返回
            if(recv_flags != TCP_FLG_ACK){
                return;
            }
            // TODO: 进行状态转移
            tcp_conn->state = TCP_STATE_ESTABLISHED;
            break;

        case TCP_STATE_ESTABLISHED:
            // 未收到顺序包，丢弃并发送重复 ACK
            if (remote_seq != tcp_conn->ack) {
                buf_init(&txbuf, 0);
                tcp_out(tcp_conn, &txbuf, host_port, remote_ip, remote_port, TCP_FLG_ACK);
                return;
            }
            // TODO: 计算接收到的数据长度，更新 ACK
            tcp_conn->ack += data_len;
            // TODO: 如果接收报文携带数据，则填写回复标志 send_flags 发送ACK
            if(data_len){
                send_flags = TCP_FLG_ACK;
            }
            // TODO: 如果收到 FIN 报文，则增加 send_flags 相应标志位，并且进行状态转移
            if(TCP_FLG_ISSET(recv_flags,TCP_FLG_FIN)){
                send_flags = TCP_FLG_ACK | TCP_FLG_FIN;
                tcp_conn->ack += 1;
                tcp_conn->state = TCP_STATE_LAST_ACK;
            }
            break;

        case TCP_STATE_LAST_ACK:
            // TODO: 仅在收到确认报文时（ACK报文）才做出处理，否则直接返回
            if(recv_flags != TCP_FLG_ACK){
                return;
            }
            // TODO: 关闭 TCP 连接
            tcp_close_connection(remote_ip,remote_port,host_port);
            break;

        default:
            printf("do not support state %d\n", tcp_conn->state);
            break;
    }

    /* Step2 ：如果接收报文携带数据，则将数据部分交付给上层应用 */
    // TODO
    if(data_len){
        tcp_handler_t* handler = (tcp_handler_t*)map_get(&tcp_handler_table,&host_port);
        if(handler){
            buf_remove_header(buf,tcp_hdr_sz);
            (*handler)(tcp_conn,buf->data,buf->len,src_ip,remote_port);   
        }
        else{
            buf_add_header(buf,sizeof(ip_hdr_t));
            icmp_unreachable(buf,src_ip,ICMP_CODE_PORT_UNREACH);
        }
    }
    
    /* Step3 ：调用tcp_out()发送回复报文，更新TCP连接序列号。 */
    // 如果无需回复，则接收逻辑结束
    if (send_flags == 0)
        return;
    // 如果 send_flags 只标识了 ACK 字段，并且应用程序已通过 tcp_send() 发送顺带 ACK，则无需再进行回复
    if (bytes_in_flight(0, send_flags) == 0 && tcp_conn->not_send_empty_ack) {
        assert(TCP_FLG_ISSET(send_flags, TCP_FLG_ACK));
        tcp_conn->not_send_empty_ack = 0;
        return;
    }

    // TODO:  初始化一个新的缓冲区，发送回复报文
    buf_t txbuf;
    buf_init(&txbuf,0);
    tcp_out(tcp_conn,&txbuf,host_port,remote_ip,remote_port,send_flags);
    // TODO: 更新序列号
    tcp_conn->seq += bytes_in_flight(0,send_flags);  // 数据部分的seq变化在tcp_send()里！这里只进行标志部分的seq变化
    /* =============================== TODO 2 END =============================== */
}

/**
 * @brief 发送一个 TCP 包
 *
 * @param tcp_conn  指向当前 TCP 连接的指针
 * @param data      要发送的数据
 * @param len       数据长度
 * @param src_port  源端口号
 * @param dst_ip    目的ip地址
 * @param dst_port  目的端口号
 */
void tcp_send(tcp_conn_t *tcp_conn, uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port) {
    // 检查payload长度是否合法
    if (len > TCP_MAX_WINDOW_SIZE) {
        printf("package is too big [max value = %d, current value = %d], please split it into small pieces in the user functions.\n", TCP_MAX_WINDOW_SIZE, len);
        return;
    }
    if (len == 0) {
        printf("no payload to send, skipping transmission.\n");
        return;
    }

    // 发送数据包
    buf_t tx_buf;
    buf_init(&tx_buf, len);
    if (data)
        memcpy(tx_buf.data, data, len);
    tcp_out(tcp_conn, &tx_buf, src_port, dst_ip, dst_port, TCP_FLG_ACK /* 顺带 ACK */);

    // 更新序列号
    tcp_conn->seq += bytes_in_flight(len, 0);
    // 标注已 ACK
    tcp_conn->not_send_empty_ack = 1;
}

/**
 * @brief 初始化 TCP 协议
 *
 */
void tcp_init() {
    map_init(&tcp_handler_table, sizeof(uint16_t), sizeof(tcp_handler_t), 0, 0, NULL, NULL);
    map_init(&tcp_conn_table, sizeof(tcp_key_t), sizeof(tcp_conn_t), 0, 0, NULL, NULL);
    net_add_protocol(NET_PROTOCOL_TCP, tcp_in);
    // 初始化随机数种子，为生成 TCP 初始序列号提供支持
    srand(time(NULL));
}

/**
 * @brief 打开一个 TCP 端口并注册处理程序
 *
 * @param port      端口号
 * @param handler   处理程序
 * @return int      成功为0，失败为-1
 */
int tcp_open(uint16_t port, tcp_handler_t handler) {
    return map_set(&tcp_handler_table, &port, &handler);
}

static _Thread_local uint16_t close_port;
static void close_port_fn(void *key, void *value, time_t *timestamp) {
    tcp_key_t *tcp_key = key;
    if (tcp_key->host_port == close_port) {
        map_delete(&tcp_conn_table, key);
    }
}
/**
 * @brief 关闭一个 TCP 端口
 */
void tcp_close(uint16_t port) {
    close_port = port;
    map_foreach(&tcp_conn_table, close_port_fn);
    map_delete(&tcp_handler_table, &port);
}

/* =============================== COMMON API =============================== */