#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

static uint16_t ip_id = -1;  // 使用全局变量ip_id
map_t map_store_fragment;

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
    // 发往上层（传输层），删去ip头部
    if(buf->len < sizeof(ip_hdr_t)){
        return;
    }
    ip_hdr_t* in_ip = (ip_hdr_t*)buf->data;
    if(in_ip->version != IP_VERSION_4 || swap16(in_ip->total_len16) > buf->len){
        return;
    }
    uint16_t ori_checksum = in_ip->hdr_checksum16;
    in_ip->hdr_checksum16 = 0;
    if(ori_checksum != checksum16((uint16_t*)in_ip,sizeof(ip_hdr_t))){
        return;
    }
    in_ip->hdr_checksum16 = ori_checksum;
    if(memcmp(in_ip->dst_ip,net_if_ip,NET_IP_LEN) != 0){
        return;
    }
    if(buf->len > swap16(in_ip->total_len16)){
        buf_remove_padding(buf,buf->len - swap16(in_ip->total_len16));
    }
    buf_remove_header(buf,sizeof(ip_hdr_t));
    if(in_ip->protocol == NET_PROTOCOL_ICMP){
        #ifdef PING    // 仅在PING测试模式下修改TTL，避免其他模块（如ip_test）因缺少icmp相关函数而报错
            set_ping_req_TTL(in_ip->ttl,buf);
        #endif
    }
    ip_fragment_in(in_ip->protocol,swap16(in_ip->flags_fragment16),buf,in_ip->src_ip,swap16(in_ip->id16));
}

/**
 * @brief 若无分片直接向上传。若有分片等分片到齐再传
 * 
 * @param protocol 协议号
 * @param flags_fragment16 分片标志
 * @param buf 向上传的数据包（已去除ip头部）
 * @param src_ip 源ip地址
 * @param id ip报文的id
 */
void ip_fragment_in(uint8_t protocol,uint16_t flags_fragment16,buf_t* buf,uint8_t* src_ip,uint16_t id){
    if(flags_fragment16 == 0){
        ip_fragment_send_in(protocol,src_ip,buf,id);
        return;
    }

    int MF = flags_fragment16 & IP_MORE_FRAGMENT;
    int offset = (flags_fragment16 & 0x1FFF) * IP_HDR_OFFSET_PER_BYTE;
    int length = buf->len;

    ipFragment_mess_t* fragment_mess = (ipFragment_mess_t*)map_get(&map_store_fragment,&id);
    if(!fragment_mess){
        fragment_mess = (ipFragment_mess_t*) malloc (sizeof(ipFragment_mess_t));
        fragment_mess->receive_bytes = 0;
        fragment_mess->total_bytes = -1;
        memset(fragment_mess->map_offset,0,sizeof(fragment_mess->map_offset));
        map_set(&map_store_fragment,&id,fragment_mess);
        fragment_mess = (ipFragment_mess_t*)map_get(&map_store_fragment,&id);   // 注意要将fragment_mess改为map里的引用
    }

    if(fragment_mess->map_offset[offset / IP_HDR_OFFSET_PER_BYTE]){
        printf("repeat ip package!id:%d\n",id);
        return;
    }

    if(MF == 0){    // 总长度由最后一个分片计算得到
        fragment_mess->total_bytes = offset + length;
    }
    mingw_gettimeofday(&fragment_mess->last_update,NULL);
    memcpy(fragment_mess->payload + offset,buf->data,length);
    fragment_mess->receive_bytes += length;
    fragment_mess->map_offset[offset / IP_HDR_OFFSET_PER_BYTE] = 1;

    if(fragment_mess->receive_bytes == fragment_mess->total_bytes){    // 集齐了就往上发并从缓存里删去
        buf_t send_buf;
        buf_init(&send_buf,fragment_mess->total_bytes);
        memcpy(send_buf.data,fragment_mess->payload,fragment_mess->total_bytes);
        ip_fragment_send_in(protocol,src_ip,&send_buf,id);
        map_delete(&map_store_fragment,&id);
    }
}

/**
 * @brief 对每个缓存的ip分片进行超时检查
 */
void fragment_check(){
    map_foreach(&map_store_fragment,fragment_check_entry);
}

/**
 * @brief 超时检查。若超时直接从缓存里删去
 */
void fragment_check_entry(void *id, void *ipfragment_mess, time_t *timestamp){
    ipFragment_mess_t* fragment_mess = (ipFragment_mess_t*) ipfragment_mess;
    dtime_t now;
    mingw_gettimeofday(&now,NULL);
    if(calcul_diff_time(fragment_mess->last_update,now) > IP_FRAGMENT_TIMEOUT){
        printf("clear id:%u timeout!\n",*((uint16_t*)id));
        map_delete(&map_store_fragment,id);
    }
}

/**
 * @brief 将整合好的ip包向上传
 * 
 * @param protocol 上层协议
 * @param src_ip 源ip
 * @param buf 数据包
 * @param id id，用于打印信息用
 */
void ip_fragment_send_in(uint8_t protocol,uint8_t* src_ip,buf_t* buf,uint16_t id){
    #ifndef IP_SER
        if(net_in(buf,protocol,src_ip) != 0){  
            buf_add_header(buf,sizeof(ip_hdr_t));
            icmp_unreachable(buf,src_ip,ICMP_CODE_PROTOCOL_UNREACH);
        }
    #else
        printf("success! id:%d buf_len:%d, buf_data:%x\n",id,(int)buf->len,buf->data[0]);
    #endif
}

/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    // TO-DO
    buf_add_header(buf,sizeof(ip_hdr_t));
    ip_hdr_t to_add_ip;
    to_add_ip.hdr_len = sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE;
    to_add_ip.version = IP_VERSION_4;
    to_add_ip.tos = 0;
    to_add_ip.total_len16 = swap16(buf->len);  // 记得要大小端转换
    to_add_ip.id16 = swap16(id);
    offset /= IP_HDR_OFFSET_PER_BYTE;
    to_add_ip.flags_fragment16 = swap16((mf ? IP_MORE_FRAGMENT : 0) | offset);
    to_add_ip.ttl = IP_DEFALUT_TTL; 
    to_add_ip.protocol = protocol;
    to_add_ip.hdr_checksum16 = 0;
    memcpy(to_add_ip.src_ip,net_if_ip,NET_IP_LEN);
    memcpy(to_add_ip.dst_ip,ip,NET_IP_LEN);
    to_add_ip.hdr_checksum16 = checksum16((uint16_t*)(&to_add_ip),sizeof(ip_hdr_t)); // 要进行类型转换
    memcpy(buf->data,&to_add_ip,sizeof(ip_hdr_t));
    arp_out(buf,ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    // TO-DO
    // 发往下层（数据链路层），加上ip头
    int max_dataSize = ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t);
    int offset = 0;
    int buf_len = buf->len;
    ip_id++;
    if(buf_len <= max_dataSize){
        ip_fragment_out(buf,ip,protocol,ip_id,offset,0);  
        return;
    }
    buf_t* ip_buf;
    while(buf_len > max_dataSize){
        ip_buf = (buf_t*) malloc (sizeof(buf_t));
        buf_init(ip_buf,max_dataSize);  // 重要！因为在ip_fragment_out中添加了头部，所以这个ip_buf的长度和data指针是被修改了的！要重新初始化
        memcpy(ip_buf->data,buf->data + offset,max_dataSize);
        ip_fragment_out(ip_buf,ip,protocol,ip_id,offset,1);
        offset += max_dataSize;
        buf_len -= max_dataSize;
        #ifdef IP_SER
            max_dataSize -= 128;   // 一次将分片长度减少128
        #endif
    }
    ip_buf = (buf_t*) malloc (sizeof(buf_t));
    buf_init(ip_buf,buf_len);  
    memcpy(ip_buf->data,buf->data + offset,buf_len);
    ip_fragment_out(ip_buf,ip,protocol,ip_id,offset,0);
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
    map_init(&map_store_fragment,sizeof(uint16_t),sizeof(ipFragment_mess_t),0,0,NULL,NULL);
}