#include "driver.h"
#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "icmp.h"

#define BUF_AMOUNT 3   // 要发送的数据包数量
#define MAX_REC_BUF MAX_STORE_BUF  // 最大接收数据包数量
#define NET_PROTOCOL_TEST 253

typedef struct buf_record{
    buf_t *buf;
    dtime_t recv_time;
    int i, j;
    int valid;
} buf_record_t;

// 发送包相关数据
int send_buf_length[BUF_AMOUNT] = {2000, 2500, 3000};
buf_t send_buf[BUF_AMOUNT];
int send_amount = 0;
// 接收缓存列表
buf_record_t rec_buf_store[MAX_REC_BUF];
int receive_amount = 0;
// 分片延迟时间
int delay_time[ ][3] = {
    {0, 500, -1},
    {250, 0, -1},
    {0, 2000, 2000}
};

// 计算时间差
int calcul_diff_time(dtime_t before, dtime_t end) {
    return (end.tv_sec - before.tv_sec) * 1000 + (end.tv_usec - before.tv_usec) / 1000;
}

void send_in() {
    dtime_t now;
    mingw_gettimeofday(&now,NULL);

    for (int i = 0; i < receive_amount; i++) {
        if (!rec_buf_store[i].valid){
            continue;
        }
            
        int i_idx = rec_buf_store[i].i;
        int j_idx = rec_buf_store[i].j;
        int delay = delay_time[i_idx][j_idx];

        if (calcul_diff_time(rec_buf_store[i].recv_time,now) >= delay) {
            printf("Forwarding: packet %d, fragment %d\n", i_idx, j_idx);
            ethernet_in(rec_buf_store[i].buf);
            rec_buf_store[i].valid = 0;
        }
    }
}

void receive_buf(){
    if (driver_recv(&rxbuf) > 0) {
        ip_hdr_t* ip_hdr = (ip_hdr_t*)(rxbuf.data + sizeof(ether_hdr_t));
        if((memcmp(net_if_ip,ip_hdr->src_ip,NET_IP_LEN) != 0) && (ip_hdr->protocol != NET_PROTOCOL_TEST)){
            ethernet_in(&rxbuf);
        }
        else{
            buf_record_t* rec = &rec_buf_store[receive_amount];
            rec->buf = (buf_t*)malloc(sizeof(buf_t));
            memcpy(rec->buf, &rxbuf, sizeof(buf_t));
            mingw_gettimeofday(&rec->recv_time, NULL);

            uint8_t* data = (uint8_t*)(rec->buf->data + sizeof(ether_hdr_t) + sizeof(ip_hdr_t));

            rec->i = data[0];
            rec->j = (swap16(ip_hdr->flags_fragment16) & 0x1FFF) / ((ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t)) / IP_HDR_OFFSET_PER_BYTE);
            
            rec->valid = 1;
            receive_amount++;
            printf("receive:%d %d,id:%d,rec_num:%d\n",rec->i,rec->j,swap16(ip_hdr->id16),receive_amount);
        }
    }
}

void send_out(){   
    if (send_amount < BUF_AMOUNT) {
        ip_out(&send_buf[send_amount],net_if_ip,NET_PROTOCOL_TEST);
        send_amount++;
    }
}

void init_buf(){
    for (int i = 0;i < BUF_AMOUNT;i++) {
        buf_init(&send_buf[i],send_buf_length[i]);
        memset(send_buf[i].data,i,send_buf_length[i]);
    }
}

void warmup(){
    dtime_t before,now;
    mingw_gettimeofday(&before, NULL);
    while(1){
        net_poll(); 
        mingw_gettimeofday(&now, NULL);
        if(calcul_diff_time(before,now) >= 1000){
            break;
        }
    }
}

int main(int argc, char const *argv[]) {
    if (net_init() == -1) {
        return -1;
    }

    // 初始化数据包
    init_buf();

    // 等待建立自身的ip-mac连接
    warmup();

    while (1) {
        send_out();       // 发送数据包
        receive_buf();    // 接收数据包
        send_in();        // 延迟发送
    }

    return 0;
}
