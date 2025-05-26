#include "driver.h"
#include "net.h"
#include "tcp.h"

#define HTTP_MAX_PATH_LENGTH 1024
#define HTTP_MAX_RESPONSE_LENGTH 1024
#define HTTP_LISTEN_PORT 80

/**
 * @brief 根据文件路径返回对应的 MIME 类型
 *
 * @param file_path 文件路径
 * @return MIME 类型字符串
 *         -  "text/html; charset=utf-8" ：HTML 文件（.html 或 .htm）
 *         -  "text/css"                 ：CSS 样式表（.css）
 *         -  "image/jpeg"               ：JPEG 图片（.jpg 或 .jpeg）
 *         -  "application/octet-stream" ：默认值，表示未知或二进制数据
 */
static inline const char *http_get_mime_type(const char *file_path) {
    if (strstr(file_path, ".html") || strstr(file_path, ".htm")) {
        return "text/html; charset=utf-8";
    } else if (strstr(file_path, ".css")) {
        return "text/css";
    } else if (strstr(file_path, ".jpg") || strstr(file_path, ".jpeg")) {
        return "image/jpeg";
    }
    return "application/octet-stream";  // 默认类型
}

/**
 * @brief 响应函数
 *
 * @param tcp_conn  指向当前 TCP 连接的指针
 * @param url_path  资源文件路径
 * @param port      本连接端口
 * @param dst_ip    目标 IP 地址
 * @param dst_port  目标端口
 */
void http_respond(tcp_conn_t *tcp_conn, char *url_path, uint16_t port, uint8_t *dst_ip, uint16_t dst_port) {
    FILE *file;
    char file_path[HTTP_MAX_PATH_LENGTH];
    memcpy(file_path, HTTP_RESOURCE_DIR, sizeof(HTTP_RESOURCE_DIR));

    // 获取文件路径，打开文件
    if (strcmp(url_path, "/") == 0) {  // 如果路径为 "/", 则默认打开 index.html
        strcat(file_path, "/index.html");
    } else {
        strcat(file_path, url_path);  // 否则，文件路径为 "${HTTP_RESOURCE_DIR}${url_path}"
    }
    // 打开文件
    file = fopen(file_path, "rb");

    char resp_buffer[HTTP_MAX_RESPONSE_LENGTH] = {0};

    // 文件不存在时发送 404 响应
    if (!file) {
        // HTTP 404 响应请求体
        char *not_found_body = "<HTML><TITLE>Not Found</TITLE>\r\n"
                               "The resource specified\r\n"
                               "is unavailable or nonexistent.\r\n"
                               "</BODY></HTML>\r\n";
        /* Step1 ：发送 HTTP 404 请求头 */
        // TODO: 发送 HTTP 状态行
        sprintf(resp_buffer, "HTTP/1.1 404 NOT FOUND\r\n");
        tcp_send(tcp_conn, (uint8_t *)resp_buffer, strlen(resp_buffer), port, dst_ip, dst_port);
        // 发送 HTTP 连接信息
        sprintf(resp_buffer, "Connection: Keep-Alive\r\n");
        tcp_send(tcp_conn, (uint8_t *)resp_buffer, strlen(resp_buffer), port, dst_ip, dst_port);
        // TODO: 发送 HTTP 内容类型
        sprintf(resp_buffer, "Content-Type: text/html\r\n");
        tcp_send(tcp_conn, (uint8_t *)resp_buffer, strlen(resp_buffer), port, dst_ip, dst_port);
        // TODO: 发送 HTTP 内容长度
        sprintf(resp_buffer, "Content-Length: %lu\r\n", strlen(not_found_body));
        tcp_send(tcp_conn, (uint8_t *)resp_buffer, strlen(resp_buffer), port, dst_ip, dst_port);
        // TODO: 发送 HTTP 响应头与响应体的分隔符
        sprintf(resp_buffer, "\r\n");
        tcp_send(tcp_conn, (uint8_t *)resp_buffer, strlen(resp_buffer), port, dst_ip, dst_port);
        // TODO: 发送 HTTP 响应体
        tcp_send(tcp_conn, (uint8_t *)not_found_body, strlen(not_found_body), port, dst_ip, dst_port);
        return;
    }

    /* Step2 ：发送 HTTP 请求头 */
    // TODO: 发送 HTTP 状态行
    sprintf(resp_buffer, "HTTP/1.1 20 OK\r\n");
        tcp_send(tcp_conn, (uint8_t *)resp_buffer, strlen(resp_buffer), port, dst_ip, dst_port);
    // 发送 HTTP 连接信息
    sprintf(resp_buffer, "Connection: Keep-Alive\r\n");
    tcp_send(tcp_conn, (uint8_t *)resp_buffer, strlen(resp_buffer), port, dst_ip, dst_port);

    const char *content_type = http_get_mime_type(file_path);
    // TODO: 发送 HTTP 内容类型，根据文件类型设置 MIME 类型
    sprintf(resp_buffer, "Content-Type: %s\r\n", content_type);
    tcp_send(tcp_conn, (uint8_t *)resp_buffer, strlen(resp_buffer), port, dst_ip, dst_port);

    fseek(file, 0, SEEK_END);
    size_t content_length = ftell(file);
    fseek(file, 0, SEEK_SET);
    // TODO: 发送 HTTP 内容长度
    sprintf(resp_buffer, "Content-Length: %lu\r\n", content_length);
    tcp_send(tcp_conn, (uint8_t *)resp_buffer, strlen(resp_buffer), port, dst_ip, dst_port);
    // TODO: 发送 HTTP 响应头与响应体的分隔符
    sprintf(resp_buffer, "\r\n");
    tcp_send(tcp_conn, (uint8_t *)resp_buffer, strlen(resp_buffer), port, dst_ip, dst_port);

    /* Step3 ：发送 HTTP 响应体 */
    size_t bytes_read;
    while ((bytes_read = fread(resp_buffer, 1, sizeof(resp_buffer), file)) > 0) {
        // TODO: 每次发送读取的文件内容块
        tcp_send(tcp_conn, (uint8_t *)resp_buffer, bytes_read, port, dst_ip, dst_port);
    }

    // 后处理: 关闭文件
    fclose(file);
}

void http_request_handler(tcp_conn_t *tcp_conn, uint8_t *data, size_t len, uint8_t *src_ip, uint16_t src_port) {
    char method[4];
    char url_path[HTTP_MAX_PATH_LENGTH];

    // 提取 HTTP 方法。目前仅支持 "GET" 请求
    if (sscanf((char *)data, "%3s", method) != 1 || strcmp(method, "GET") != 0)
        return;

    // 获取请求 URL
    int idx = 0;
    int j = 0;
    while (data[idx] != ' ')
        ++idx;
    ++idx;
    while (data[idx] != ' ') {
        url_path[j++] = data[idx++];
    }
    url_path[j] = '\0';

    // 发送响应
    http_respond(tcp_conn, url_path, HTTP_LISTEN_PORT, src_ip, src_port);
}

int main(int argc, char const *argv[]) {
    if (net_init() == -1) {  // 初始化协议栈
        printf("net init failed.");
        return -1;
    }

    tcp_open(HTTP_LISTEN_PORT, http_request_handler);  // 注册端口的tcp监听回调

    while (1) {
        net_poll();  // 一次主循环
    }

    return 0;
}
