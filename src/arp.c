#include <string.h>
#include <stdio.h>
#include "net.h"
#include "arp.h"
#include "ethernet.h"
#include <assert.h>
/**
 * @brief 初始的arp包
 *
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp)
{
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print()
{
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip)
{
    // TO-DO
    // Step1 ：调用buf_init()对txbuf进行初始化。
    buf_init(&txbuf, ETHERNET_MIN_TRANSPORT_UNIT);
    // Step2 ：填写ARP报头。
    // Step3 ：ARP操作类型为ARP_REQUEST，注意大小端转换。
    arp_pkt_t *hdr = (arp_pkt_t *)(txbuf.data);
    hdr->hw_type16 = swap16(ARP_HW_ETHER);
    hdr->pro_type16 = swap16(NET_PROTOCOL_IP);
    hdr->hw_len = NET_MAC_LEN;
    hdr->pro_len = NET_IP_LEN;
    hdr->opcode16 = swap16(ARP_REQUEST);
    memcpy(hdr->sender_mac, net_if_mac, NET_MAC_LEN);
    memcpy(hdr->sender_ip, net_if_ip, NET_IP_LEN);
    memset(hdr->target_mac, 0, NET_MAC_LEN);
    memcpy(hdr->target_ip, target_ip, NET_IP_LEN);
    // Step4 ：调用ethernet_out函数将ARP报文发送出去。
    // 注意：ARP announcement或ARP请求报文都是广播报文，
    // 其目标MAC地址应该是广播地址：FF-FF-FF-FF-FF-FF。
    ethernet_out(&txbuf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac)
{
    // TO-DO
    // Step1 ：首先调用buf_init()来初始化txbuf。
    buf_init(&txbuf, ETHERNET_MIN_TRANSPORT_UNIT);
    // Step2 ：接着，填写ARP报头首部。
    arp_pkt_t *hdr = (arp_pkt_t *)(txbuf.data);
    hdr->hw_type16 = swap16(ARP_HW_ETHER);
    hdr->pro_type16 = swap16(NET_PROTOCOL_IP);
    hdr->hw_len = NET_MAC_LEN;
    hdr->pro_len = NET_IP_LEN;
    hdr->opcode16 = swap16(ARP_REPLY);
    memcpy(hdr->sender_mac, net_if_mac, NET_MAC_LEN);
    memcpy(hdr->sender_ip, net_if_ip, NET_IP_LEN);
    memcpy(hdr->target_mac, target_mac, NET_MAC_LEN);
    memcpy(hdr->target_ip, target_ip, NET_IP_LEN);
    // Step3 ：调用ethernet_out()函数将填充好的ARP报文发送出去。
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    // Step1 ：首先判断数据长度，如果数据长度小于ARP头部长度，则认为数据包不完整，丢弃不处理。
    if (buf->len < sizeof(arp_pkt_t))
    {
        return;
    }
    // Step2 ：接着，做报头检查，查看报文是否完整，检测内容包括：
    // ARP报头的硬件类型、上层协议类型、MAC硬件地址长度、IP协议地址长度、操作类型，
    // 检测这些内存是否符合协议规定。
    arp_pkt_t *hdr = (arp_pkt_t *)(buf->data);
    int f = 0;
    f += !!(hdr->hw_type16 == swap16(ARP_HW_ETHER));
    f += !!(hdr->pro_type16 == swap16(NET_PROTOCOL_IP));
    f += !!(hdr->hw_len == NET_MAC_LEN);
    f += !!(hdr->pro_len == NET_IP_LEN);
    f += !!(hdr->opcode16 == swap16(ARP_REQUEST) || hdr->opcode16 == swap16(ARP_REPLY));
    if (f < 5)
    {
        return;
    }
    // Step3 ：调用map_set()函数更新ARP表项。
    map_set(&arp_table, hdr->sender_ip, hdr->sender_mac);
    // Step4 ：调用map_get()函数查看该接收报文的IP地址是否有对应的arp_buf缓存。
    buf_t *get_buf = map_get(&arp_buf, hdr->sender_ip);
    if (get_buf != NULL)
    {
        //调用ethernet_out()函数直接发给以太网层，接着调用map_delete()函数将这个缓存的数据包删除掉。
        ethernet_out(get_buf, hdr->sender_mac,NET_PROTOCOL_IP);
        map_delete(&arp_buf, hdr->sender_ip);
    }
    //判断接收到的报文是否为ARP_REQUEST请求报文，并且该请求报文的target_ip是本机的IP，
    //若是，则认为是请求本主机MAC地址的ARP请求报文，调用arp_resp()函数回应一个响应报文。
    else
    {
        if(hdr->opcode16 == swap16(ARP_REQUEST)&&!memcmp(hdr->target_ip,net_if_ip,NET_IP_LEN))
        {
            arp_resp(hdr->sender_ip,hdr->sender_mac);
        }
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip)
{
    // TO-DO
    // Step1 ：调用map_get()函数，根据IP地址来查找ARP表(arp_table)。
    uint8_t *mac = map_get(&arp_table, ip);
    // Step2 ：如果能找到该IP地址对应的MAC地址，则将数据包直接发送给以太网层，
    // 即调用ethernet_out函数直接发出去。
    if (mac != NULL)
    {
        ethernet_out(buf, mac, NET_PROTOCOL_IP);
    }
    // Step3 ：如果没有找到对应的MAC地址，进一步判断arp_buf是否已经有包了，
    // 如果有，则说明正在等待该ip回应ARP请求，此时不能再发送arp请求；
    // 如果没有包，则调用map_set()函数将来自IP层的数据包缓存到arp_buf，
    // 然后，调用arp_req()函数，发一个请求目标IP地址对应的MAC地址的ARP request报文。
    else
    {
        buf_t *get_buf = map_get(&arp_buf, ip);
        if (get_buf != NULL)
        {
            return;
        }
        else
        {
            map_set(&arp_buf, ip, buf);
            arp_req(ip);
        }
    }
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init()
{
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}