#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

int ip_id=0;

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    // Step1 ：如果数据包的长度小于IP头部长度，丢弃不处理。
    if (buf->len < sizeof(ip_hdr_t))
    {
        return;
    }
    // Step2 ：接下来做报头检测，检查内容至少包括：IP头部的版本号是否是IPv4，
    //总长度字段小于或等于收到的包的长度等，如果不符合这些要求，则丢弃不处理。
    //IP版本不为IPv4，或者总长度字段大于接受到包的长度，就丢弃
    ip_hdr_t *hdr = (ip_hdr_t *)(buf->data);
    if(hdr->version!=IP_VERSION_4)
    {
        return;
    } 

    // Step3 ：先把IP头部的头部校验和字段用其他变量保存起来，接着将该头部校验和字段置0，
    //然后调用checksum16函数来计算头部校验和，如果与IP头部的首部校验和字段不一致，丢弃不处理，
    //如果一致，则再将该头部校验和字段恢复成原来的值。
    uint16_t hdr_checksum16_backup=(hdr->hdr_checksum16);
    hdr->hdr_checksum16=0;
    uint16_t my_hdr_checksum16=checksum16((uint16_t *)buf->data,sizeof(ip_hdr_t));
    if(my_hdr_checksum16==hdr_checksum16_backup)
    {
        hdr->hdr_checksum16=(hdr_checksum16_backup);
    }
    else
    {
        return;
    }
    // Step4 ：对比目的IP地址是否为本机的IP地址，如果不是，则丢弃不处理。
    if(memcmp(hdr->dst_ip,net_if_ip,NET_IP_LEN))
    {
        //若不是，则memcmp返回非0
        return;
    }
    // Step5 ：如果接收到的数据包的长度大于IP头部的总长度字段，则说明该数据包有填充字段，
    //可调用buf_remove_padding()函数去除填充字段。
    if(swap16(hdr->total_len16)<buf->len)
    {
        buf_remove_padding(buf,buf->len-swap16(hdr->total_len16));
    }
    // Step6 ：调用buf_remove_header()函数去掉IP报头。
    // Step7 ：调用net_in()函数向上层传递数据包。
    //如果是不能识别的协议类型，即调用icmp_unreachable()返回ICMP协议不可达信息。
    if(hdr->protocol!=NET_PROTOCOL_ICMP&&hdr->protocol!=NET_PROTOCOL_UDP)
    {
        icmp_unreachable(buf,hdr->src_ip,ICMP_CODE_PROTOCOL_UNREACH);
        return;
    }
    buf_remove_header(buf,sizeof(ip_hdr_t));
    net_in(buf,hdr->protocol,hdr->src_ip);
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
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // TO-DO
    // Step1 ：调用buf_add_header()增加IP数据报头部缓存空间。
    buf_add_header(buf,sizeof(ip_hdr_t));
    // Step2 ：填写IP数据报头部字段。
    ip_hdr_t *hdr = (ip_hdr_t *)(buf->data);
    // Step3 ：先把IP头部的首部校验和字段填0，再调用checksum16函数计算校验和，
    //然后把计算出来的校验和填入首部校验和字段。
    hdr->hdr_len=sizeof(ip_hdr_t)/IP_HDR_LEN_PER_BYTE;
    hdr->version=IP_VERSION_4;
    hdr->tos=0;
    hdr->total_len16=swap16(buf->len);
    hdr->id16=swap16(id);
    //uint16_t mf_data=(mf==1)?IP_MORE_FRAGMENT:0;
    hdr->flags_fragment16=swap16(mf+offset);
    hdr->ttl=IP_DEFALUT_TTL;
    hdr->protocol=protocol;
    memcpy(hdr->src_ip,net_if_ip,NET_IP_LEN);
    memcpy(hdr->dst_ip,ip,NET_IP_LEN);
    hdr->hdr_checksum16=0;
    uint16_t cksum=checksum16((uint16_t *)buf->data,sizeof(ip_hdr_t));
    hdr->hdr_checksum16=(cksum);
    // Step4 ：调用arp_out函数()将封装后的IP头部和数据发送出去。
    arp_out(buf,ip);

}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TO-DO
    // Step1 ：首先检查从上层传递下来的数据报包长是否大于IP协议最大负载包长
    //（1500字节（MTU） 减去IP首部长度）。
    // Step2 ：如果超过IP协议最大负载包长，则需要分片发送。
    //首先调用buf_init()初始化一个ip_buf,将数据报包长截断，
    //每个截断后的包长 = IP协议最大负载包长（1500字节 - IP首部长度），
    //调用ip_fragment_out()函数发送出去。
    //如果截断后最后的一个分片小于或等于IP协议最大负载包长，
    //调用buf_init()初始化一个ip_buf，大小等于该分片大小，再调用ip_fragment_out()函数发送出去。
    //注意，最后一个分片的MF = 0。
    //int id=0;
    size_t max_len=ETHERNET_MAX_TRANSPORT_UNIT-sizeof(ip_hdr_t);
    if(buf->len>max_len)
    {
        int frag_num=buf->len/max_len+1;
        //不是最后一个分片的分片的长度必定是最大长度
        for(int i=0;i<frag_num-1;i++)
        {
            buf_t ip_buf;
            buf_init(&ip_buf,max_len);
            int offset=i*max_len;
            memcpy(ip_buf.data,&(buf->data[offset]),max_len);
            ip_fragment_out(&ip_buf,ip,protocol,ip_id,offset/IP_HDR_OFFSET_PER_BYTE,IP_MORE_FRAGMENT);
        }       
        buf_t end_ip_buf;
        int end_offset=(frag_num-1)*max_len;
        int end_len=buf->len-end_offset;
        buf_init(&end_ip_buf,end_len);
        memcpy(end_ip_buf.data,&(buf->data[end_offset]),end_len);
        ip_fragment_out(&end_ip_buf,ip,protocol,ip_id,end_offset/IP_HDR_OFFSET_PER_BYTE,0);
        
    }
    // Step3 ：如果没有超过IP协议最大负载包长，则直接调用ip_fragment_out()函数发送出去。
    else
    {
        ip_fragment_out(buf,ip,protocol,ip_id,0,0);
    }
    ip_id+=1;
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}