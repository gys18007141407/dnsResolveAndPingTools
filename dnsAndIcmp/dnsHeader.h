
#ifndef DNS_HEADER_H
#define DNS_HEADER_H

#include<cstddef>
#include<ctype.h>
#include<stdint.h>

/*
  +--+--+--+--+--+--+--+
  |      Header(头部)   |
  +--+--+--+--+--+--+--+
  |      Queries(问题)  |
  +--+--+--+--+--+--+--+
  |      Answer(回复)   |
  +--+--+--+--+--+--+--+
  |Authority(权威名称服务器)|
  +--+--+--+--+--+--+--+
  | Additional(附加信息)|
  +--+--+--+--+--+--+--+


        DNS Header
  0                                         31
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |   ID (报文标志)      |      FLAG          |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |   QDCOUNT(问题数量)  |   ANCOUNT(回复数量) |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |ASCOUNT(权威服务器数量)|   ARCOUNT(附加数量) |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+





EXAMPLE: Domain Name System (query)

    Transaction ID: 0x9ad0                              #事务ID
    Flags: 0x0000 Standard query                        #报文中的标志字段
        0... .... .... .... = Response: Message is a query
                                                        #QR字段, 值为0, 因为是一个请求包
        .000 0... .... .... = Opcode: Standard query (0)
                                                        #Opcode字段, 值为0, 因为是标准查询
        .... ..0. .... .... = Truncated: Message is not truncated
                                                        #TC字段
        .... ...0 .... .... = Recursion desired: Don't do query recursively 
                                                        #RD字段
        .... .... .0.. .... = Z: reserved (0)           #保留字段, 值为0
        .... .... ...0 .... = Non-authenticated data: Unacceptable   
                                                        #保留字段, 值为0
    Questions: 1                                        #问题计数, 这里有1个问题
    Answer RRs: 0                                       #回答资源记录数
    Authority RRs: 0                                    #权威名称服务器计数
    Additional RRs: 0                                   #附加资源记录数

    以上输出信息显示了 DNS 请求报文中基础结构部分中包含的字段以及对应的值。
    这里需要注意的是，在请求中 Questions 的值不可能为 0
    Answer RRs，Authority RRs，Additional RRs 的值都为 0，因为在请求中还没有响应的查询结果信息。这些信息在响应包中会有相应的值。


FLAGS:
    QR(1bit）：查询/响应的标志位，1为响应，0为查询
    opcode（4bit）：定义查询或响应的类型（0为标准的，1为反向的，2为服务器状态请求，3-15保留值）
    AA（1bit）：授权回答的标志位。该位在响应报文中有效，1表示域名服务器是权限服务器
    TC（1bit）：截断标志位。1表示响应已超过512字节并已被截断
    RD（1bit）：被请求报文设置，该位为1表示客户端希望得到递归回答，应答时使用相同的值返回。

    RA（1bit）：支持递归， 这个比特位在应答中设置或取消，用来代表服务器是否支持递归查询。
    zero（3bit）：保留字段。
    rcode（4bit）：返回码，表示响应的差错状态，通常为0和3，各取值含义如下：
        0 无差错
        1 报文格式差错(Format error)服务器不能理解的请求报文
        2 服务器失败（Server failure）因为服务器的原因导致没办法处理的请求
        3 名字错误（Name error） 只有对授权域名解析服务器有意义，指出解析的域名不存在
        4 没有实现（Not Implemented）域名服务器不支持的查询类型
        5 拒绝（Refused）服务器由于设置的策略据局给出应答
        6 - 15 保留值

Queries:
    问题部分指的是报文格式中查询问题区域（Queries）部分。该部分是用来显示 DNS 查询请求的问题，通常只有一个问题。该部分包含正在进行的查询信息，包含查询名（被查询主机名字）、查询类型、查询类。

    问题部分格式如图所示。
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                  查询问题                 |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |      查询类型        |       查询类        |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    该部分中每个字段含义如下：
    查询名：一般为要查询的域名，有时也会是 IP 地址，用于反向查询。
    查询类型：DNS 查询请求的资源类型。通常查询类型为 A 类型，表示由域名获取对应的 IP 地址。
    查询类：地址类型，通常为互联网地址，值为 1
*/

#define MAX_DOMAINNAME_LEN  255
#define DNS_PORT            53

#define DNS_TYPE_SIZE       2
#define DNS_CLASS_SIZE      2
#define DNS_TTL_SIZE        4
#define DNS_DATALEN_SIZE    2
#define DNS_TYPE_A          0x0001 //1 a host address
#define DNS_TYPE_CNAME      0x0005 //5 the canonical name for an alias

#define DNS_PACKET_MAX_SIZE (sizeof(CDNSHeader) + MAX_DOMAINNAME_LEN + DNS_TYPE_SIZE + DNS_CLASS_SIZE)

#define MAX_EPOLL_EVENT 128
#define EPOLL_TIME_OUT  (1000*2)

struct CDNSHeader{

    uint16_t ID; //
    uint16_t FLAGS; //
    uint16_t Questions; //
    uint16_t Answers; //
    uint16_t Authority_Domain_Servers; //
    uint16_t Addition_Records; //
};


#endif