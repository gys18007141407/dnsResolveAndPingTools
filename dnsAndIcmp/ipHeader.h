
#ifndef IP_HEADER_H
#define IP_HEADER_H


#include <stdint.h>

#define DEF_PACKET_SIZE 32
#define ECHO_REQUEST 8
#define ECHO_REPLY 0

/*                       IP报文格式 
    0            8           16                        32 
    +------------+------------+-------------------------+ 
    | ver + hlen |  服务类型   |          总长度          | 
    +------------+------------+----+--------------------+ 
    |           标识位         |flag|    分片偏移(13位)   | 
    +------------+------------+----+--------------------+ 
    |   生存时间  | 高层协议号   |        首部校验和        | 
    +------------+------------+-------------------------+ 
    |                   源 IP 地址                       | 
    +---------------------------------------------------+ 
    |                  目的 IP 地址                      | 
    +---------------------------------------------------+ 
 
*/

struct CIPHeader{
    uint8_t versionAndHeaderLen; // 4位版本号和4位首部长度
    uint8_t serverType;
    uint16_t totalLen;
    uint16_t ID;
    uint16_t flagAndFragOffset;  // 3位标志和13位片偏移
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checkSum;
    uint32_t sourceIP;
    uint32_t targetIP;
};


#endif