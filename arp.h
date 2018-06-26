//
// Created by AoEiuV020 on 2018.06.25-11:50:47.
//

#ifndef ARPPARSE_ARP_H
#define ARPPARSE_ARP_H


#include <stdlib.h>
#include <arpa/inet.h>

struct Ether {
    u_char distMac[6];   // 目的mac,
    u_char sourMac[6];   // 源mac,
    u_int16_t type;      // 协议类型，
};

struct Ipv4 {
    u_int8_t version:4; // 版本，
    u_int8_t headerLength:4; // 首部长度，
    u_int8_t tos; // 服务类型，
    u_int16_t length; // 总长度，
    u_int16_t sign; // 标志，
    u_int8_t sign2:3; // 标志，
    u_int16_t offset:13; // 片位移，
    u_int8_t ttl; // 生存时间，
    u_int8_t protocol; // 协议，
    u_int16_t sum; // 校验和，
    struct in_addr sourIp; // 源ip,
    struct in_addr distIp; // 目的ip,
};

#endif //ARPPARSE_ARP_H
