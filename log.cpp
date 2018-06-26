//
// Created by AoEiuV020 on 2018.06.25-11:26:47.
//

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "log.h"


void logMac(FILE *logFile, const unsigned char *buf) {
    fprintf(logFile, "%02X", buf[0]);
    for (int i = 1; i < 6; ++i) {
        fprintf(logFile, ":%02X", buf[i]);
    }
}

void logIp(FILE *logFile, struct in_addr buf) {
    fprintf(logFile, inet_ntoa(buf));
}

void log(FILE *logFile, const unsigned char *buf, pcap_pkthdr packet) {
    Ether ether = ((Ether *) buf)[0];
    if (ether.type != (short) 0x0800) {
        fprintf(logFile, "%04X ", ether.type);
//        return;
    }
    Ipv4 ipv4 = ((Ipv4 *) buf + 14)[0];
    logIp(logFile, ipv4.sourIp);
    fprintf(logFile, " ");
    logMac(logFile, ether.sourMac);
    fprintf(logFile, " ");
    logIp(logFile, ipv4.distIp);
    fprintf(logFile, " ");
    logMac(logFile, ether.distMac);
    fprintf(logFile, " ");

    fprintf(logFile, "%s", ctime(&packet.ts.tv_sec));

/*
    MacPackArp arp = ((const MacPackArp *) pkt)[0];
    printf("type: ");
    binPrint(arp.type, 2);
    printf("\n");
    printf("from: ");
    binPrint(arp.sourAddr, 6);
    printf(",");
    ipPrint(arp.sourIPAddr);
    printf("\n");
    printf("to  : ");
    binPrint(arp.destAddr, 6);
    printf(",");
    ipPrint(arp.destIPAddr);
    printf("\n");
*/
}
