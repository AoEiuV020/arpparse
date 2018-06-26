//
// Created by AoEiuV020 on 2018.06.25-11:26:47.
//

#ifndef ARPPARSE_LOG_H
#define ARPPARSE_LOG_H

#include <pcap.h>
#include "arp.h"

void log(FILE *logFile, const unsigned char *buf, struct pcap_pkthdr packet);

#endif //ARPPARSE_LOG_H
