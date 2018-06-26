#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <time.h>
#include <arpa/inet.h>

#define MAXBYTES2CAPTURE 2048
#define ARP_REQUEST     1
#define ARP_REPLY       2

typedef struct arphdr {
    u_int16_t htype;        //hardware type
    u_int16_t ptype;        //protocol type
    u_char hlen;            //hardware address length
    u_char plen;            //protocol address length
    u_int16_t oper;         //operation code
    u_char sha[6];          //sendHardware address
    u_char spa[4];          //sender ip address
    u_char tha[6];          //target hardware address
    u_char tpa[4];          //target ip address
} arphdr_t;


void logMac(FILE *logFile, const unsigned char *buf) {
    fprintf(logFile, "%02X", buf[0]);
    for (int i = 1; i < 6; ++i) {
        fprintf(logFile, ":%02X", buf[i]);
    }
}

void logIp(FILE *logFile, const unsigned char *buf) {
    fprintf(logFile, "%3d", buf[0]);
    for (int i = 1; i < 4; ++i) {
        fprintf(logFile, ".%3d", buf[i]);
    }
}

void logIpAddr(FILE *logFile, struct in_addr buf) {
    fprintf(logFile, inet_ntoa(buf));
}


int main(int argc, char **argv) {
    int i = 0;
    bpf_u_int32 net = 0;
    bpf_u_int32 mask = 0;
    struct bpf_program filter; //  用于过滤arp包， 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;   //  管理网卡， 
    struct pcap_pkthdr pkthdr; //  包含时间， 
    const unsigned char *packet = NULL; //  原生数据字节， 
    const char *dev = NULL; //  要抓包的设备， 
    arphdr_t *arpheader = NULL; //  指向arp头， 
    FILE *logFile = stdout; //  日志文件，暂且直接打印，方便测试， 
//    dev = pcap_lookupdev(errbuf);
    if (argc != 2) {
        printf("USAGE: arpsniffer <interface>\n");
        exit(1);
    }
    // 暂且通过参数传入设备，方便测试，
    dev = argv[1];

    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    // 开始抓包，
    handle = pcap_open_live(argv[1], MAXBYTES2CAPTURE, 0, 512, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "打开网卡<%s>失败: %s\n", dev, errbuf);
        exit(1);
    }

    // look up device network addr and mask
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "获取网卡<%s>的子网掩码失败: %s\n", dev, errbuf);
        exit(1);
    }

    // 过滤，只处理arp包，
    pcap_compile(handle, &filter, "arp", 0, mask);

    pcap_setfilter(handle, &filter);

    // 死循环抓包，
    while (1) {
        if ((packet = pcap_next(handle, &pkthdr)) == NULL) {
            continue;
        }

        arpheader = (struct arphdr *) (packet + 14); //  数据帧头部长度14,
        // 只处理ipv4的，
        if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800) {
            logIp(logFile, arpheader->spa);
            fprintf(logFile, " ");
            logMac(logFile, arpheader->sha);
            fprintf(logFile, " ");
            logIp(logFile, arpheader->tpa);
            fprintf(logFile, " ");
            logMac(logFile, arpheader->tha);
            fprintf(logFile, " ");

            fprintf(logFile, "%s", (ntohs(arpheader->oper) == ARP_REQUEST) ? "请求" : "响应");
            fprintf(logFile, " ");
            fprintf(logFile, "%s", ctime(&pkthdr.ts.tv_sec));
        }
    }
    return 0;
}