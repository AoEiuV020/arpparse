/*
 * 遇到的问题，
 * 1. 打开网卡失败，报错显示You don't have permission to capture on that device (socket: Operation not permitted)，
 *    原因是权限不足，
 *    通过sudo得到root权限再运行解决问题，
 * 2. 将pcap_next的返回值为NULL作为退出循环的条件，结果意外跳出循环，
 *    原因是有过滤数据包时pcap_next的正常返回值可能为NULL，
 *    改成死循环，pcap_next返回NULL就continue跳过解决问题，
 * 3. 打印到屏幕上的正常，但是打印到日志文件里的内容有缺，
 *    原因是输出到文件的有块缓冲，没有马上输出，然而退出程序是通过ctrl-c强行停止程序，导致没来的及清空输出缓冲，
 *    每行打印后手动调用fflush清空缓冲解决问题，
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <time.h>
#include <arpa/inet.h>
#include <errno.h>

#define MAXBYTES2CAPTURE 2048
#define ARP_REQUEST     1
#define ARP_REPLY       2

typedef struct arphdr {
    u_int16_t htype;        //hardware type
    u_int16_t ptype;        //protocol type
    u_char hlen;            //hardware address length
    u_char plen;            //protocol address length
    u_int16_t oper;         //operation code
    u_char sha[6];          // 源mac，
    u_char spa[4];          // 源ip，
    u_char tha[6];          // 目标mac,
    u_char tpa[4];          // 目标ip,
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

void logArp(FILE *logFile, const arphdr_t *arpheader, struct pcap_pkthdr *pkthdr) {
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
    char timestr[30]; // 用于存时间的字符串，
    strftime(timestr, 30, "%Y-%m-%d %H:%M:%S", localtime(&(pkthdr->ts.tv_sec)));
    fprintf(logFile, "%s\n", timestr);
    // 刷新缓冲，否则强退时可能没有实际写入日志，
    fflush(logFile);
}

int main(int argc, char **argv) {
    int i = 0;
    bpf_u_int32 net = 0;
    bpf_u_int32 mask = 0;
    struct bpf_program filter; //  用于过滤arp包， 
    char errbuf[PCAP_ERRBUF_SIZE]; // 用于存错误信息的buffer,
    pcap_t *handle = NULL;   //  管理网卡，
    struct pcap_pkthdr pkthdr; //  包含时间， 
    const unsigned char *packet = NULL; //  原生数据字节， 
    const char *dev = NULL; //  要抓包的设备， 
    arphdr_t *arpheader = NULL; //  指向arp头， 
    FILE *logFile = NULL; //  日志文件，

    // 准备日志文件，
    char *logFilePath;
    if (argc != 2) {
        // 不带参数就不打印日志，
        logFilePath = "/dev/null";
    } else {
        // 第一个参数是日志文件路径，
        logFilePath = argv[1];
    }
    logFile = fopen(logFilePath, "w");
    if (logFile == NULL) {
        fprintf(stderr, "打开日志文件<%s>失败：%s\n", logFilePath, strerror(errno));
        exit(1);
    }

    // 准备存错误日志的buffer，
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    // 查询当前活动的网卡，抓这个网卡的包，
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "找不到网卡: %s\n", errbuf);
        exit(1);
    }

    // 打开网卡，准备开始抓包，
    handle = pcap_open_live(dev, MAXBYTES2CAPTURE, 0, 512, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "打开网卡<%s>失败: %s\n", dev, errbuf);
        exit(1);
    }

    // 找网卡的ip和掩码，也就是子网范围，用于过滤数据包，
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "获取网卡<%s>的子网掩码失败: %s\n", dev, errbuf);
        exit(1);
    }

    // 过滤，只处理这个网卡的arp包，
    pcap_compile(handle, &filter, "arp", 0, mask);
    pcap_setfilter(handle, &filter);

    // 死循环抓包，
    while (1) {
        // 如果是null就跳过，表示不是程序要的包，
        if ((packet = pcap_next(handle, &pkthdr)) == NULL) {
            continue;
        }

        arpheader = (struct arphdr *) (packet + 14); //  数据帧头部长度14,
        // 只处理ipv4的，
        if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800) {
            // 打印到屏幕，
            logArp(stdout, arpheader, &pkthdr);
            // 打印到日志文件，
            logArp(logFile, arpheader, &pkthdr);
        }
    }
    return 0;
}
