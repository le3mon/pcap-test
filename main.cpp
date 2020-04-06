#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <string.h>
#include <stdlib.h>
#include <algorithm>

#define MAC_LEN 6
#define IP_LEN 4
using namespace std;

#pragma pack(push, 1)
typedef struct _type_ethernet{
    uint8_t dst_mac[MAC_LEN];
    uint8_t src_mac[MAC_LEN];
    uint16_t type;
} type_ethernet;

typedef struct _type_ip{
    uint8_t h_len:4;
    uint8_t ver:4;
    uint8_t tos;
    uint16_t total_len;
    uint16_t idneti;
    uint8_t off:5;
    uint8_t flag:3;
    uint8_t off_2;
    uint8_t ttl;
    uint8_t proto;
    uint16_t checksum;
    uint8_t src_ip[IP_LEN];
    uint8_t dst_ip[IP_LEN];
}type_ip;

typedef struct _type_tcp{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t flag:4;
    uint8_t h_len:4;
    uint8_t flag_2;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
}type_tcp;
#pragma pack(pop)

void cmbn_dst_src(uint8_t *tmp,uint8_t *src, uint8_t *dst, size_t len){
    memcpy(tmp,src,len);
    memcpy(tmp+len,dst,len);
}

void print_mac(uint8_t *src, uint8_t *dst){
    uint8_t tmp[MAC_LEN*2]={0,};
    cmbn_dst_src(tmp,src,dst,MAC_LEN);
    int j=0;
    for (int i=1;i<=2;i++){
        if (i==1)
            printf("Source MAC : ");
        if (i==2)
            printf("Destination MAC : ");
        for (;j<MAC_LEN*i;j++) {
            if (j == MAC_LEN*i-1){
                printf("%02x\n", tmp[j]);
            }
            else{
                printf("%02x:", tmp[j]);
            }
        }
        j=MAC_LEN;
    }
}
void print_ip(uint8_t *src, uint8_t *dst){
    uint8_t tmp[IP_LEN*2]={0,};
    int j=0;
    cmbn_dst_src(tmp,src,dst,IP_LEN);
    for (int i=1;i<=2;i++){
        if (i==1)
            printf("Source IP : ");
        if (i==2)
            printf("Destination IP : ");
        for (;j<IP_LEN*i;j++) {
            if (j == IP_LEN*i-1){
                printf("%d\n", tmp[j]);
            }
            else{
                printf("%d.", tmp[j]);
            }
        }
        j=IP_LEN;
    }
}

void print_port(uint16_t src, uint16_t dst){
    printf("Source port : %d\n", ntohs(src));
    printf("Destination port : %d\n", ntohs(dst));
}

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        type_ethernet *eth = reinterpret_cast<type_ethernet*>(const_cast<u_char*>(packet)); // use c++ style cast
        if(ntohs(eth->type) != ETHERTYPE_IP)
            continue;
        type_ip *iph = reinterpret_cast<type_ip*>(const_cast<u_char*>(packet+=sizeof (type_ethernet)));
        if(iph->proto != IPPROTO_TCP)
            continue;
        type_tcp *tcph = reinterpret_cast<type_tcp*>(const_cast<u_char*>(packet+=(iph->h_len*4)));
        print_mac(eth->src_mac, eth->dst_mac);
        print_ip(iph->src_ip,iph->dst_ip);
        print_port(tcph->src_port,tcph->dst_port);
        packet += (tcph->h_len*4);
        int data_len = ntohs(iph->total_len) - iph->h_len*4 - tcph->h_len*4;
        int print_len = min(data_len,16);
        for (int i=0;i<print_len;i++)
            printf("%02x ", packet[i]);
        printf("\n-------------------------------------------\n\n");
    }
    pcap_close(handle);
}
