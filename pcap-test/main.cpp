#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#define MAC_LEN 6
#define IP_LEN 4

#pragma pack(push, 1)
typedef struct _type_ethernet{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t type;
} type_ethernet;

typedef struct _type_ip{
    uint8_t ver:4;
    uint8_t h_len:4;
    uint8_t tos;
    uint16_t total_len;
    uint16_t idneti;
    uint8_t flag:3;
    uint16_t frg_off:13;
    uint8_t ttl;
    uint8_t proto;
    uint16_t checksum;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
}type_ip;

typedef struct _type_tcp{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t h_len:4;
    uint8_t rev:6;
    uint8_t flag:6;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
}type_tcp;
#pragma pack(pop)

void print_mac(uint8_t tmp[]){
    for (int i=0;i<MAC_LEN;i++) {
        if (i == MAC_LEN-1){
            printf("%02x\n", tmp[i]);
        }
        else{
            printf("%02x:", tmp[i]);
        }
    }
}

void print_ip(uint8_t tmp[]){
    for (int i=0;i<IP_LEN;i++) {
        if (i == IP_LEN-1){
            printf("%d\n", tmp[i]);
        }
        else{
            printf("%d.", tmp[i]);
        }
    }
}

void print_port(uint16_t src, uint16_t dst){
    printf("printf src : %d\n", ntohs(src));
    printf("printf dst : %d\n", ntohs(dst));
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
        printf("%u bytes captured\n", header->caplen);
        type_ethernet *eth = reinterpret_cast<type_ethernet*>(const_cast<u_char*>(packet)); // use c++ style cast
        printf("Source MAC : ");
        print_mac(eth->src_mac);
        printf("Destination MAC : ");
        print_mac(eth->dst_mac);
        if(ntohs(eth->type) == ETHERTYPE_IP){
            type_ip *iph = reinterpret_cast<type_ip*>(const_cast<u_char*>(packet+=sizeof (type_ethernet)));
            printf("Source IP : ");
            print_ip(iph->src_ip);
            printf("Destination IP : ");
            print_ip(iph->dst_ip);
            if(iph->proto == IPPROTO_TCP){
                type_tcp *tcph = reinterpret_cast<type_tcp*>(const_cast<u_char*>(packet+=iph->h_len));
                print_port(tcph->src_port,tcph->dst_port);
                if((iph->total_len - (iph->h_len + tcph->h_len)) < 0){
                    packet += tcph->h_len;
                    for (int i=0;i<16;i++) {
                        printf("%c", packet[i]);
                    }

                }
            }
        }
    }

    pcap_close(handle);
}
