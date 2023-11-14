#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>


/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6]; /* destination host address */
    u_char  ether_shost[6]; /* source host address */
    u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl : 4, //IP header length
        iph_ver : 4; //IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag : 3, //Fragmentation flags
        iph_offset : 13; //Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};

void packet_handler(unsigned char* user, const struct pcap_pkthdr* pkthdr, const unsigned char* packet) {
    // Ethernet header 파싱
    struct ethheader* eth = (struct ethheader*)packet;
    printf("Ethernet Header:\n");
    printf("Source MAC: %s\n", ether_ntoa((struct ether_addr*)eth->ether_shost));
    printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr*)eth->ether_dhost));

    // IP header 파싱
    struct ipheader* ip = (struct ipheader*)(packet + sizeof(struct ethheader));
    printf("IP Header:\n");
    printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));

    // 패킷이 TCP인지 확인
    if (ip->iph_protocol == IPPROTO_TCP) {
        // TCP header 파싱
        struct tcpheader* tcp = (struct tcpheader*)(packet + sizeof(struct ethheader) + (ip->iph_ihl * 4));
        printf("TCP Header:\n");
        printf("Source Port: %d\n", ntohs(tcp->tcp_sport));
        printf("Destination Port: %d\n", ntohs(tcp->tcp_dport));

        // Message 출력
        int data_offset = sizeof(struct ethheader) + (ip->iph_ihl * 4) + (TH_OFF(tcp) * 4);
        int data_len = pkthdr->len - data_offset;
        int max_print_len = 32;  // Maximum length of the message to print
        int print_len = data_len < max_print_len ? data_len : max_print_len;

        printf("Message:\n");
        for (int i = 0; i < print_len; ++i) {
            printf("%02x ", packet[data_offset + i]);
        }
        printf("\n");
    }
    printf("\n");
}

int main()
{
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; // TCP 프로토콜로 설정
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name ens33
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        return -1;
    }

    // Step 3: Capture packets
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);   //Close the handle
    return 0;
}
