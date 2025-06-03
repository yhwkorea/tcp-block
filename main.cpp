#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include <cstring>
#include <iostream>
#include <fstream>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <netinet/in.h>

using namespace std;

const string REDIRECT_MSG = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";

void usage() {
    cout << "syntax : tcp-block <interface> <pattern>\n";
    cout << "sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n";
}


uint16_t checksum(uint16_t* buf, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1)
        sum += *(uint8_t*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

void send_rst(const struct ip* ip_hdr, const struct tcphdr* tcp_hdr) {
    char packet[1500] = {0};
    struct ip* iph = (struct ip*)packet;
    struct tcphdr* tcph = (struct tcphdr*)(packet + sizeof(struct ip));

    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
    iph->ip_id = htons(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_src = ip_hdr->ip_src;
    iph->ip_dst = ip_hdr->ip_dst;
    iph->ip_sum = 0;
    iph->ip_sum = checksum((uint16_t*)iph, sizeof(struct ip));

    tcph->th_sport = tcp_hdr->th_sport;
    tcph->th_dport = tcp_hdr->th_dport;
    tcph->th_seq = tcp_hdr->th_ack;
    tcph->th_off = 5;
    tcph->th_flags = TH_RST | TH_ACK;
    tcph->th_win = htons(65535);
    tcph->th_sum = 0;

    struct {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t len;
    } pseudo_header;

    pseudo_header.src = iph->ip_src.s_addr;
    pseudo_header.dst = iph->ip_dst.s_addr;
    pseudo_header.zero = 0;
    pseudo_header.proto = IPPROTO_TCP;
    pseudo_header.len = htons(sizeof(struct tcphdr));

    char temp[1500];
    memcpy(temp, &pseudo_header, sizeof(pseudo_header));
    memcpy(temp + sizeof(pseudo_header), tcph, sizeof(struct tcphdr));
    tcph->th_sum = checksum((uint16_t*)temp, sizeof(pseudo_header) + sizeof(struct tcphdr));

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    const int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr = iph->ip_dst;

    sendto(sock, packet, sizeof(struct ip) + sizeof(struct tcphdr), 0,
           (struct sockaddr*)&dst, sizeof(dst));
    close(sock);
}

void send_fin_with_payload(const struct ip* ip_hdr, const struct tcphdr* tcp_hdr) {
    char packet[1500] = {0};
    int payload_len = REDIRECT_MSG.size();

    struct ip* iph = (struct ip*)packet;
    struct tcphdr* tcph = (struct tcphdr*)(packet + sizeof(struct ip));
    char* payload = packet + sizeof(struct ip) + sizeof(struct tcphdr);
    memcpy(payload, REDIRECT_MSG.c_str(), payload_len);

    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + payload_len);
    iph->ip_id = htons(12345);
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_src = ip_hdr->ip_dst;
    iph->ip_dst = ip_hdr->ip_src;
    iph->ip_sum = 0;
    iph->ip_sum = checksum((uint16_t*)iph, sizeof(struct ip));

    tcph->th_sport = tcp_hdr->th_dport;
    tcph->th_dport = tcp_hdr->th_sport;
    tcph->th_seq = tcp_hdr->th_ack;
    tcph->th_ack = tcp_hdr->th_seq;
    tcph->th_off = 5;
    tcph->th_flags = TH_FIN | TH_ACK;
    tcph->th_win = htons(65535);
    tcph->th_sum = 0;

    struct {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t len;
    } pseudo_header;

    pseudo_header.src = iph->ip_src.s_addr;
    pseudo_header.dst = iph->ip_dst.s_addr;
    pseudo_header.zero = 0;
    pseudo_header.proto = IPPROTO_TCP;
    pseudo_header.len = htons(sizeof(struct tcphdr) + payload_len);

    char temp[1500];
    memcpy(temp, &pseudo_header, sizeof(pseudo_header));
    memcpy(temp + sizeof(pseudo_header), tcph, sizeof(struct tcphdr) + payload_len);
    tcph->th_sum = checksum((uint16_t*)temp, sizeof(pseudo_header) + sizeof(struct tcphdr) + payload_len);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    const int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr = iph->ip_dst;

    sendto(sock, packet, sizeof(struct ip) + sizeof(struct tcphdr) + payload_len, 0,
           (struct sockaddr*)&dst, sizeof(dst));
    close(sock);
}

bool check_pattern(const u_char* packet, const string& pattern) {
    struct ip* ip_hdr = (struct ip*)(packet + 14);
    if (ip_hdr->ip_p != IPPROTO_TCP) return false;

    int ip_len = ip_hdr->ip_hl * 4;
    struct tcphdr* tcp_hdr = (struct tcphdr*)((u_char*)ip_hdr + ip_len);
    int tcp_len = tcp_hdr->th_off * 4;
    int data_offset = 14 + ip_len + tcp_len;

    const char* data = (const char*)packet + data_offset;
    int data_len = ntohs(ip_hdr->ip_len) - ip_len - tcp_len;

    if (data_len <= 0) return false;

    string payload(data, data_len);
    return payload.find(pattern) != string::npos;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        cerr << "couldn't open device " << dev << " (" << errbuf << ")\n";
        return -1;
    }

    string pattern = argv[2];
    struct pcap_pkthdr* header;
    const u_char* packet;

    while (true) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) break;

        if (check_pattern(packet, pattern)) {
            struct ip* ip_hdr = (struct ip*)(packet + 14);
            struct tcphdr* tcp_hdr = (struct tcphdr*)((u_char*)ip_hdr + ip_hdr->ip_hl * 4);

            send_rst(ip_hdr, tcp_hdr);
            send_fin_with_payload(ip_hdr, tcp_hdr);
            cout << "[+] Blocked!\n";
        }
    }

    pcap_close(handle);
    return 0;
}
