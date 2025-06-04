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

void send_packet(const char* packet, int size, const in_addr& dst_ip) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket");
        return;
    }
    const int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr = dst_ip;

    if (sendto(sock, packet, size, 0, (sockaddr*)&dst, sizeof(dst)) < 0)
        perror("sendto");
    else
        cout << "[+] Packet sent (size: " << size << ")\n";

    close(sock);
}

void send_rst(const ip* ip_hdr, const tcphdr* tcp_hdr) {
    char packet[1500] = {0};
    ip* iph = (ip*)packet;
    tcphdr* tcph = (tcphdr*)(packet + sizeof(ip));

    *iph = *ip_hdr;
    iph->ip_len = htons(sizeof(ip) + sizeof(tcphdr));
    iph->ip_ttl = 64;
    iph->ip_sum = 0;
    iph->ip_sum = checksum((uint16_t*)iph, sizeof(ip));

    *tcph = *tcp_hdr;
    tcph->th_seq = tcp_hdr->th_ack;
    tcph->th_flags = TH_RST | TH_ACK;
    tcph->th_sum = 0;

    struct {
        uint32_t src, dst;
        uint8_t zero, proto;
        uint16_t len;
    } pseudo = {iph->ip_src.s_addr, iph->ip_dst.s_addr, 0, IPPROTO_TCP, htons(sizeof(tcphdr))};

    char temp[1500];
    memcpy(temp, &pseudo, sizeof(pseudo));
    memcpy(temp + sizeof(pseudo), tcph, sizeof(tcphdr));
    tcph->th_sum = checksum((uint16_t*)temp, sizeof(pseudo) + sizeof(tcphdr));

    send_packet(packet, sizeof(ip) + sizeof(tcphdr), iph->ip_dst);
}

void send_fin_with_payload(const ip* ip_hdr, const tcphdr* tcp_hdr, int data_len) {
    char packet[1500] = {0};
    int payload_len = REDIRECT_MSG.size();
    ip* iph = (ip*)packet;
    tcphdr* tcph = (tcphdr*)(packet + sizeof(ip));
    char* payload = packet + sizeof(ip) + sizeof(tcphdr);
    memcpy(payload, REDIRECT_MSG.c_str(), payload_len);

    iph->ip_v = 4;
    iph->ip_hl = 5;
    iph->ip_ttl = 128;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_src = ip_hdr->ip_dst;
    iph->ip_dst = ip_hdr->ip_src;
    iph->ip_len = htons(sizeof(ip) + sizeof(tcphdr) + payload_len);
    iph->ip_sum = 0;
    iph->ip_sum = checksum((uint16_t*)iph, sizeof(ip));

    tcph->th_sport = tcp_hdr->th_dport;
    tcph->th_dport = tcp_hdr->th_sport;
    tcph->th_seq = tcp_hdr->th_ack;
    tcph->th_ack = htonl(ntohl(tcp_hdr->th_seq) + data_len);
    tcph->th_off = 5;
    tcph->th_flags = TH_FIN | TH_ACK;
    tcph->th_win = htons(65535);
    tcph->th_sum = 0;

    struct {
        uint32_t src, dst;
        uint8_t zero, proto;
        uint16_t len;
    } pseudo = {iph->ip_src.s_addr, iph->ip_dst.s_addr, 0, IPPROTO_TCP, htons(sizeof(tcphdr) + payload_len)};

    char temp[1500];
    memcpy(temp, &pseudo, sizeof(pseudo));
    memcpy(temp + sizeof(pseudo), tcph, sizeof(tcphdr) + payload_len);
    tcph->th_sum = checksum((uint16_t*)temp, sizeof(pseudo) + sizeof(tcphdr) + payload_len);

    send_packet(packet, sizeof(ip) + sizeof(tcphdr) + payload_len, iph->ip_dst);
}

bool check_pattern(const u_char* packet, const string& pattern, int& data_len) {
    const ip* ip_hdr = (ip*)(packet + 14);
    if (ip_hdr->ip_p != IPPROTO_TCP) return false;
    int ip_len = ip_hdr->ip_hl * 4;
    const tcphdr* tcp_hdr = (tcphdr*)((u_char*)ip_hdr + ip_len);
    int tcp_len = tcp_hdr->th_off * 4;
    int offset = 14 + ip_len + tcp_len;

    data_len = ntohs(ip_hdr->ip_len) - ip_len - tcp_len;
    if (data_len <= 0) return false;

    string payload((char*)packet + offset, data_len);
    return payload.find(pattern) != string::npos;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage(); return -1;
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
        if (res <= 0) continue;
        int data_len = 0;
        if (check_pattern(packet, pattern, data_len)) {
            const ip* ip_hdr = (ip*)(packet + 14);
            const tcphdr* tcp_hdr = (tcphdr*)((u_char*)ip_hdr + ip_hdr->ip_hl * 4);
            send_fin_with_payload(ip_hdr, tcp_hdr, data_len);
            usleep(1000); // 1ms 대기
            send_rst(ip_hdr, tcp_hdr);
            cout << "[+] Blocked!" << endl;
        }
    }
    pcap_close(handle);
    return 0;
}
