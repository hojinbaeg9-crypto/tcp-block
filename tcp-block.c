#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h> //ntohs, struct in_addr 사용
#include <sys/socket.h> // socket
#include <netinet/in.h> // sockaddr_in 구조체, htons, htonl, IPPROTO_TCP
#include <net/ethernet.h> // ETH_P_ALL

#include <unistd.h> //close
#include <sys/ioctl.h> // get_mac_address와 get_ip_address 함수에서 ioctl 사용
#include <net/if.h> //if_nametoindex()
#include <netpacket/packet.h> //struct sockaddr_ll

#define _GNU_SOURCE //memmem 함수
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_ACK 0x10

struct ethernet_hdr
{
    uint8_t  dst[6];/* destination ethernet address */
    uint8_t  src[6];/* source ethernet address */
    uint16_t protocol;                 /* protocol */
};

struct ipv4_hdr
{
    //리틀 엔디안을 맞춰주기 위해 version과 ihl 순서 반대로
    uint8_t ihl : 4, version : 4;       
    uint8_t tos;       /* type of service */
    uint16_t tot_len;         /* total length */
    uint16_t id;          /* identification */
    uint16_t offset;
    uint8_t ttl;          /* time to live */
    uint8_t protocol;            /* protocol */
    uint16_t hdr_checksum;         /* checksum */
    uint32_t src_add; /* source address */
    uint32_t dst_add; /* dest address */
};

struct tcp_hdr
{
    uint16_t src_port;       /* source port */
    uint16_t dst_port;       /* destination port */
    uint32_t seq_num;          /* sequence number */
    uint32_t ack_num;          /* acknowledgement number */
	//리틀 엔디안을 맞춰주기 위해 reserved와 data_offset 순서 반대로
    uint8_t reserved : 4, data_offset : 4;        /* data offset */
    uint8_t  flags;       /* control flags */
    uint16_t window;         /* window */
    uint16_t checksum;         /* checksum */
    uint16_t urgent_p;         /* urgent pointer */
};

struct pseudo_hdr {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_len;
};

void usage() {
    printf("syntax: tcp-block <interface> <pattern>\n");
    printf("sample: tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

typedef struct {
    char* dev_;
} Param;

//전역변수 구조체 param의 선언과 param.dev를 NULL로 초기화 
Param param = {
        .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return false;
    }
    //param->dev(문자열)에 네트워크 인터페이스 넣음
    param->dev_ = argv[1];
    return true;
}

uint8_t my_mac[6];
uint32_t my_ip;
int raw_skt_fd = -1;

int get_mac_address(const char* if_name, uint8_t* mac_out) {
	struct ifreq ifr;
	int fd;

	// 1. 커널과 통신할 임시 소켓 오픈
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	// 2. 인터페이스 이름 복사 (버퍼 오버플로우 방지)
	strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);

	// 3. ioctl 호출: 하드웨어 주소(MAC) 요청
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl - SIOCGIFHWADDR");
		close(fd);
		return -1;
	}

	// 4. 결과 복사 (ifr_hwaddr.sa_data에 6바이트 MAC이 들어있음)
	memcpy(mac_out, ifr.ifr_hwaddr.sa_data, 6);

	close(fd);
	return 0;
}

int get_ip_address(const char* if_name, uint32_t* ip_out) {
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return -1;

	strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
		close(fd);
		return -1;
	}

	// 이미 네트워크 바이트 순서로 받아옴
	uint32_t ip = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;
	// 우리 로직(Host Order 저장 후 htonl 호출)에 맞추기 위해 ntohl 적용
	*ip_out = ntohl(ip);

	close(fd);
	return 0;
}

uint16_t checksum(uint16_t* buf, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf;
        buf++;
        len -= 2;
    }

    if (len == 1) 
        sum += *(uint8_t*)buf;

    while (sum >> 16) 
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)(~sum);
}

void backward_pass(int skt_fd, const uint8_t* org_packet, uint32_t org_data_len, uint32_t org_ip_header_len, uint32_t org_tcp_header_len) {
    uint8_t packet[1500];
    memcpy(packet, org_packet + sizeof(struct ethernet_hdr), org_ip_header_len + org_tcp_header_len);

    struct ipv4_hdr* ip = (struct ipv4_hdr*)packet;
    struct tcp_hdr* tcp = (struct tcp_hdr*)(packet + org_ip_header_len);

    tcp->data_offset = 5; 
    uint8_t fixed_tcp_header_len = 20;

    char warning[] = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";
    ip->tot_len = htons(org_ip_header_len + fixed_tcp_header_len + strlen(warning));
    ip->ttl = 128;
    uint32_t tmp_add = ip->src_add;
    ip->src_add = ip->dst_add;
    ip->dst_add = tmp_add;

    uint16_t tmp_port = tcp->src_port;
    tcp->src_port = tcp->dst_port;
    tcp->dst_port = tmp_port;

    uint32_t current_ack = ntohl(tcp->ack_num);
    uint32_t current_seq = ntohl(tcp->seq_num);
    uint32_t next_ack = current_seq + org_data_len; 
    tcp->seq_num = htonl(current_ack);    // 서버가 보내야 할 Seq
    tcp->ack_num = htonl(next_ack);       // 서버가 보내야 할 Ack

    tcp->flags = TH_ACK | TH_FIN;
    // TCP Payload로 warning 메시지 삽입
    memcpy(packet + org_ip_header_len + fixed_tcp_header_len, warning, strlen(warning));
    // ip checksum 계산
    ip->hdr_checksum = 0;
    ip->hdr_checksum = checksum((uint16_t*)ip, org_ip_header_len);

    // tcp checksum 계산
    uint16_t tcp_len = fixed_tcp_header_len + strlen(warning);

    struct pseudo_hdr pseudo;
    pseudo.src_ip = ip->src_add;
    pseudo.dst_ip = ip->dst_add;
    pseudo.zero = 0;
    pseudo.protocol = ip->protocol;
    pseudo.tcp_len = htons(tcp_len);

    uint8_t buf[1500];
    memcpy(buf, &pseudo, sizeof(pseudo));
    tcp->checksum = 0;
    memcpy(buf + sizeof(pseudo), tcp, tcp_len);
    tcp->checksum = checksum((uint16_t*)buf, sizeof(pseudo) + tcp_len);

    // 패킷 전송
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip->dst_add;
    int packet_len = ntohs(ip->tot_len);
    if (sendto(skt_fd, packet, packet_len, 0, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("sendto");
        return;
    }
}

void forward_pass(pcap_t* pcap,const uint8_t* org_packet, uint32_t org_data_len, uint32_t org_ip_header_len, uint32_t org_tcp_header_len) {
    uint8_t packet[1500];
    memcpy(packet, org_packet, sizeof(struct ethernet_hdr) + org_ip_header_len + org_tcp_header_len);
    struct ethernet_hdr* ethernet = (struct ethernet_hdr*)packet;
    memcpy(ethernet->src, my_mac, 6);

    struct ipv4_hdr* ip = (struct ipv4_hdr*)(packet + sizeof(*ethernet));
    struct tcp_hdr* tcp = (struct tcp_hdr*)(packet + sizeof(*ethernet) + org_ip_header_len);

    tcp->data_offset = 5; 
    uint8_t fixed_tcp_header_len = 20;

    ip->tot_len = htons(org_ip_header_len + fixed_tcp_header_len);

    tcp->seq_num = htonl(ntohl(tcp->seq_num) + org_data_len);
    tcp->flags = TH_ACK | TH_RST;

    // ip checksum 계산
    ip->hdr_checksum = 0;
    ip->hdr_checksum = checksum((uint16_t*)ip, org_ip_header_len);

    // tcp checksum 계산
    uint16_t tcp_len = fixed_tcp_header_len;

    struct pseudo_hdr pseudo;
    pseudo.src_ip = ip->src_add;
    pseudo.dst_ip = ip->dst_add;
    pseudo.zero = 0;
    pseudo.protocol = ip->protocol;
    pseudo.tcp_len = htons(tcp_len);

    uint8_t buf[1500];
    memcpy(buf, &pseudo, sizeof(pseudo));
    tcp->checksum = 0;
    memcpy(buf + sizeof(pseudo), tcp, tcp_len);
    tcp->checksum = checksum((uint16_t*)buf, sizeof(pseudo) + tcp_len);

    // 패킷 전송
    pcap_sendpacket(pcap, packet, sizeof(struct ethernet_hdr) + org_ip_header_len + fixed_tcp_header_len);
    
}

int main(int argc, char* argv[]) {
    //인자 개수가 정상적이지 않으면 종료
    if (!parse(&param, argc, argv)) return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }
    get_mac_address(param.dev_, my_mac);
    get_ip_address(param.dev_, &my_ip);

    raw_skt_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one = 1;
    if (setsockopt(raw_skt_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == -1) {
        perror("setsockopt");
        close(raw_skt_fd);
        pcap_close(pcap);
        return -1;
    }
    while (true) {
        struct pcap_pkthdr* header; //패킷 메타 정보
        const uint8_t* packet;       //패킷의 시작주소?
        struct ethernet_hdr* ethernet;
        struct ipv4_hdr* ip;
        struct tcp_hdr* tcp;
        uint16_t data_len = 0;
		uint8_t ip_header_len = 0;
		uint8_t tcp_header_len = 0; 
		uint32_t src_ip, dst_ip;

        int res = pcap_next_ex(pcap, &header, &packet);

        if (res == 0) continue; //타임아웃이면 다시 시도
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        ethernet = (struct ethernet_hdr*)packet;
        if (ntohs(ethernet->protocol) != 0x0800) {
			//printf("Not an IPv4 packet\n");
            continue;
        } //IPv4 패킷이 아니면 다시 시도
        ip = (struct ipv4_hdr*)(packet + sizeof(*ethernet));
        //TCP 패킷이 아니면 다시 시도
        if (ip->protocol != 6) {
			//printf("Not a TCP packet\n");
            continue;
        }
		ip_header_len = (ip->ihl) << 2; 

        tcp = (struct tcp_hdr*)(packet + sizeof(*ethernet) + ip_header_len);
		tcp_header_len = (tcp->data_offset) << 2; 
        // http 패킷이 아니면 다시 시도
        if(ntohs(tcp->src_port) != 80 && ntohs(tcp->dst_port) != 80) {
            //80은 HTTP의 기본 포트 번호
            //printf("Not an HTTP packet\n");
            continue;
        }
        //데이터 길이 계산
		data_len = ntohs(ip->tot_len) - ip_header_len - tcp_header_len;
        if(data_len <= 0) continue;

        //캡쳐한 길이가 ethernet header + ip header + tcp header보다 작으면 다시 시도
        if (header->caplen < sizeof(*ethernet) + ip_header_len + tcp_header_len) {
			//printf("Captured length is less than the sum of Ethernet, IP, and TCP headers\n");
            continue;
        }

        char* pattern = argv[2];
        char* payload = (char*)(packet + sizeof(*ethernet) + ip_header_len + tcp_header_len);
          
        if (memmem(payload, data_len, pattern, strlen(pattern)) != NULL) {
            printf("\nPattern found: %s\n", pattern);  
            backward_pass(raw_skt_fd, packet, data_len, ip_header_len, tcp_header_len);  
            forward_pass(pcap, packet, data_len, ip_header_len, tcp_header_len); 
        }

    }
    close(raw_skt_fd);
    pcap_close(pcap);
    return 0;
}
