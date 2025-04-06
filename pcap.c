#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth = (struct ether_header *)packet;
    struct ip *ip = (struct ip *)(packet + sizeof(struct ether_header));
    
    if (ip->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ip->ip_hl * 4));
        
        printf("Ethernet: Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
               eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
        printf("Ethernet: Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
               eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

        printf("IP: Src: %s\n", inet_ntoa(ip->ip_src));
        printf("IP: Dst: %s\n", inet_ntoa(ip->ip_dst));

        printf("TCP: Src Port: %d\n", ntohs(tcp->th_sport));
        printf("TCP: Dst Port: %d\n", ntohs(tcp->th_dport));

        int ip_header_len = ip->ip_hl * 4;
        int tcp_header_len = tcp->th_off * 4;
        const u_char *payload = packet + sizeof(struct ether_header) + ip_header_len + tcp_header_len;
        int payload_len = header->caplen - (sizeof(struct ether_header) + ip_header_len + tcp_header_len);

        printf("Message: ");
        for (int i = 0; i < payload_len && i < 32; i++) {
            if (isprint(payload[i])) putchar(payload[i]);
            else putchar('.');
        }
        printf("\n");
    }
} 

int main() {
	pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  
  // 1. pcap_open_live 함수로 NIC 열기
  handle = pcap_open_live("enp0s0", BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
	  fprintf(stderr, "Error!:%s\n", errbuf);
	  return 1;
  }
  
	// 2. TCP 대상으로만 필터 적용
	struct bpf_program fp;
  char filter_exp[] = "tcp"; //필터 문자열 선언
  bpf_u_int32 net;
  pcap_compile(handle, &fp, filter_exp, 0, net); 
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }
	
	// 3. 패킷 캡처 시작
	pcap_loop(handle, 0, got_packet, NULL);
	
	// 4. 종료
	pcap_close(handle);
	return 0;
}