#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}
#define ETHER_ADDR_LEN 6
void print_mac(uint8_t *m){
	printf("%02x:%02x:%02x:%02x:%02x:%02x",m[0],m[1],m[2],m[3],m[4],m[5]);
}

void print_dst(uint8_t *m){
	printf("%d.%d.%d.%d",m[24],m[25],m[26],m[27]);
}

void print_src(uint8_t *m){
	printf("%d.%d.%d.%d",m[20],m[21],m[22],m[23]);
}

int set_tcp_start(uint8_t *m){
	//printf("%02x",m[14]);
	uint8_t a = m[14]<<4;
	uint8_t b = a>>4;
	//printf("%02x\n",a);
	//printf("%02x\n",b);
	//printf("len : %d",b*4);
	return (int)b*4;
}

int set_tcp_len(int a, uint8_t *m){
	uint8_t b = m[a+26]>>4;
	//printf("tcp len : %d",m[a+26]*4);
	//printf(" %d\n",b*4);
	return (int)a + (int)b*4;
}

void print_src_port(uint8_t *m,int a){
	printf("%d",(m[a+14]<<8)|m[a+15]);
}


void print_dst_port(uint8_t *m,int a){
	printf("%d",(m[a+16]<<8)|m[a+17]);
	//printf("\n%02x %02x %02x %02x",m[a+16],m[a+17],m[a+18],m[a+19]);
}

void print_data(int a,uint8_t *m){
	int b = m[a+14];
	for(int x=0;x<10;x++){
		printf("%02x ",m[a+14+x]);
	}
	printf("\n");
	//printf("%02x",b);
	//printf("\n%02x %02x %02x %02x %02x %02x\n",m[a+15],m[a+16],m[a+17],m[a+18],m[a+19],m[a+20]);
}

struct libnet_ethernet_hdr

{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};


int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header; //all size
		const u_char* packet; //first header capture
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("=============================\n");
		printf("%u bytes captured\n", header->caplen);
		struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *)packet;
		printf("smac ");
		print_mac(eth_hdr -> ether_shost);
		printf("\n");
		
		printf("dmac ");
		print_mac(eth_hdr -> ether_dhost);
		printf("\n");
		
		if(ntohs(eth_hdr -> ether_type) != 0x0800) continue;
		printf("source ip : ");
		print_src(eth_hdr -> ether_shost);
		printf("\n");
		printf("destination ip : ");
		print_dst(eth_hdr -> ether_shost);
		printf("\n");
		
		printf("source port : ");
		print_src_port(eth_hdr -> ether_dhost,set_tcp_start(eth_hdr -> ether_dhost));
		printf("\ndestination port : ");
		print_dst_port(eth_hdr -> ether_dhost,set_tcp_start(eth_hdr -> ether_dhost));
		printf("\n");
		
		//printf("data start : ");
		int start_tcp = set_tcp_len(set_tcp_start(eth_hdr -> ether_dhost),eth_hdr -> ether_dhost);
		//printf("%d",set_tcp_len(set_tcp_start(eth_hdr -> ether_dhost),eth_hdr -> ether_dhost));
		//printf("%d\n",start_tcp);
		//print_data(eth_hdr -> ether_dhost,set_tcp_len(eth_hdr -> ether_dhost));
		printf("data : ");
		print_data(start_tcp, eth_hdr -> ether_dhost);
		printf("\n");
	}

	pcap_close(pcap);
}
