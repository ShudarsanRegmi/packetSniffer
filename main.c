#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <net/if.h>


#define BUFFSIZE 65536
#define MAX_IP_LENGTH 45 // Maximum length of IPv6 address is 45 characters
#define MY_APP_PORT 8080			


void get_interface_ip(struct sockaddr_in *localipptr, const char *interface);
void packet_capture(const char *interface, int len);
void display_ethernet_header(struct ethhdr *eth);
void display_ip_packet(struct iphdr *ip, struct sockaddr_in source, struct sockaddr_in dest);
void display_udp_header(struct udphdr *udp);
void display_tcp_header(struct tcphdr *tcp);
void display_udp_payload (unsigned char *data, int remaining_data );


// Function to get interface ip
void get_interface_ip(struct sockaddr_in *localipptr, const char *interface) {
    int n;
    struct ifreq ifr;
 
    n = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , interface , IFNAMSIZ - 1);
    ioctl(n, SIOCGIFADDR, &ifr);
    close(n);
	memcpy(localipptr, &ifr.ifr_addr, sizeof(struct sockaddr_in));
}

// function to display ethernet header
void display_ethernet_header(struct ethhdr *eth) {
	printf("\n-------ETHERNET HEADER--------------\n");
	printf("\t|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	printf("\t|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	printf("\t|-Protocol : %d\n", eth->h_proto);
}


void display_ip_packet(struct iphdr *ip,struct sockaddr_in source, struct sockaddr_in dest) {
	printf("\n-------IP HEADER--------------\n");
	source.sin_addr.s_addr = ip->saddr;	
	dest.sin_addr.s_addr = ip->daddr;	
	printf("\t|-Version: %d\n", (unsigned int)ip->version);
	printf("\t|-Internet Header Length : %d DWORDS or %d Bytes\n", (unsigned int)ip->ihl, ((unsigned int)(ip->ihl)) * 4);
	printf("\t|-Type of Service: %d\n", (unsigned int)ip->tos);
	printf("\t|-Total Length: %d\n", (unsigned int)ip->tos);
	printf("\t|-Total Length : %d Bytes\n", ntohs(ip->tot_len));
	printf("\t|-Identification : %d\n", ntohs(ip->id));
	printf("\t|-Time To Live : %d\n", (unsigned int)ip->ttl);
	printf("\t|-Protocol : %d\n", (unsigned int)ip->protocol);
	printf("\t|-Header Checksum : %d\n", ntohs(ip->check));
	printf("\t|-Source IP : %s\n", inet_ntoa(source.sin_addr));
	printf("\t|-Destination IP : %s\n", inet_ntoa(dest.sin_addr));
}


void display_tcp_header (struct tcphdr *tcp) {	
	printf("********************HERE WE GO-------------------------------\n");
	printf("\nTCP Header\n");
	printf("\t|-Source Port        : %u\n", ntohs(tcp->source));
	printf("\t|-Destination Port   : %u\n", ntohs(tcp->dest));
	printf("\t|-Sequence Number   : %u\n", ntohl(tcp->seq));
	printf("\t|-Acknowledge Number : %u\n", ntohl(tcp->ack_seq));
	printf("\t|-Header Length     : %d DWORDS or %d BYTES\n", (unsigned int)tcp->doff, (unsigned int)tcp->doff*4);
	printf("\t|----------Flags-----------\n");
	printf("\t\t|-Urgent Flag        : %d\n", (unsigned int)tcp->urg);
	printf("\t\t|-Acknowledgement Flag : %d\n", (unsigned int)tcp->ack);
	printf("\t\t|-Push Flag           : %d\n", (unsigned int)tcp->psh);
	printf("\t\t|-Reset Flag          : %d\n", (unsigned int)tcp->rst);
	printf("\t\t|-Synchronise Flag    : %d\n", (unsigned int)tcp->syn);
	printf("\t\t|-Finish Flag         : %d\n", (unsigned int)tcp->fin);
	printf("\t|-Window size        : %d\n", ntohs(tcp->window));
	printf("\t|-Checksum           : %d\n", ntohs(tcp->check));
	printf("\t|-Urgent Pointer     : %d\n", tcp->urg_ptr);
}

void display_tcp_payload (unsigned char *data, int remaining_data, int srcport, int dstport) {
	printf("TCP port = %d\n",srcport);
	printf("\n-------TCP PAYLOAD--------------\n");
	for(int i=0;i<remaining_data;i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf(" %.2X ", data[i]);
	}
}

void display_udp_header(struct udphdr *udp) {	
	printf("\n-------UDP HEADER--------------\n");
	printf("\t|-Source Port : %d\n", ntohs(udp->source));
	printf("\t|-Destination Port : %d\n", ntohs(udp->dest));
	printf("\t|-UDP Length : %d\n", ntohs(udp->len));
	printf("\t|-UDP Checksum : %d\n", ntohs(udp->check));
}


void display_udp_payload (unsigned char *data, int remaining_data ) {

	printf("\n-------UDP PAYLOAD--------------\n");
	for(int i=0;i<remaining_data;i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
    printf(" %.2X ", data[i]);
	
	}
}
void packet_capture(const char *interface, int len) {
	int sock;
	// creating a raw socket
	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if(sock == -1)
		perror("Failed to create a socket");
	

	// binding the interface to the socket
	if(setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface, len) == -1){
		fprintf(stderr, "Failed to select the chosen interface");
	}

	printf("Binding to the specific interface was successful..\n");

	// This buffer holds the captured packet
	unsigned char *buffer = (unsigned char*)malloc(BUFFSIZE);
	memset(buffer, 0, BUFFSIZE);

	// These strucutres are used to store the source and destination ip address extracted from the captured packet
	struct sockaddr saddr;
	struct sockaddr_in source, dest; // source and destination
	memset(&source, 0, sizeof(source));
	memset(&dest, 0, sizeof(dest));

	int saddr_len = sizeof(saddr);

	int buflen; 

	/* while(1) { */
		buflen = recvfrom(sock,buffer, BUFFSIZE, 0, &saddr, (socklen_t *)&saddr_len); // capturing the packet
		if(buflen == -1)
			perror("Failed to receive the packet: ");

		
		// packet dissection to get ethernet headers
		struct ethhdr *eth  = (struct ethhdr*)(buffer); // separating ethernet information from buffer

		unsigned short iphdrlen;
		//packet dissection to get ip header
		struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr)); // separting ip information from buffer
		unsigned int *ip_bytes = (unsigned int *)malloc(10*sizeof(unsigned int));

		iphdrlen = ip->ihl*4;

		int remaining_data;
		unsigned char *data;
	
		// In ip packet if the protocol value is 6 then it's a tcp packet
		if(ip->protocol == 6) {
			display_ethernet_header(eth);
			display_ip_packet(ip, source, dest);
			printf("\n*******************Displaying TCP headers*****************************************\n");
			struct tcphdr *tcp= (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));	
			display_tcp_header(tcp);
			data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
			remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
			printf("remaining data = %d\n", remaining_data);
			printf("data = %p\n",data);
			display_tcp_payload(data, remaining_data, ntohs(tcp->source), ntohs(tcp->dest));
		}

		// In ip packet if the value of protocol field is 17 then it's a udp packet
		else if(ip->protocol == 17) {
				display_ethernet_header(eth);
				display_ip_packet(ip, source, dest);
				printf("\n*******************Displayig UDP headers*****************************************\n");
				struct udphdr *udp=(struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));	
				data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
				remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
				display_udp_header(udp);
				display_udp_payload(data, remaining_data);

		}
		// displaying other lower level packets (arp,rarp,etc)
		else{
			printf("Displaying other packet details");
			display_ethernet_header(eth);
			display_ip_packet(ip, source, dest);
		}


		// clearing the buffer
		memset(buffer, 0, BUFFSIZE);
		close(sock);
		
	/* } */
}

int main() {
	// getting interface name
	const char *interface;
	interface = "wlp2s0"; // name of my wifi-interface
	int len = strnlen(interface, IFNAMSIZ);

	if (len == IFNAMSIZ) {
		fprintf(stderr, "Too long iface name");
		return -1;
	}
	
	struct sockaddr_in localip;
	get_interface_ip(&localip, interface);
	printf("IP address of interface %s is %s", interface, inet_ntoa(localip.sin_addr));

	packet_capture(interface, len);	 // calling packet capture from main
	return 0;
}

