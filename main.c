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

struct ip_filter {
	/*PROTOCOL*/
	int use_status; /*0 --> not being used, 1 --> source_filter is being used, 2--> dest_filter_is_being_used, 4-> both is being used*/
	// 4th filter is not implemented in this version
	struct sockaddr_in source_filter;
	struct sockaddr_in dest_filter;
};


void get_interface_ip(struct sockaddr_in *localipptr, const char *interface);
void packet_capture(const char *interface, int len, int command, struct ip_filter *myfilterptr);
void display_ethernet_header(struct ethhdr *eth);
void display_ip_packet(struct iphdr *ip, struct sockaddr_in source, struct sockaddr_in dest);
void display_udp_header(struct udphdr *udp);
void display_tcp_header(struct tcphdr *tcp);
void display_udp_payload (unsigned char *data, int remaining_data );
void display_tcp_packet_thumbnail(struct ethhdr *eth, struct iphdr *ip, struct tcphdr *tcp,  struct sockaddr_in source, struct sockaddr_in dest);
void display_udp_packet_thumbnail(struct ethhdr *eth, struct iphdr *ip, struct udphdr *udp, struct sockaddr_in source, struct sockaddr_in dest);


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

void display_tcp_packet_thumbnail(struct ethhdr *eth, struct iphdr *ip, struct tcphdr *tcp,  struct sockaddr_in source, struct sockaddr_in dest)  {
	printf("\n#####DISPLAYING TCP PACKET THUMBNAIL#####");
	source.sin_addr.s_addr = ip->saddr;	
	dest.sin_addr.s_addr = ip->daddr;	
	// for low level protocols which is not using ip it will show 0
	printf("\n [[ TCP Packet :: ipv%d Source: %s :: ", (unsigned int)ip->version, inet_ntoa(source.sin_addr));
	printf("Dest: %s ]]",inet_ntoa(dest.sin_addr));
	/* printf("\n[[ TCP Packet :: ipv%d :: Source: %s :: Dest: %s ]]\n", (unsigned int)ip->version, inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr)); */
}

void display_udp_packet_thumbnail(struct ethhdr *eth, struct iphdr *ip, struct udphdr *udp, struct sockaddr_in source, struct sockaddr_in dest) {
	printf("\n#####DISPLAYING UDP PACKET THUMBNAIL#####");
	source.sin_addr.s_addr = ip->saddr;	
	dest.sin_addr.s_addr = ip->daddr;	
	// for low level protocols which is not using ip it will show 0
	printf("\n [[ UDP  Packet :: ipv%d Source: %s :: ", (unsigned int)ip->version, inet_ntoa(source.sin_addr));
	printf("Dest: %s ]]",inet_ntoa(dest.sin_addr));
}

void display_other_packets_thumbnail(struct ethhdr *eth, struct iphdr *ip, struct sockaddr_in source, struct sockaddr_in dest) {
	printf("\n#####DISPLAYING OTHER PACKET THUMBNAIL#####");
	source.sin_addr.s_addr = ip->saddr;	
	dest.sin_addr.s_addr = ip->daddr;	
	// for low level protocols which is not using ip it will show 0
	printf("\n [[ OTHER Packet :: ipv%d Source: %s :: ", (unsigned int)ip->version, inet_ntoa(source.sin_addr));
	printf("Dest: %s ]]",inet_ntoa(dest.sin_addr));
	/* printf("\n[[ TCP Packet :: ipv%d :: Source: %s :: Dest: %s ]]\n", (unsigned int)ip->version, inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr)); */

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

void packet_capture(const char *interface, int len, int command, struct ip_filter *myfilterptr) {
	printf("Got command = %d", command);
	int sock;
	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	
	if(myfilterptr->use_status == 0) {
		printf("Not using any ip filter\n");
	}else if(myfilterptr->use_status == 1) {
		printf("Source filter is being used..\n");
	}else if(myfilterptr->use_status == 2) {
		printf("Destination filter is being used..\n");
	}else if(myfilterptr->use_status == 3) {
		printf("Both filter is being used\n");
	}else{
		printf("Invalid Filter\n");
		exit(0);
	}

	/* exit(0); */
	if(sock == -1)
		perror("Failed to create a socket");

// binding the interface to the socket
	if(setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface, len) == -1){
		fprintf(stderr, "Failed to select the chosen interface");
	}

	printf("Binding to the specific interface was successful..\n");

	unsigned char *buffer = (unsigned char*)malloc(BUFFSIZE);
	memset(buffer, 0, BUFFSIZE);

	struct sockaddr saddr;
	struct sockaddr_in source, dest;
	memset(&source, 0, sizeof(source));
	memset(&dest, 0, sizeof(dest));

	int saddr_len = sizeof(saddr);

	int buflen;

while(1) { // infinite loop
	buflen = recvfrom(sock,buffer, BUFFSIZE, 0, &saddr, (socklen_t *)&saddr_len); // capturing the packet

	if(buflen == -1)
		perror("Failed to receive the packet: ");


	struct ethhdr *eth  = (struct ethhdr*)(buffer); // separating ethernet information from buffer


	unsigned short iphdrlen;
	struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr)); // separting ip information from buffer
	unsigned int *ip_bytes = (unsigned int *)malloc(10*sizeof(unsigned int));
	/* ip_bytes = (unsigned int *)buffer + sizeof(struct ethhdr); */


	/* for(int i = 0; i< 20; i++) { */
	/* 	printf("%.2X ", *(ip_bytes+i)); */
	/* } */
	/* exit(0); */

	iphdrlen = ip->ihl*4; //IHL means Internet Header Length (IHL), which is the number of 32-bit words in the header. So we have to multiply the IHL by 4 to get the size of the header in bytes:
	/* getting pointer to udp header*/

	int remaining_data;
	unsigned char *data;
	
	source.sin_addr.s_addr = ip->saddr;
	dest.sin_addr.s_addr = ip->daddr;

	/* printf("use Status = %d\n", myfilterptr->use_status); */
	/* printf("\t|-Source IP : %s\n", inet_ntoa(myfilterptr->source_filter.sin_addr)); */
	/* printf("\t|-Destination IP : %s\n", inet_ntoa(myfilterptr->dest_filter.sin_addr)); */

	if (myfilterptr->use_status == 2 && (ip->daddr != myfilterptr->dest_filter.sin_addr.s_addr) ||
		myfilterptr->use_status == 1 && (ip->saddr != myfilterptr->source_filter.sin_addr.s_addr))	 { 
		// if source/destination filter is set but the current packet doesn't doesn't math
		// no need to go through each case below
		/* printf("IP filter was set, but the packet doesn't match the used filter\n"); */
		/* exit(0); */
	}else{
	// if source filter is set and ip packet does not match the desitnation filter
	switch(command) {
	/*
		filter:protocol
		 1) display_all_packet_thumbnails (DEFAULT)
		 2) display_tcp_udp_thumbnails
		 3) display_tcp_udp_packet_details
		 4) display_tcp_packet_details
		 5) display_udp_packet_details
		 6) display_all_packet_details
		 7)	display_packets_to_ip
		 8_ display_packets_from_ip
		 9_Monitor_my_application
		 10_port based filter (not implemented in this version)
		 11) analyse_the_traffic_coming_to_a_port
	*/
		 /* 1) display_all_packet_thumbnails (DEFAULT) */
		case 1:
			if(ip->protocol == 6) {
				struct tcphdr *tcp= (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr)); // extracting tcp from the buffer
				display_tcp_packet_thumbnail(eth, ip, tcp, source, dest);
			}else if(ip->protocol == 17) {
				struct udphdr *udp = (struct udphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));
				display_udp_packet_thumbnail(eth, ip, udp, source, dest);
			}else{
				display_other_packets_thumbnail(eth, ip, source, dest);
			}
		break;

		 /* 2) display_tcp_udp_thumbnails */
		case 2:
			struct tcphdr *tcp= (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr)); // extracting tcp from the buffer
			display_tcp_packet_thumbnail(eth, ip, tcp, source, dest);
			struct udphdr *udp = (struct udphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));
			display_udp_packet_thumbnail(eth, ip, udp, source, dest);
		break;
		
		 /* 3) display_tcp_udp_packet_details */
		case 3:

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

		if(ip->protocol == 17) {
				display_ethernet_header(eth);
				display_ip_packet(ip, source, dest);
				printf("\n*******************Displayig UDP headers*****************************************\n");
				struct udphdr *udp=(struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));	
				data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
				remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
				display_udp_header(udp);
				display_udp_payload(data, remaining_data);

		}
		break;

		 /* 4) display_tcp_packet_details */
		case 4:
			if(ip->protocol == 6) {
				display_ethernet_header(eth);
				display_ip_packet(ip, source, dest);
				printf("\n*******************Displaying tcp headers*****************************************\n");
				struct tcphdr *tcp= (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));	
				display_tcp_header(tcp);
				data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
				remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
				printf("remaining data = %d\n", remaining_data);
				printf("data = %p\n",data);
				display_tcp_payload(data, remaining_data, ntohs(tcp->source), ntohs(tcp->dest));
			}
		break;
		
		 /* 5) display_udp_packet_details */
		case 5:
		if(ip->protocol == 17) {
				display_ethernet_header(eth);
				display_ip_packet(ip, source, dest);
				printf("\n*******************Displayig UDP headers*****************************************\n");
				struct udphdr *udp=(struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));	
				data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
				remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
				display_udp_header(udp);
				display_udp_payload(data, remaining_data);

		}
		break;


		 /* 6) display_all_packet_details */
		case 6:
		
			if(ip->protocol == 6) {
				display_ethernet_header(eth);
				display_ip_packet(ip, source, dest);
				printf("\n*******************Displaying tcp headers*****************************************\n");
				struct tcphdr *tcp= (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));	
				display_tcp_header(tcp);
				data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
				remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
				printf("remaining data = %d\n", remaining_data);
				printf("data = %p\n",data);
				display_tcp_payload(data, remaining_data, ntohs(tcp->source), ntohs(tcp->dest));
			}
			else if(ip->protocol == 17) {
				display_ethernet_header(eth);
				display_ip_packet(ip, source, dest);
				printf("\n*******************Displayig UDP headers*****************************************\n");
				struct udphdr *udp=(struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));	
				data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
				remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
				display_udp_header(udp);
				display_udp_payload(data, remaining_data);

		}else{
				display_ethernet_header(eth);
				display_ip_packet(ip, source, dest);
		}
		break;

		 /* 7)	display_packets_to_ip */
		case 7: 
		// bring the prameterized ip and the captured ip in same format and compare	
		/* printf("__________HERE___________________\n"); */


		source.sin_addr.s_addr = ip->daddr;
		/* printf("destination IP = %s\n", inet_ntoa(source.sin_addr)); */

		dest.sin_addr.s_addr = ip->saddr;
		/* printf("destination IP = %s\n", inet_ntoa(dest.sin_addr)); */


		// Using destination filter
		if (myfilterptr->use_status == 2) {
			/* printf("Filter IP = %s\n", inet_ntoa(myfilterptr->dest_filter.sin_addr)); */

			/* printf("BInary IP = %d\n",ip->saddr); */
			/* printf("BInary IP2 = %d\n",myfilterptr->dest_filter.sin_addr.s_addr); */

			if(ip->daddr == myfilterptr->dest_filter.sin_addr.s_addr) {
				printf("MATCHED################################################33\n");


				if(ip->protocol == 6) {
					display_ethernet_header(eth);
					display_ip_packet(ip, source, dest);
					printf("\n*******************Displaying tcp headers*****************************************\n");
					struct tcphdr *tcp= (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));	
					display_tcp_header(tcp);
					data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
					remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
					display_tcp_payload(data, remaining_data, ntohs(tcp->source), ntohs(tcp->dest));
				}
				if(ip->protocol == 17) {
					display_ethernet_header(eth);
					display_ip_packet(ip, source, dest);
					printf("\n*******************Displayig UDP headers*****************************************\n");
					struct udphdr *udp=(struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));	
					data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
					remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
					display_udp_header(udp);
					display_udp_payload(data, remaining_data);

			}
				// here display all the tcp and udp packets that is going to the parameterized ip
				
			}

				
		}

		break;


		 /* 8_ display_packets_from_ip */
		case 8: 
		// Using source filter
		/* printf("CASE 8"); */
		if (myfilterptr->use_status == 1) {
			/* printf("Filter IP = %s\n", inet_ntoa(myfilterptr->dest_filter.sin_addr)); */

			/* printf("BInary IP = %d\n",ip->saddr); */
			/* printf("BInary IP2 = %d\n",myfilterptr->dest_filter.sin_addr.s_addr); */
			/* printf("Using destinatin filter..\n"); */
			if(ip->saddr == myfilterptr->source_filter.sin_addr.s_addr) {
				printf("MATCHED SOURCE ADDREESS ################################################33\n");


				if(ip->protocol == 6) {
					display_ethernet_header(eth);
					display_ip_packet(ip, source, dest);
					printf("\n*******************Displaying tcp headers*****************************************\n");
					struct tcphdr *tcp= (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));	
					display_tcp_header(tcp);
					data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
					remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
					display_tcp_payload(data, remaining_data, ntohs(tcp->source), ntohs(tcp->dest));
				}
				if(ip->protocol == 17) {
					display_ethernet_header(eth);
					display_ip_packet(ip, source, dest);
					printf("\n*******************Displayig UDP headers*****************************************\n");
					struct udphdr *udp=(struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));	
					data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
					remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
					display_udp_header(udp);
					display_udp_payload(data, remaining_data);

				}
				// here display all the tcp and udp packets that is going to the parameterized ip
				
			}

				
		}
		break;
		// Monitor my application	
		case 9:

		source.sin_addr.s_addr = ip->daddr;
		/* printf("destination IP = %s\n", inet_ntoa(source.sin_addr)); */

		dest.sin_addr.s_addr = ip->saddr;
		/* printf("destination IP = %s\n", inet_ntoa(dest.sin_addr)); */

		/* printf("Monitoring your application\n"); */
		if( ip->protocol == 6 ) {
		printf("Caputred tcp packets\n");
			struct tcphdr *tcp= (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));	
			printf("Source = %d\n",ntohs(tcp->source));
			printf("Destination= %d\n",ntohs(tcp->dest));
			if(tcp->dest == htons(5173) || tcp->source == htons(5713)) {
				// only external traffic will be able to come here...
				// I can keep this in logfile
				printf("Private Resource accessed from outside..\n");	
				/* printf("\t|-Source Port        : %u\n", ntohs(tcp->source)); */
				/* printf("\t|-Destination Port   : %u\n", ntohs(tcp->dest)); */
				/* printf("\t| Source Address = %s",inet_ntoa(source.sin_addr)); */
				/* printf("\t| Destination Address = %s",inet_ntoa(dest.sin_addr)); */
				printf("%s\n",inet_ntoa(source.sin_addr));
			}
		}
		break;

		case 10:
		// identify the http, ftp and telnet traffic
		/* printf("Inside case 10\n"); */
		if(ip->protocol == 6) {
				struct tcphdr *tcp= (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
				data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
			/* printf("Port = %d",ntohs(tcp->dest)); / */
		}
		if(ip->protocol == 6) {
			/* display_ethernet_header(eth); */
			/* display_ip_packet(ip, source, dest); */
			/* printf("\n*******************Displaying tcp headers*****************************************\n"); */
			struct tcphdr *tcp= (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));	
			/* display_tcp_header(tcp); */


			data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
			remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));

			printf("RRRRRRRemaining data = %d\n", remaining_data);
			printf("data = %p\n",data);
			display_tcp_payload(data, remaining_data, ntohs(tcp->source), ntohs(tcp->dest));


			printf("--------------------------------------\n");
			int offset = 12;	
			/* printf("data  = %.2X\n",data[offset+0]); */	
			/* printf("data  = %.2X\n",data[offset+1]); */	
			/* printf("data  = %.2X\n",data[offset+2]); */	

			/* printf("data  = %c\n",data[offset+0]); */	
			/* printf("data  = %c\n",data[offset+1]); */	
			/* printf("data  = %c\n",data[offset+2]); */	
			
			// we'v hex values in 'data' variable which is an array.
			// so we'll check the first few bytes of that data variable and match with http, then we can identify the packet as http
			// GET POST PUT UPDATE PATCH DELETE OPTIONS HEAD
			//
			//
			// DUNNO WHY AM I GETTING HTTP TRAFFIC AT OFFSET 12
			//checking for get 47 45 54
			//
			int http = 0;
			int ftp = 0;


			 if (data[offset + 0] == 0x47 && data[offset + 1] == 0x45 && data[offset + 2] == 0x54) {
				printf("This is a GET request\n");
				http = 1;
			} else if (data[offset + 0] == 0x50 && data[offset + 1] == 0x4f && data[offset + 2] == 0x53 && data[offset + 3] == 0x54) {
				printf("This is a POST request\n");
				http = 1;
			} else if (data[offset + 0] == 0x50 && data[offset + 1] == 0x55 && data[offset + 2] == 0x54) {
				printf("This is a PUT request\n");
				http = 1;
			} else if (data[offset + 0] == 0x50 && data[offset + 1] == 0x41 && data[offset + 2] == 0x54 && data[offset + 3] == 0x43 && data[offset + 4] == 0x48) {
				printf("This is a PATCH request\n");
				http = 1;
			} else if (data[offset + 0] == 0x44 && data[offset + 1] == 0x45 && data[offset + 2] == 0x4c && data[offset + 3] == 0x45 && data[offset + 4] == 0x54 && data[offset + 5] == 0x45) {
				printf("This is a DELETE request\n");
				http = 1;
			} else if (data[offset + 0] == 0x4f && data[offset + 1] == 0x50 && data[offset + 2] == 0x54 && data[offset + 3] == 0x49 && data[offset + 4] == 0x4f && data[offset + 5] == 0x4e && data[offset + 6] == 0x53) {
				printf("This is an OPTIONS request\n");
				http = 1;
			} else if (data[offset + 0] == 0x48 && data[offset + 1] == 0x54 && data[offset + 2] == 0x54 && data[offset + 3] == 0x50) {
				printf("This is HTTP response\n");
				http = 1;
			}else{
				// do nothing
			}
		// implentaion for ftp 

		if (http == 1) {
			// Log the insecure connection
			struct sockaddr_in source, dest;
			source.sin_addr.s_addr = ip->saddr;	
			dest.sin_addr.s_addr = ip->daddr;

			/* for (int i = 0; i< 20; i++) { */
			/* 	printf("%.2X ", *(ip+i)); */
			/* } */
			printf("\t|-Source IP : %s\n", inet_ntoa(source.sin_addr));
			printf("\t|-Destination IP : %s\n", inet_ntoa(dest.sin_addr));
			printf("\t|-Version: %d\n", (unsigned int)ip->version);
			printf("\t|-Internet Header Length : %d DWORDS or %d Bytes\n", (unsigned int)ip->ihl, ((unsigned int)(ip->ihl)) * 4);
			printf("\t|-Type of Service: %d\n", (unsigned int)ip->tos);
			printf("\t|-Total Length: %d\n", (unsigned int)ip->tos);
			printf("----------------------------------------------------\n");
			printf("\t|-Source Port        : %u\n", ntohs(tcp->source));
			printf("\t|-Destination Port   : %u\n", ntohs(tcp->dest));
			printf("\t|-Sequence Number   : %u\n", ntohl(tcp->seq));
			printf("\t|-Acknowledge Number : %u\n", ntohl(tcp->ack_seq));
			exit(0);
				
		}

		if (ftp == 1) {
			printf("FTP PROTOCOL DETECTED\n\n");
		}
			

		}
		

		break;


	}
} // ip didn't match

	// clearing the buffer
	memset(buffer, 0, BUFFSIZE);
}
	printf("\n");
	close(sock);
	
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
	
	int command = 1;
	printf("\n1) Display All Packet Thumbnails\n");
	printf("2) Display TCP/UDP Thumbnails\n");
	printf("3) Display TCP/UDP Packet Details\n");
	printf("4) Display TCP Packet Details\n");
	printf("5) Display UDP Packet Details\n");
	printf("6) Display All Packet Details\n");

	printf("Choose one of the options below: ");
	scanf("%d",&command);


	struct ip_filter *myfilterptr, myfilter;
	myfilterptr = &myfilter;

	char from_filter_ip[INET_ADDRSTRLEN];
	char to_filter_ip[INET_ADDRSTRLEN];

	strcpy(from_filter_ip, "0.0.0.0");
	strcpy(to_filter_ip, "0.0.0.0");
	myfilterptr->use_status = 0;


	struct sockaddr_in from_filter_addr;
	struct sockaddr_in to_filter_addr;


	inet_pton(AF_INET,from_filter_ip, &from_filter_addr.sin_addr);
	inet_pton(AF_INET, to_filter_ip, &to_filter_addr.sin_addr);


	myfilterptr->source_filter = from_filter_addr;
	myfilterptr->dest_filter = to_filter_addr;

	packet_capture(interface, len, command, myfilterptr);	 // calling packet capture from main
	return 0;
}

