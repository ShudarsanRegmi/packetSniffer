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
#include <regex.h>

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

int validateIPAddress(char *ip_address) {
    regex_t ipv4_regex, ipv6_regex;
    int ret;

    // Regular expressions for IPv4 and IPv6 addresses
    ret = regcomp(&ipv4_regex, "^([0-9]{1,3}\\.){3}[0-9]{1,3}$", REG_EXTENDED); 
    if (ret != 0) {
        printf("Failed to compile IPv4 regex\n");
        return -1;
    }

    ret = regcomp(&ipv6_regex, "^[0-9a-fA-F:]+$", REG_EXTENDED);
    if (ret != 0) {
        printf("Failed to compile IPv6 regex\n");
        regfree(&ipv4_regex);
        return -1;
    }

    // Matching the input IP address with both IPv4 and IPv6 regex
    ret = regexec(&ipv4_regex, ip_address, 0, NULL, 0);
    if (ret == 0) {
        regfree(&ipv4_regex);
        regfree(&ipv6_regex);
        return 4; // IPv4 address
    }

    ret = regexec(&ipv6_regex, ip_address, 0, NULL, 0);
    if (ret == 0) {
        regfree(&ipv4_regex);
        regfree(&ipv6_regex);
        return 6; // IPv6 address
    }

    // Neither IPv4 nor IPv6
    regfree(&ipv4_regex);
    regfree(&ipv6_regex);
    return 0;
}
void display_ethernet_header(struct ethhdr *eth) {
    // Visual delimiter to separate current packet from the previous one
    printf("\n🔻🔻🔻🔻🔻🔻🔻🔻🔻🔻🔻🔻🔻🔻🔻🔻🔻🔻🔻🔻🔻🔻🔻🔻\n");
    // Display the Ethernet header information
    printf("🌐 Ethernet Header 🌐\n");
    printf("--------------------------------------------------\n");
    printf("🔸 Source MAC Address      : %02X-%02X-%02X-%02X-%02X-%02X\n",
           eth->h_source[0], eth->h_source[1], eth->h_source[2],
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("🔸 Destination MAC Address : %02X-%02X-%02X-%02X-%02X-%02X\n",
           eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
           eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    printf("🔸 Protocol                : 0x%04X\n", ntohs(eth->h_proto));
    printf("--------------------------------------------------\n");

}



void display_ip_packet(struct iphdr *ip, struct sockaddr_in source, struct sockaddr_in dest) {
    // Populate the source and destination addresses
    source.sin_addr.s_addr = ip->saddr;
    dest.sin_addr.s_addr = ip->daddr;

    // Display the IP header information
    printf("\n🔵🔷🔹 IP Packet Overview 🔹🔷🔵\n");
    printf("==============================================\n");
    printf("🔸 Version               : %d\n", (unsigned int)ip->version);
    printf("🔸 Header Length         : %d DWORDS (%d Bytes)\n", (unsigned int)ip->ihl, ((unsigned int)(ip->ihl)) * 4);
    printf("🔸 Type of Service       : %d\n", (unsigned int)ip->tos);
    printf("🔸 Total Length          : %d Bytes\n", ntohs(ip->tot_len));
    printf("🔸 Identification        : %d\n", ntohs(ip->id));
    printf("🔸 Time To Live (TTL)    : %d\n", (unsigned int)ip->ttl);
    printf("🔸 Protocol              : %d\n", (unsigned int)ip->protocol);
    printf("🔸 Header Checksum       : 0x%04X\n", ntohs(ip->check));
    printf("==============================================\n");

    // Display the source and destination IP addresses
    printf("🌍 Source IP Address      : %s\n", inet_ntoa(source.sin_addr));
    printf("🌍 Destination IP Address : %s\n", inet_ntoa(dest.sin_addr));
    printf("==============================================\n");
    printf("✨ End of IP Packet Overview ✨\n");
}

void display_tcp_header(struct tcphdr *tcp) {
    printf("\n🌐 TCP Header Information 🌐\n");
    printf("--------------------------------------------------\n");
    printf("🔹 Source Port        : %u\n", ntohs(tcp->source));
    printf("🔹 Destination Port   : %u\n", ntohs(tcp->dest));
    printf("🔹 Sequence Number    : %u\n", ntohl(tcp->seq));
    printf("🔹 Acknowledge Number : %u\n", ntohl(tcp->ack_seq));
    printf("🔹 Header Length      : %d DWORDS (%d BYTES)\n", (unsigned int)tcp->doff, (unsigned int)tcp->doff * 4);

    printf("--------------------------------------------------\n");
    printf("🔸 Flags 🔸\n");
    printf("   🟢 URG : %d\n", (unsigned int)tcp->urg);
    printf("   🟢 ACK : %d\n", (unsigned int)tcp->ack);
    printf("   🟢 PSH : %d\n", (unsigned int)tcp->psh);
    printf("   🟢 RST : %d\n", (unsigned int)tcp->rst);
    printf("   🟢 SYN : %d\n", (unsigned int)tcp->syn);
    printf("   🟢 FIN : %d\n", (unsigned int)tcp->fin);

    printf("--------------------------------------------------\n");
    printf("🔹 Window Size        : %d\n", ntohs(tcp->window));
    printf("🔹 Checksum           : 0x%04X\n", ntohs(tcp->check));
    printf("🔹 Urgent Pointer     : %d\n", ntohs(tcp->urg_ptr));
    printf("--------------------------------------------------\n");
    printf("🌟 End of TCP Header Information 🌟\n");
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
	printf("\n-------TCP PAYLOAD--------------\n");
	for(int i=0;i<remaining_data;i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf(" %.2X ", data[i]);
	}
	printf("\n---------------------------------------------------\n\n");
}

void display_udp_header(struct udphdr *udp) {
    printf("\n🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡🟡\n");

    // Display the UDP header information
    printf("\n🌊 UDP Header 🌊\n");
    printf("============================================\n");
    printf("🔹 Source Port      : %d\n", ntohs(udp->source));
    printf("🔹 Destination Port : %d\n", ntohs(udp->dest));
    printf("🔹 Length           : %d\n", ntohs(udp->len));
    printf("🔹 Checksum         : 0x%04X\n", ntohs(udp->check));
    printf("============================================\n");

    // End delimiter for the current packet
    printf("🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢\n");
}

void display_udp_payload (unsigned char *data, int remaining_data ) {

	printf("\n-------UDP PAYLOAD--------------\n");
	for(int i=0;i<remaining_data;i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
    printf(" %.2X ", data[i]);
	}
	printf("\n---------------------------------------------------\n\n");
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


	iphdrlen = ip->ihl*4; //IHL means Internet Header Length (IHL), which is the number of 32-bit words in the header. So we have to multiply the IHL by 4 to get the size of the header in bytes:
	/* getting pointer to udp header*/

	int remaining_data;
	unsigned char *data;
	
	source.sin_addr.s_addr = ip->saddr;
	dest.sin_addr.s_addr = ip->daddr;


	if (myfilterptr->use_status == 2 && (ip->daddr != myfilterptr->dest_filter.sin_addr.s_addr) ||
		myfilterptr->use_status == 1 && (ip->saddr != myfilterptr->source_filter.sin_addr.s_addr))	 { 
		// if source/destination filter is set but the current packet doesn't doesn't math
		// no need to go through each case below
		/* printf("IP filter was set, but the packet doesn't match the used filter\n"); */
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
			struct tcphdr *tcp= (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));	
			display_tcp_header(tcp);
			data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
			remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
			display_tcp_payload(data, remaining_data, ntohs(tcp->source), ntohs(tcp->dest));
		}

		if(ip->protocol == 17) {
				display_ethernet_header(eth);
				display_ip_packet(ip, source, dest);
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
				struct tcphdr *tcp= (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));	
				display_tcp_header(tcp);
				data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
				remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
				display_tcp_payload(data, remaining_data, ntohs(tcp->source), ntohs(tcp->dest));
			}
		break;
		
		 /* 5) display_udp_packet_details */
		case 5:
		if(ip->protocol == 17) {
				display_ethernet_header(eth);
				display_ip_packet(ip, source, dest);
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
				struct tcphdr *tcp= (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));	
				display_tcp_header(tcp);
				data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
				remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
				display_tcp_payload(data, remaining_data, ntohs(tcp->source), ntohs(tcp->dest));
			}
			else if(ip->protocol == 17) {
				display_ethernet_header(eth);
				display_ip_packet(ip, source, dest);
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

		source.sin_addr.s_addr = ip->daddr;
		dest.sin_addr.s_addr = ip->saddr;
		// Using destination filter
		if (myfilterptr->use_status == 2) {
			if(ip->daddr == myfilterptr->dest_filter.sin_addr.s_addr) {
				if(ip->protocol == 6) {
					display_ethernet_header(eth);
					display_ip_packet(ip, source, dest);
					struct tcphdr *tcp= (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));	
					display_tcp_header(tcp);
					data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
					remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
					display_tcp_payload(data, remaining_data, ntohs(tcp->source), ntohs(tcp->dest));
				}
				if(ip->protocol == 17) {
					display_ethernet_header(eth);
					display_ip_packet(ip, source, dest);
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
			if(ip->saddr == myfilterptr->source_filter.sin_addr.s_addr) {
				if(ip->protocol == 6) {
					display_ethernet_header(eth);
					display_ip_packet(ip, source, dest);
					struct tcphdr *tcp= (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));	
					display_tcp_header(tcp);
					data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
					remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
					display_tcp_payload(data, remaining_data, ntohs(tcp->source), ntohs(tcp->dest));
				}
				if(ip->protocol == 17) {
					display_ethernet_header(eth);
					display_ip_packet(ip, source, dest);
					struct udphdr *udp=(struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));	
					data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
					remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
					display_udp_header(udp);
					display_udp_payload(data, remaining_data);

				}
				
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
	printf("7) Display Packets to IP\n");
	printf("8) Display Packets from IP\n");

	printf("Choose one of the options below: ");
	scanf("%d",&command);


	struct ip_filter *myfilterptr, myfilter;
	myfilterptr = &myfilter;

	char from_filter_ip[INET_ADDRSTRLEN];
	char to_filter_ip[INET_ADDRSTRLEN];

	strcpy(from_filter_ip, "0.0.0.0");
	strcpy(to_filter_ip, "0.0.0.0");
	myfilterptr->use_status = 0;

	if(command == 8) {
		myfilterptr->use_status = 1;
		printf("Enter the source ip: ");
		getchar();
		scanf("%45s", from_filter_ip); // Read up to 45 characters (maximum for IPv6)

		// perform ip validation
		int version = validateIPAddress(from_filter_ip);
		if(version == 4 || version == 6) {
			printf("IP validated...\n");
			printf("From Filter IP = %s",from_filter_ip);
		}else{
			printf("Invalid ip");
			return 0;
		}

	}

	if(command == 7) {
		myfilterptr->use_status = 2;
		printf("Enter the destination ip: ");
		getchar();
		scanf("%45s", to_filter_ip); // Read up to 45 characters (maximum for IPv6)

		// perform ip validation
		int version = validateIPAddress(to_filter_ip);
		if(version == 4 || version == 6) {
			printf("IP validated...\n");
			printf("To Filter IP = %s",to_filter_ip);
		}else{
			printf("Invalid ip");
			return 0;
		}
	}

	struct sockaddr_in from_filter_addr;
	struct sockaddr_in to_filter_addr;

	inet_pton(AF_INET,from_filter_ip, &from_filter_addr.sin_addr);
	inet_pton(AF_INET, to_filter_ip, &to_filter_addr.sin_addr);


	myfilterptr->source_filter = from_filter_addr;
	myfilterptr->dest_filter = to_filter_addr;

	packet_capture(interface, len, command, myfilterptr);	 // calling packet capture from main
	return 0;
}

