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

	return 0;
}
