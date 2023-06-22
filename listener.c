#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <unistd.h>
#include <string.h>

int serverSock;
struct sockaddr_in server_addr;

void send_result(unsigned char *addr, unsigned int port, int ifOpen)
{
	if(!strcmp(addr, "***.***.***.***"))
		return;

	unsigned char *message = (unsigned char *)malloc(32);
	memset(message, 0, 32);

	if(ifOpen)
	{
		sprintf(message, "%s : %u Open\0", addr, port);
		printf("=> %s : %u Open\n\n", addr, port);
	}
	else
	{
		sprintf(message, "%s : %u Closed\0", addr, port);
		printf("=> %s : %u Closed\n\n", addr, port);
	}

	int nWrite = write(serverSock, message, 32);
	if(nWrite < 0)
		printf("Write Error\n");

	free(message);

	return;
}

void IP_header_parse(unsigned char *buffer)
{
	struct iphdr *ipHeader = (struct iphdr *)buffer;
	struct sockaddr_in source, dest;

	source.sin_addr.s_addr = ipHeader->saddr;
	dest.sin_addr.s_addr = ipHeader->daddr;

	printf(" - Source IP: %s\n", inet_ntoa(source.sin_addr));
	printf(" - Dest   IP: %s\n", inet_ntoa(dest.sin_addr));

	return;
}


void TCP_parse(unsigned char *buffer, int size)
{
	struct iphdr *ipHeader = (struct iphdr *)(buffer + ETH_HLEN);
	unsigned short ipHeaderLen = ipHeader->ihl * 4;
	struct tcphdr *tcph = (struct tcphdr *)(buffer + ipHeaderLen + ETH_HLEN);

	if((unsigned int)ntohs(tcph->source) == **** || (unsigned int)ntohs(tcph->dest) == ****)
		return;

	printf("[*] Received!\n");

	IP_header_parse(buffer + ETH_HLEN);

	printf(" - Source Port: %u\n", ntohs(tcph->source));
	printf(" - Dest   Port: %u\n", ntohs(tcph->dest));
	printf(" - ACK Flag: %d\n", (unsigned int)tcph->ack);
	printf(" - RST Flag: %d\n", (unsigned int)tcph->rst);
	printf(" - SYN Flag: %d\n", (unsigned int)tcph->syn);

	unsigned char *saddr = (unsigned char *)malloc(20);
	struct sockaddr_in source;
	source.sin_addr.s_addr = ipHeader->saddr;
	memset(saddr, 0, 20);
	memcpy(saddr, inet_ntoa(source.sin_addr), strlen(inet_ntoa(source.sin_addr)));

	unsigned int sport = (unsigned int)ntohs(tcph->source);

	if((unsigned int)tcph->rst)
	{
		send_result(saddr, sport, 0);
	}
	else
	{
		send_result(saddr, sport, 1);
	}

	free(saddr);

	return;
}

int main()
{
	int sock_r;
	sock_r = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	serverSock = socket(PF_INET, SOCK_STREAM, 0);
	
	if(serverSock < 0)
	{
		printf("Error in serverSocket\n");
		return -1;
	}
	
	if(sock_r < 0)
	{
		printf("Error in Socket\n");
		return -1;
	}
	
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr("***.***.***.***");
	server_addr.sin_port = htons(****);

	if(connect(serverSock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
		printf("Connect Error\n");

	unsigned char *buffer = (unsigned char *) malloc(65536);
	memset(buffer, 0, 65536);

	printf("[*] Listening...\n");
	while(1)
	{
		int buflen = recvfrom(sock_r, buffer, 65536, 0, NULL, NULL);
		if(buflen < 0)
		{
			printf("Error in reading recvfrom function\n");
			return -1;
		}
		
		struct iphdr *ipHeader = (struct iphdr *)(buffer + ETH_HLEN);
		switch(ipHeader->protocol)
		{
			case 6:		// TCP
				TCP_parse(buffer, buflen);
				break;
			default:
				break;
		}
	}
	free(buffer);

	return 0;
}
