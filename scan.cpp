#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <vector>

using namespace std;

static unsigned short compute_ip_checksum(unsigned short *addr, unsigned int count)
{
	register unsigned long sum = 0;
	while( count > 1)
	{
		sum += *addr++;
		count -= 2;
	}
	if(count > 0)
	{
		sum += ((*addr)&htons(0xFF00));
	}
	while(sum >> 16)
	{
		sum = (sum & 0xffff) + (sum >> 16);
	}
	sum = ~sum;
	return ((unsigned short)sum);
}

void compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload)
{
	register unsigned long sum = 0;
	unsigned short tcpLen = ntohs(pIph->tot_len) - (pIph->ihl << 2);
	struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);

	sum += (pIph->saddr >> 16) & 0xFFFF;
	sum += (pIph->saddr) & 0xFFFF;

	sum += (pIph->daddr >> 16) & 0xFFFF;
	sum += (pIph->daddr) & 0xFFFF;

	sum += htons(IPPROTO_TCP);
	sum += htons(tcpLen);

	tcphdrp->check = 0;
	while(tcpLen > 1)
	{
		sum += *ipPayload++;
		tcpLen -= 2;
	}
	if(tcpLen > 0)
	{
		sum += ((*ipPayload)&htons(0xFF00));
	}
	while(sum >> 16)
	{
		sum = (sum & 0xffff) + (sum >> 16);
	}
	sum = ~sum;
	tcphdrp->check = (unsigned short)sum;
}

int synScan(unsigned char* source_ip, unsigned char* target_ip, unsigned int target_port, int raw_socket)
{
	struct iphdr ip_header;
	ip_header.ihl = 5;
	ip_header.version = 4;
	ip_header.tos = 0;
	ip_header.tot_len = 0;
	ip_header.id = htons(rand() % 65535);
	ip_header.frag_off = 0;
	ip_header.ttl = 64;
	ip_header.protocol = 6;
	ip_header.check = 0;
	ip_header.saddr = inet_addr((const char*)source_ip);
	ip_header.daddr = inet_addr((const char*)target_ip);

    struct tcphdr tcp_header;
	tcp_header.source = htons(rand() % 65535);
	tcp_header.dest = htons(target_port);
	tcp_header.seq = htonl(221756075);
	tcp_header.ack_seq = htonl(0);
	tcp_header.res1 = 0;
	tcp_header.doff = 5;
	tcp_header.fin = 0;
	tcp_header.syn = 1;
	tcp_header.rst = 0;
	tcp_header.psh = 0;
	tcp_header.ack = 0;
	tcp_header.urg = 0;
	tcp_header.ece = 0;
	tcp_header.cwr = 0;
	tcp_header.window = htons(1024);
	tcp_header.check = 0;
	tcp_header.urg_ptr = htons(0);

    struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(target_port);
	sin.sin_addr.s_addr = inet_addr((const char*)target_ip);

   	unsigned char data[0];

    ip_header.tot_len = htons(sizeof(ip_header) + sizeof(tcp_header) + sizeof(data));
	int totalFrameLength = sizeof(ip_header) + sizeof(tcp_header) + sizeof(data);

    unsigned char packet[totalFrameLength];

    ip_header.check = compute_ip_checksum((unsigned short*)&ip_header, ip_header.ihl<<2);
	compute_tcp_checksum(&ip_header, (unsigned short*)&tcp_header);

	memcpy(packet, &ip_header, sizeof(ip_header));
	memcpy(packet + sizeof(ip_header), &tcp_header, sizeof(tcp_header));
	memcpy(packet + sizeof(ip_header) + sizeof(tcp_header), data, sizeof(data));

    if(sendto(raw_socket, packet, sizeof(packet), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
	{
		perror("PACKET NOT SENT\n");
		return EXIT_FAILURE;
	}
	else
	{
		printf("PACKET SENT\n");
	}

	return EXIT_SUCCESS;
}

int nullScan(unsigned char* source_ip, unsigned char* target_ip, unsigned int target_port, int raw_socket)
{
    struct iphdr ip_header;
	ip_header.ihl = 5;
	ip_header.version = 4;
	ip_header.tos = 0;
	ip_header.tot_len = 0;
	ip_header.id = htons(rand() % 65535);
	ip_header.frag_off = 0;
	ip_header.ttl = 64;
	ip_header.protocol = 6;
	ip_header.check = 0;
	ip_header.saddr = inet_addr((const char*)source_ip);
	ip_header.daddr = inet_addr((const char*)target_ip);

    struct tcphdr tcp_header;
	tcp_header.source = htons(rand() % 65535);
	tcp_header.dest = htons(target_port);
	tcp_header.seq = htonl(221756075);
	tcp_header.ack_seq = htonl(0);
	tcp_header.res1 = 0;
	tcp_header.doff = 5;
	tcp_header.fin = 0;
	tcp_header.syn = 0;
	tcp_header.rst = 0;
	tcp_header.psh = 0;
	tcp_header.ack = 0;
	tcp_header.urg = 0;
	tcp_header.ece = 0;
	tcp_header.cwr = 0;
	tcp_header.window = htons(1024);
	tcp_header.check = 0;
	tcp_header.urg_ptr = htons(0);

    struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(target_port);
	sin.sin_addr.s_addr = inet_addr((const char*)target_ip);

   	unsigned char data[0];

    ip_header.tot_len = htons(sizeof(ip_header) + sizeof(tcp_header) + sizeof(data));
	int totalFrameLength = sizeof(ip_header) + sizeof(tcp_header) + sizeof(data);

    unsigned char packet[totalFrameLength];

    ip_header.check = compute_ip_checksum((unsigned short*)&ip_header, ip_header.ihl<<2);
	compute_tcp_checksum(&ip_header, (unsigned short*)&tcp_header);

	memcpy(packet, &ip_header, sizeof(ip_header));
	memcpy(packet + sizeof(ip_header), &tcp_header, sizeof(tcp_header));
	memcpy(packet + sizeof(ip_header) + sizeof(tcp_header), data, sizeof(data));

    if(sendto(raw_socket, packet, sizeof(packet), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
	{
		perror("PACKET NOT SENT\n");
		return EXIT_FAILURE;
	}
	else
	{
		printf("PACKET SENT\n");
	}

	return EXIT_SUCCESS;
}

int finScan(unsigned char* source_ip, unsigned char* target_ip, unsigned int target_port, int raw_socket)
{
    struct iphdr ip_header;
	ip_header.ihl = 5;
	ip_header.version = 4;
	ip_header.tos = 0;
	ip_header.tot_len = 0;
	ip_header.id = htons(rand() % 65535);
	ip_header.frag_off = 0;
	ip_header.ttl = 64;
	ip_header.protocol = 6;
	ip_header.check = 0;
	ip_header.saddr = inet_addr((const char*)source_ip);
//	ip_header.saddr = inet_addr("***.***.***.***");
	ip_header.daddr = inet_addr((const char*)target_ip);

    struct tcphdr tcp_header;
	tcp_header.source = htons(rand() % 65535);
	tcp_header.dest = htons(target_port);
	tcp_header.seq = htonl(221756075);
	tcp_header.ack_seq = htonl(0);
	tcp_header.res1 = 0;
	tcp_header.doff = 5;
	tcp_header.fin = 1;
	tcp_header.syn = 0;
	tcp_header.rst = 0;
	tcp_header.psh = 0;
	tcp_header.ack = 0;
	tcp_header.urg = 0;
	tcp_header.ece = 0;
	tcp_header.cwr = 0;
	tcp_header.window = htons(1024);
	tcp_header.check = 0;
	tcp_header.urg_ptr = htons(0);

    struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(target_port);
	sin.sin_addr.s_addr = inet_addr((const char*)target_ip);

   	unsigned char data[0];

    ip_header.tot_len = htons(sizeof(ip_header) + sizeof(tcp_header) + sizeof(data));
	int totalFrameLength = sizeof(ip_header) + sizeof(tcp_header) + sizeof(data);

    unsigned char packet[totalFrameLength];

    ip_header.check = compute_ip_checksum((unsigned short*)&ip_header, ip_header.ihl<<2);
	compute_tcp_checksum(&ip_header, (unsigned short*)&tcp_header);

	memcpy(packet, &ip_header, sizeof(ip_header));
	memcpy(packet + sizeof(ip_header), &tcp_header, sizeof(tcp_header));
	memcpy(packet + sizeof(ip_header) + sizeof(tcp_header), data, sizeof(data));

    if(sendto(raw_socket, packet, sizeof(packet), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
	{
		perror("PACKET NOT SENT\n");
		return EXIT_FAILURE;
	}
	else
	{
		printf("PACKET SENT\n");
	}

	return EXIT_SUCCESS;
}

int xMasScan(unsigned char* source_ip, unsigned char* target_ip, unsigned int target_port, int raw_socket)
{
    struct iphdr ip_header;
	ip_header.ihl = 5;
	ip_header.version = 4;
	ip_header.tos = 0;
	ip_header.tot_len = 0;
	ip_header.id = htons(rand() % 65535);
	ip_header.frag_off = 0;
	ip_header.ttl = 64;
	ip_header.protocol = 6;
	ip_header.check = 0;
	ip_header.saddr = inet_addr((const char*)source_ip);
	ip_header.daddr = inet_addr((const char*)target_ip);

    struct tcphdr tcp_header;
	tcp_header.source = htons(rand() % 65535);
	tcp_header.dest = htons(target_port);
	tcp_header.seq = htonl(221756075);
	tcp_header.ack_seq = htonl(0);
	tcp_header.res1 = 0;
	tcp_header.doff = 5;
	tcp_header.fin = 1;
	tcp_header.syn = 0;
	tcp_header.rst = 0;
	tcp_header.psh = 1;
	tcp_header.ack = 0;
	tcp_header.urg = 1;
	tcp_header.ece = 0;
	tcp_header.cwr = 0;
	tcp_header.window = htons(1024);
	tcp_header.check = 0;
	tcp_header.urg_ptr = htons(0);

    struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(target_port);
	sin.sin_addr.s_addr = inet_addr((const char*)target_ip);

   	unsigned char data[0];

    ip_header.tot_len = htons(sizeof(ip_header) + sizeof(tcp_header) + sizeof(data));
	int totalFrameLength = sizeof(ip_header) + sizeof(tcp_header) + sizeof(data);

    unsigned char packet[totalFrameLength];

    ip_header.check = compute_ip_checksum((unsigned short*)&ip_header, ip_header.ihl<<2);
	compute_tcp_checksum(&ip_header, (unsigned short*)&tcp_header);

	memcpy(packet, &ip_header, sizeof(ip_header));
	memcpy(packet + sizeof(ip_header), &tcp_header, sizeof(tcp_header));
	memcpy(packet + sizeof(ip_header) + sizeof(tcp_header), data, sizeof(data));

    if(sendto(raw_socket, packet, sizeof(packet), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
	{
		perror("PACKET NOT SENT\n");
		return EXIT_FAILURE;
	}
	else
	{
		printf("PACKET SENT\n");
	}

	return EXIT_SUCCESS;
}

int main()
{
    FILE* fp1;
	FILE* fp3;
    fp1 = fopen("ipList.txt", "r");
	fp3 = fopen("sourceIPs.txt", "r");


	vector<unsigned char*> ipList;
	vector<unsigned char*> sourceIpList;
	char line[1024];
    char *pLine;
    unsigned char* ptmp;

    while (!feof(fp1)) 
	{
        pLine = fgets(line, 1024, fp1);
	if(pLine == 0)
		break;
        ptmp = new unsigned char[strlen(pLine)];
        memcpy(ptmp, pLine, strlen(pLine)-1);
        ipList.push_back(ptmp);
    }
    printf("hi?\n");

	while (!feof(fp3)) 
	{
        pLine = fgets(line, 1024, fp3);
	if(pLine == 0)
		break;
        ptmp = new unsigned char[strlen(pLine)];
        memcpy(ptmp, pLine, strlen(pLine)-1);
        sourceIpList.push_back(ptmp);
    }
	
	fclose(fp1);
	fclose(fp3);

	int targetPort[] = {*, **, ***, ****};
	int numPort = sizeof(targetPort) / 4;
	int numIP = ipList.size();
	int numSource = sourceIpList.size();
	int total = numPort * numIP;
	int done = 0;
	int progress[numIP][numPort] = {};

	printf("[*] # of ports: %d\n", numPort);
	printf("[*] # of IPs: %d\n", numIP);

	if(access("nmapProgress.txt", 0) < 0)
	{
		FILE* fp2 = fopen("nmapProgress.txt", "w");
		unsigned char* tmpchar = (unsigned char*)malloc(1);
		for(int i = 0 ; i < numIP ; i++)
		{
			for(int j = 0 ; j < numPort ; j++)
			{
				*tmpchar = progress[i][j] + '0';
				fwrite(tmpchar, 1, 1, fp2);
			}
		}
		free(tmpchar);
		fclose(fp2);
	}
	else
	{
		FILE* fp2 = fopen("nmapProgress.txt", "r");
		for(int i = 0 ; i < numIP ; i++)
		{
			for(int j = 0 ; j < numPort ; j++)
			{
				char tmpchar = fgetc(fp2);
				progress[i][j] = (int)(tmpchar - '0');
				if(progress[i][j] == 1)
					done += 1;
			}
		}
		fclose(fp2);
	}

	printf("[*] Done : %d\n", done);

    int raw_socket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

	if(raw_socket < 0)
	{
		perror("SOCKET CREATION ERROR");
		return EXIT_FAILURE;
	}
	else
	{
		printf("SOCKET CREATED\n");
	}

	int enabled = 1;
	
	if(setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &enabled, sizeof(enabled)) < 0)
	{
		perror("SOCKET OPTION NOT SET");
		return EXIT_FAILURE;
	}
	else
	{
		printf("SOCKET OPTION SET\n");
	}

	srand(time(NULL));
	while(1)
	{
		for(int i = 0 ; i < numIP ; i++)
		{
			for(int j = 0 ; j < numPort ; j++)
			{
				printf("%d", progress[i][j]);
			}
		}
		printf("\n");

		int randNum;
		float interval;
		int sourceRand;
		int scanType;
		int ret;

		unsigned char* tmpchar = (unsigned char*)malloc(1);
		randNum = random() % total;
		printf("RandNum: %d\n", randNum);
		printf("progress: %d\n", progress[randNum % numIP][randNum % numPort]);
		printf("%d %d\n", randNum % numIP, randNum % numPort);
		if(progress[randNum % numIP][randNum % numPort] == 0)
		{
			interval = ((float)rand()/RAND_MAX)*(float)(4.0) + 1.0;
			printf("[*] Sleep for %f seconds...\n", interval);
			sleep(interval);

			scanType = random() % 4;
			sourceRand = random() % numSource;
			if(scanType == 0)
			{
				printf("[*] %s : %d (%d/%d) -- SynScan / SouceIP : %s\n", ipList.at(randNum % numIP), targetPort[randNum % numPort], done + 1, total, sourceIpList.at(sourceRand));
				ret = synScan(sourceIpList.at(sourceRand), ipList.at(randNum % numIP), targetPort[randNum % numPort], raw_socket);
				if(ret)
					continue;
			}
			else if(scanType == 1)
			{
				printf("[*] %s : %d (%d/%d) -- NullScan / SouceIP : %s\n", ipList.at(randNum % numIP), targetPort[randNum % numPort], done + 1, total, sourceIpList.at(sourceRand));
				ret = nullScan(sourceIpList.at(sourceRand), ipList.at(randNum % numIP), targetPort[randNum % numPort], raw_socket);
				if(ret)
					continue;			
			}
			else if(scanType == 2)
			{
				printf("[*] %s : %d (%d/%d) -- FinScan / SouceIP : %s\n", ipList.at(randNum % numIP), targetPort[randNum % numPort], done + 1, total, sourceIpList.at(sourceRand));
				ret = finScan(sourceIpList.at(sourceRand), ipList.at(randNum % numIP), targetPort[randNum % numPort], raw_socket);
				if(ret)
					continue;			
			}
			else if(scanType == 3)
			{
				printf("[*] %s : %d (%d/%d) -- XMasScan / SouceIP : %s\n", ipList.at(randNum % numIP), targetPort[randNum % numPort], done + 1, total, sourceIpList.at(sourceRand));
				ret = xMasScan(sourceIpList.at(sourceRand), ipList.at(randNum % numIP), targetPort[randNum % numPort], raw_socket);
				if(ret)
					continue;			
			}

			progress[randNum % numIP][randNum % numPort] = 1;
			
			FILE* fp2 = fopen("nmapProgress.txt", "w");
			for(int i = 0 ; i < numIP ; i++)
			{
				for(int j = 0 ; j < numPort ; j++)
				{
					*tmpchar = progress[i][j] + '0';
					fwrite(tmpchar, 1, 1, fp2);
				}
			}
			fclose(fp2);
			
			done += 1;
		}
		if(done == total)
		{
			free(tmpchar);			
			break;
		}

	}
}
