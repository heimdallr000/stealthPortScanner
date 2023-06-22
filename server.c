#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

int main()
{
	int server_sock;
	int client_sock;

	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	socklen_t client_addr_size;

	server_sock = socket(PF_INET, SOCK_STREAM, 0);
	if(server_sock == -1)
		printf("Socket Error!\n");

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(****);

	if(bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1)
		printf("Bind Error\n");
	if(listen(server_sock, 5) == -1)
		printf("Listen Error\n");

	client_addr_size = sizeof(client_addr);
	client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_addr_size);
	if(client_sock == -1)
		printf("Accept Error\n");

	unsigned char *message = malloc(32);
	memset(message, 0, 32);
	int nRead;

	while(1)
	{
		nRead = read(client_sock, message, 32);
		if(nRead < 0)
		{
			printf("Read Error\n");
			return 0;
		}
		printf("[*] Messaged Received!\n");
		printf(" - %s\n\n", message);

	}

	free(message);
}
