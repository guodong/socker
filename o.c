#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT 80

int main()
{
	char myIP[16];
	unsigned int myPort;
	struct sockaddr_in server_addr, my_addr;
	int sockfd;

	// Connect to server
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Can't open stream socket.");
		exit(-1);
	}

  printf("%d\n", sockfd);

	// Set server_addr
	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(SERVER_ADDR);
	server_addr.sin_port = htons(SERVER_PORT);

	// Connect to server
	if (connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
		perror("Connect server error");
		// close(sockfd);
		// exit(-1);
	}

	// Get my ip address and port
	bzero(&my_addr, sizeof(my_addr));
	int len = sizeof(my_addr);
	getsockname(sockfd, (struct sockaddr *) &my_addr, &len);
	inet_ntop(AF_INET, &my_addr.sin_addr, myIP, sizeof(myIP));
	myPort = ntohs(my_addr.sin_port);

	printf("Local ip address: %s\n", myIP);
	printf("Local port : %u\n", myPort);

	return 0;
}